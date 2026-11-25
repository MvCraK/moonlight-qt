// SS-NETWORK extension (see ss-network/README.md).
// UDP media is encrypted/decrypted in place on moonlight-common-c's own sockets
// (see shim/ss_shim.c). Setup TCP from common-c uses the one-shot loopback relay,
// and Qt networking (HTTP pairing, polling, USB/file tunnels) uses the local
// SOCKS5 endpoint below. Subscription YAML is parsed here as well.
use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Aes256, Block,
};
use bytes::{Bytes, BytesMut};
use serde::Deserialize;
use shadowsocks::{
    config::{ServerAddr, ServerType},
    context::{Context, SharedContext},
    crypto::{
        v1::{random_iv_or_salt, Cipher},
        v2::udp::UdpCipher,
        CipherCategory, CipherKind,
    },
    relay::{
        socks5::Address,
        udprelay::{
            crypto_io::{decrypt_server_payload, encrypt_client_payload},
            options::UdpSocketControlData,
        },
    },
    ProxyClientStream, ServerConfig,
};
use std::{
    cell::RefCell,
    ffi::{CStr, CString},
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket},
    os::raw::c_char,
    slice,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::watch,
    time::timeout,
};

const AEAD2022_CLIENT_TYPE: u8 = 0;
const AEAD2022_SERVER_TYPE: u8 = 1;
const AEAD2022_MAX_TS_DIFF: u64 = 30;

// ---- Physical interface bypass & anti-Fake-IP DNS -----------------------------

static BYPASS_IF_INDEX: AtomicU32 = AtomicU32::new(0);
static BYPASS_IF_NAME: RwLock<Option<String>> = RwLock::new(None);

/// Configures the physical non-TUN interface to bind outbound SS sockets to
/// when a system VPN/TUN (e.g. FlClash TUN) is active. Pass `if_index == 0`
/// or `if_name == null` to disable bypass and use normal OS routing.
#[no_mangle]
pub unsafe extern "C" fn vss_set_bypass_interface(if_index: u32, if_name: *const c_char) {
    let name = if if_index != 0 && !if_name.is_null() {
        CStr::from_ptr(if_name)
            .to_str()
            .ok()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    } else {
        None
    };
    let active_index = if name.is_some() { if_index } else { 0 };
    if let Ok(mut guard) = BYPASS_IF_NAME.write() {
        *guard = name;
    }
    BYPASS_IF_INDEX.store(active_index, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn vss_bypass_if_index() -> u32 {
    BYPASS_IF_INDEX.load(Ordering::Acquire)
}

fn current_bypass() -> (u32, Option<String>) {
    let idx = BYPASS_IF_INDEX.load(Ordering::Acquire);
    if idx == 0 {
        return (0, None);
    }
    let name = BYPASS_IF_NAME.read().ok().and_then(|g| g.clone());
    if name.is_some() {
        (idx, name)
    } else {
        (0, None)
    }
}

/// Returns true for RFC 2544 benchmark range (198.18.0.0/15), universally used
/// by Clash / FlClash / Surge / sing-box Fake-IP resolvers.
#[inline]
fn is_fake_ip(ip: Ipv4Addr) -> bool {
    (u32::from(ip) & 0xfffe_0000) == 0xc612_0000
}

#[inline]
fn is_usable_public_or_lan_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !is_fake_ip(ip)
}

#[cfg(target_os = "macos")]
fn bind_socket_to_if_v4(fd: std::os::unix::io::RawFd, if_index: u32) -> std::io::Result<()> {
    if if_index == 0 {
        return Ok(());
    }
    const IP_BOUND_IF: libc::c_int = 25;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_BOUND_IF,
            &if_index as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn bind_socket_to_if_v4(raw_socket: usize, if_index: u32) -> std::io::Result<()> {
    if if_index == 0 {
        return Ok(());
    }
    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    }
    const IPPROTO_IP: i32 = 0;
    const IP_UNICAST_IF: i32 = 31;
    // Per Winsock docs, IP_UNICAST_IF takes the IPv4 interface index in network byte order.
    let net_idx: u32 = if_index.to_be();
    let rc = unsafe {
        setsockopt(
            raw_socket,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &net_idx as *const u32 as *const u8,
            std::mem::size_of::<u32>() as i32,
        )
    };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn bind_socket_to_if_v4(_fd: i32, _if_index: u32) -> std::io::Result<()> {
    Ok(())
}

fn bind_udp_to_if(sock: &UdpSocket, if_index: u32) -> std::io::Result<()> {
    if if_index == 0 {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        bind_socket_to_if_v4(sock.as_raw_fd(), if_index)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        bind_socket_to_if_v4(sock.as_raw_socket() as usize, if_index)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (sock, if_index);
        Ok(())
    }
}

fn build_dns_a_query(host: &str, txid: u16) -> Option<Vec<u8>> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    let mut pkt = Vec::with_capacity(12 + trimmed.len() + 6);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    pkt.extend_from_slice(&[0u8; 6]); // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return None;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Some(pkt)
}

fn skip_dns_name(msg: &[u8], mut off: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        let len = *msg.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if (len & 0xc0) == 0xc0 {
            // Compression pointer takes 2 bytes and ends the name at this position.
            if off + 1 >= msg.len() {
                return None;
            }
            return Some(off + 2);
        }
        if (len & 0xc0) != 0 {
            return None;
        }
        off = off.checked_add(1 + len)?;
        if off > msg.len() {
            return None;
        }
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
}

fn parse_dns_a_response(msg: &[u8], expected_txid: u16) -> Option<Ipv4Addr> {
    if msg.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([msg[0], msg[1]]);
    if txid != expected_txid {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if (flags & 0x8000) == 0 || (flags & 0x000f) != 0 {
        return None; // Not a response or RCODE != NOERROR
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut off = 12usize;
    for _ in 0..qdcount {
        off = skip_dns_name(msg, off)?;
        off = off.checked_add(4)?;
        if off > msg.len() {
            return None;
        }
    }
    for _ in 0..ancount {
        off = skip_dns_name(msg, off)?;
        if off + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rclass = u16::from_be_bytes([msg[off + 2], msg[off + 3]]);
        let rdlength = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        off += 10;
        if off + rdlength > msg.len() {
            return None;
        }
        if rtype == 1 && rclass == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(msg[off], msg[off + 1], msg[off + 2], msg[off + 3]);
            if is_usable_public_or_lan_ipv4(ip) {
                return Some(ip);
            }
        }
        off += rdlength;
    }
    None
}

/// Resolves `host` via direct UDP A-record queries bound to `if_index`, racing
/// major domestic & global public resolvers so Fake-IP TUN DNS is bypassed.
fn resolve_ipv4_direct(host: &str, if_index: u32) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    let mut rand_bytes = [0u8; 2];
    random_iv_or_salt(&mut rand_bytes);
    let txid = u16::from_be_bytes(rand_bytes);
    let query = build_dns_a_query(host, txid)?;

    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    if if_index != 0 {
        bind_udp_to_if(&sock, if_index).ok()?;
    }
    let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));

    const RESOLVERS: [SocketAddrV4; 3] = [
        SocketAddrV4::new(Ipv4Addr::new(223, 5, 5, 5), 53),
        SocketAddrV4::new(Ipv4Addr::new(119, 29, 29, 29), 53),
        SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53),
    ];
    let mut sent_any = false;
    for server in RESOLVERS {
        if sock.send_to(&query, server).is_ok() {
            sent_any = true;
        }
    }
    if !sent_any {
        return None;
    }

    let deadline = Instant::now() + Duration::from_millis(1600);
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(ip) = parse_dns_a_response(&buf[..n], txid) {
                    return Some(ip);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    None
}

fn resolve_ipv4_smart(host: &str, if_index: u32) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    if if_index != 0 {
        if let Some(ip) = resolve_ipv4_direct(host, if_index) {
            return Some(ip);
        }
    }
    let os_ip = (host, 0u16).to_socket_addrs().ok().and_then(|mut it| {
        it.find_map(|a| match a {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
    });
    if let Some(ip) = os_ip {
        if !is_fake_ip(ip) {
            return Some(ip);
        }
        // OS DNS returned a Clash/FlClash Fake-IP (198.18.0.0/15): try direct DNS!
        if let Some(real_ip) = resolve_ipv4_direct(host, if_index) {
            return Some(real_ip);
        }
        if if_index == 0 {
            return Some(ip);
        }
        return None;
    }
    None
}

/// Resolves `host` to an IPv4 string (free with `vss_free_string`).
#[no_mangle]
pub unsafe extern "C" fn vss_resolve_ipv4(host: *const c_char, if_index: u32) -> *mut c_char {
    if host.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(host_str) = CStr::from_ptr(host).to_str() else {
        return std::ptr::null_mut();
    };
    let effective_if = if if_index != 0 { if_index } else { vss_bypass_if_index() };
    match resolve_ipv4_smart(host_str, effective_if)
        .and_then(|ip| CString::new(ip.to_string()).ok())
    {
        Some(s) => s.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// TCP reachability probe using the same anti-Fake-IP DNS and physical interface
/// binding as SS traffic. Returns handshake latency in ms, or -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn vss_probe_tcp(host: *const c_char, port: u16, timeout_ms: u32) -> i32 {
    if host.is_null() || port == 0 {
        return -1;
    }
    let Ok(host_str) = CStr::from_ptr(host).to_str() else {
        return -1;
    };
    let (if_index, _) = current_bypass();
    let Some(ip) = resolve_ipv4_smart(host_str, if_index) else {
        return -1;
    };
    let target = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let timeout_dur = Duration::from_millis(timeout_ms.clamp(200, 10000) as u64);
    let rt = runtime();
    rt.block_on(async move {
        let Ok(sock) = tokio::net::TcpSocket::new_v4() else {
            return -1;
        };
        if if_index != 0 {
            #[cfg(target_os = "macos")]
            {
                use std::os::unix::io::AsRawFd;
                let _ = bind_socket_to_if_v4(sock.as_raw_fd(), if_index);
            }
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawSocket;
                let _ = bind_socket_to_if_v4(sock.as_raw_socket() as usize, if_index);
            }
        }
        let start = Instant::now();
        match timeout(timeout_dur, sock.connect(target)).await {
            Ok(Ok(_stream)) => start.elapsed().as_millis().min(i32::MAX as u128) as i32,
            _ => -1,
        }
    })
}

// ---- SS 2022 & AEAD Crypto ----------------------------------------------------

thread_local! {
    static UDP_ENC_BUF: RefCell<BytesMut> = RefCell::new(BytesMut::with_capacity(2048));
}

#[inline]
fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pre-expanded AES-ECB cipher for SIP022 16-byte UDP packet header encryption.
enum HeaderEcb {
    None,
    Aes128(Aes128),
    Aes256(Aes256),
}
impl HeaderEcb {
    fn new(method: CipherKind, key: &[u8], identity_keys: &[Bytes]) -> Self {
        if !identity_keys.is_empty() {
            return Self::None; // Multi-user EIH uses crypto_io fallback.
        }
        match method {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => Aes128::new_from_slice(key)
                .map(Self::Aes128)
                .unwrap_or(Self::None),
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => Aes256::new_from_slice(key)
                .map(Self::Aes256)
                .unwrap_or(Self::None),
            _ => Self::None,
        }
    }
    #[inline]
    fn is_some(&self) -> bool {
        !matches!(self, Self::None)
    }
    #[inline]
    fn encrypt_header(&self, header: &mut [u8]) {
        let block = Block::from_mut_slice(header);
        match self {
            Self::Aes128(c) => c.encrypt_block(block),
            Self::Aes256(c) => c.encrypt_block(block),
            Self::None => unreachable!(),
        }
    }
    #[inline]
    fn decrypt_header(&self, header: &mut [u8]) {
        let block = Block::from_mut_slice(header);
        match self {
            Self::Aes128(c) => c.decrypt_block(block),
            Self::Aes256(c) => c.decrypt_block(block),
            Self::None => unreachable!(),
        }
    }
}

#[derive(Deserialize)]
struct Node {
    server: String,
    port: u16,
    cipher: String,
    password: String,
    #[serde(default)]
    tfo: bool,
    #[serde(default)]
    resolved_ip: Option<String>,
}
impl Node {
    fn config(self) -> Option<Endpoint> {
        if self.server.is_empty()
            || self.port == 0
            || self.password.is_empty()
            || !matches!(
                self.cipher.as_str(),
                "aes-128-gcm"
                    | "aes-256-gcm"
                    | "chacha20-ietf-poly1305"
                    | "2022-blake3-aes-128-gcm"
                    | "2022-blake3-aes-256-gcm"
                    | "2022-blake3-chacha20-poly1305"
            )
        {
            return None;
        }
        let address = if let Some(ip) = self
            .resolved_ip
            .as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok())
        {
            ServerAddr::SocketAddr(SocketAddr::new(ip, self.port))
        } else {
            match self.server.parse::<IpAddr>() {
                Ok(ip) => ServerAddr::SocketAddr(SocketAddr::new(ip, self.port)),
                Err(_) => ServerAddr::DomainName(self.server, self.port),
            }
        };
        Some(Endpoint {
            config: ServerConfig::new(address, self.password, self.cipher.parse().ok()?).ok()?,
            tfo: self.tfo,
            resolved_v4: Arc::new(Mutex::new(None)),
        })
    }
}

#[derive(Clone)]
struct Endpoint {
    config: ServerConfig,
    tfo: bool,
    resolved_v4: Arc<Mutex<Option<(u32, SocketAddrV4)>>>,
}
impl Endpoint {
    fn resolved_server_config(&self, if_index: u32) -> Option<ServerConfig> {
        match self.config.addr() {
            ServerAddr::SocketAddr(_) => Some(self.config.clone()),
            ServerAddr::DomainName(host, port) => {
                if let Ok(guard) = self.resolved_v4.lock() {
                    if let Some((cached_if, addr)) = *guard {
                        if cached_if == if_index {
                            let mut cfg = self.config.clone();
                            cfg.set_addr(ServerAddr::SocketAddr(SocketAddr::V4(addr)));
                            return Some(cfg);
                        }
                    }
                }
                let ip = resolve_ipv4_smart(host, if_index)?;
                let v4 = SocketAddrV4::new(ip, *port);
                if let Ok(mut guard) = self.resolved_v4.lock() {
                    *guard = Some((if_index, v4));
                }
                let mut cfg = self.config.clone();
                cfg.set_addr(ServerAddr::SocketAddr(SocketAddr::V4(v4)));
                Some(cfg)
            }
        }
    }
}

/// Shared configuration and resolved server endpoint for a UDP route.
struct UdpNode {
    method: CipherKind,
    key: Box<[u8]>,
    identity_keys: Box<[Bytes]>,
    header_ecb: HeaderEcb,
    ctx: SharedContext,
    host: ServerAddr,
    resolved: Mutex<Option<(u32, SocketAddrV4)>>,
    disconnected: watch::Receiver<bool>,
}
impl UdpNode {
    fn new(
        endpoint: &Endpoint,
        ctx: SharedContext,
        disconnected: watch::Receiver<bool>,
    ) -> Arc<Self> {
        let config = &endpoint.config;
        let method = config.method();
        let key: Box<[u8]> = config.key().into();
        let identity_keys: Box<[Bytes]> = config.identity_keys().into();
        let header_ecb = HeaderEcb::new(method, &key, &identity_keys);
        Arc::new(Self {
            method,
            key,
            identity_keys,
            header_ecb,
            ctx,
            host: config.addr().clone(),
            resolved: Mutex::new(None),
            disconnected,
        })
    }
    fn is_active(&self) -> bool {
        // This receiver never marks updates as seen. The sole update revokes the route.
        matches!(self.disconnected.has_changed(), Ok(false))
    }
    // Moonlight's media sockets are AF_INET, so the node must be reachable over IPv4.
    fn server(&self) -> Option<SocketAddrV4> {
        let if_index = vss_bypass_if_index();
        let mut cached = self.resolved.lock().unwrap();
        if let Some((cached_if, addr)) = *cached {
            if cached_if == if_index {
                return Some(addr);
            }
        }
        let resolved = match &self.host {
            ServerAddr::SocketAddr(SocketAddr::V4(addr)) => Some(*addr),
            ServerAddr::SocketAddr(SocketAddr::V6(_)) => None,
            ServerAddr::DomainName(host, port) => {
                resolve_ipv4_smart(host, if_index).map(|ip| SocketAddrV4::new(ip, *port))
            }
        };
        if let Some(addr) = resolved {
            *cached = Some((if_index, addr));
        }
        resolved
    }
    fn overhead(&self) -> usize {
        match self.method.category() {
            CipherCategory::Aead2022 => {
                let nonce_len = match self.method {
                    CipherKind::AEAD2022_BLAKE3_AES_128_GCM
                    | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => 0,
                    _ => self.method.nonce_len(),
                };
                let eih_len = match self.method {
                    CipherKind::AEAD2022_BLAKE3_AES_128_GCM
                    | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => self.identity_keys.len() * 16,
                    _ => 0,
                };
                nonce_len + 8 + 8 + eih_len + 1 + 8 + 2 + 7 + self.method.tag_len()
            }
            _ => self.method.salt_len() + 7 + self.method.tag_len(),
        }
    }
}

/// Per-socket UDP session state shared with C.
/// Each Moonlight socket owns its own SIP022 `client_session_id`, monotonic `packet_id`,
/// pre-derived client `UdpCipher`, and inline single-slot server `UdpCipher` cache.
pub struct UdpFlow {
    node: Arc<UdpNode>,
    client_session_id: u64,
    packet_id: AtomicU64,
    client_cipher: Option<UdpCipher>,
    server_cache: Mutex<Option<(u64, UdpCipher)>>,
}
impl UdpFlow {
    fn new(node: Arc<UdpNode>) -> Self {
        let mut sid = 0u64;
        while sid == 0 {
            let mut bytes = [0u8; 8];
            random_iv_or_salt(&mut bytes);
            sid = u64::from_be_bytes(bytes);
        }
        let client_cipher = if node.header_ecb.is_some() {
            Some(UdpCipher::new(node.method, &node.key, sid))
        } else {
            None
        };
        Self {
            node,
            client_session_id: sid,
            packet_id: AtomicU64::new(0),
            client_cipher,
            server_cache: Mutex::new(None),
        }
    }
    #[inline]
    fn is_active(&self) -> bool {
        self.node.is_active()
    }
}

struct Routes {
    home_tcp: Endpoint,
    company: Endpoint,
    home_udp_node: Arc<UdpNode>,
    company_udp_node: Arc<UdpNode>,
    ctx: SharedContext,
    disconnected: watch::Sender<bool>,
}

static ROUTES: Mutex<Option<Arc<Routes>>> = Mutex::new(None);
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

#[no_mangle]
pub unsafe extern "C" fn vss_config(json: *const c_char) -> bool {
    if json.is_null() {
        let mut routes = ROUTES.lock().unwrap();
        if let Some(previous) = routes.take() {
            previous.disconnected.send_replace(true);
        }
        return true;
    }
    let Some((home_tcp, home_udp, company)) = (|| {
        let [tcp, udp, company]: [Node; 3] =
            serde_json::from_slice(CStr::from_ptr(json).to_bytes()).ok()?;
        Some((tcp.config()?, udp.config()?, company.config()?))
    })() else {
        return false;
    };
    let mut routes = ROUTES.lock().unwrap();
    // Refreshes affect new connections. Disconnect also revokes connections that predate them.
    let disconnected = routes.as_ref().map_or_else(
        || watch::channel(false).0,
        |previous| previous.disconnected.clone(),
    );
    let inactive = disconnected.subscribe();
    let ctx = Context::new_shared(ServerType::Local);
    *routes = Some(Arc::new(Routes {
        home_udp_node: UdpNode::new(&home_udp, ctx.clone(), inactive.clone()),
        company_udp_node: UdpNode::new(&company, ctx.clone(), inactive),
        home_tcp,
        company,
        ctx,
        disconnected,
    }));
    true
}

fn current() -> Option<Arc<Routes>> {
    ROUTES.lock().unwrap().clone()
}

/// Selects the UDP node for an IPv4 destination (host order), resolves its server,
/// and creates a per-socket UDP flow (with a unique SIP022 session ID).
/// Caller releases with `vss_udp_release`.
#[no_mangle]
pub unsafe extern "C" fn vss_udp_acquire(
    ip: u32,
    server_ip: *mut u32,
    server_port: *mut u16,
) -> *const UdpFlow {
    let Some(routes) = current() else {
        return std::ptr::null();
    };
    let node = match ip >> 8 {
        0x0a0000 => &routes.home_udp_node,
        0x0a0101 => &routes.company_udp_node,
        _ => return std::ptr::null(),
    };
    let Some(server) = node.server() else {
        return std::ptr::null();
    };
    if !node.is_active() {
        return std::ptr::null();
    }
    *server_ip = u32::from(*server.ip());
    *server_port = server.port();
    Box::into_raw(Box::new(UdpFlow::new(node.clone())))
}

#[no_mangle]
pub unsafe extern "C" fn vss_udp_release(flow: *const UdpFlow) {
    if !flow.is_null() {
        drop(Box::from_raw(flow as *mut UdpFlow));
    }
}

#[no_mangle]
pub unsafe extern "C" fn vss_udp_overhead(flow: *const UdpFlow) -> usize {
    (*flow).node.overhead()
}

#[no_mangle]
pub unsafe extern "C" fn vss_udp_is_active(flow: *const UdpFlow) -> bool {
    (*flow).is_active()
}

/// Encrypts one outbound UDP datagram into `out`.
/// Supports both legacy AEAD and AEAD-2022 (`2022-blake3-*`).
#[no_mangle]
pub unsafe extern "C" fn vss_udp_encrypt(
    flow: *const UdpFlow,
    ip: u32,
    port: u16,
    data: *const u8,
    len: usize,
    out: *mut u8,
    cap: usize,
) -> isize {
    let flow = &*flow;
    let node = &flow.node;
    if !flow.is_active() {
        return -1;
    }
    if node.method.category() == CipherCategory::Aead2022 {
        if len > 0 {
            if let Some(ref cipher) = flow.client_cipher {
                let total = 34 + len + 16;
                if total > cap {
                    return -1;
                }
                let pkt = slice::from_raw_parts_mut(out, total);
                let pid = flow.packet_id.fetch_add(1, Ordering::Relaxed);
                pkt[0..8].copy_from_slice(&flow.client_session_id.to_be_bytes());
                pkt[8..16].copy_from_slice(&pid.to_be_bytes());
                pkt[16] = AEAD2022_CLIENT_TYPE;
                pkt[17..25].copy_from_slice(&unix_now_secs().to_be_bytes());
                pkt[25..27].copy_from_slice(&0u16.to_be_bytes());
                pkt[27] = 1; // ATYP_V4
                pkt[28..32].copy_from_slice(&ip.to_be_bytes());
                pkt[32..34].copy_from_slice(&port.to_be_bytes());
                pkt[34..34 + len].copy_from_slice(slice::from_raw_parts(data, len));
                let (header, body) = pkt.split_at_mut(16);
                cipher.encrypt_packet(&header[4..16], body);
                node.header_ecb.encrypt_header(header);
                return total as isize;
            }
        }
        let payload = if len > 0 {
            slice::from_raw_parts(data, len)
        } else {
            &[]
        };
        let addr =
            Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)));
        let mut control = UdpSocketControlData::default();
        control.client_session_id = flow.client_session_id;
        control.packet_id = flow.packet_id.fetch_add(1, Ordering::Relaxed);
        return UDP_ENC_BUF.with(|cell| {
            let mut dst = cell.borrow_mut();
            dst.clear();
            encrypt_client_payload(
                &node.ctx,
                node.method,
                &node.key,
                &addr,
                &control,
                &node.identity_keys,
                payload,
                &mut dst,
            );
            if dst.len() > cap {
                return -1;
            }
            slice::from_raw_parts_mut(out, dst.len()).copy_from_slice(&dst);
            dst.len() as isize
        });
    }
    let salt_len = node.method.salt_len();
    let total = len + node.overhead();
    if total > cap {
        return -1;
    }
    let out = slice::from_raw_parts_mut(out, total);
    let (salt, body) = out.split_at_mut(salt_len);
    random_iv_or_salt(salt);
    body[0] = 1;
    body[1..5].copy_from_slice(&ip.to_be_bytes());
    body[5..7].copy_from_slice(&port.to_be_bytes());
    if len > 0 {
        body[7..7 + len].copy_from_slice(slice::from_raw_parts(data, len));
    }
    Cipher::new(node.method, &node.key, salt).encrypt_packet(body);
    total as isize
}

/// Decrypts an inbound UDP datagram in place without moving the payload.
/// Writes the payload byte offset within `buf` to `*offset`, sender to `*ip`/`*port`.
#[no_mangle]
pub unsafe extern "C" fn vss_udp_decrypt_view(
    flow: *const UdpFlow,
    buf: *mut u8,
    len: usize,
    offset: *mut usize,
    ip: *mut u32,
    port: *mut u16,
) -> isize {
    let flow = &*flow;
    let node = &flow.node;
    if !flow.is_active() {
        return -1;
    }
    if node.method.category() == CipherCategory::Aead2022 {
        if node.header_ecb.is_some() {
            if len < 58 {
                return -1;
            }
            let packet = slice::from_raw_parts_mut(buf, len);
            let (header, body) = packet.split_at_mut(16);
            node.header_ecb.decrypt_header(header);
            let server_sid = u64::from_be_bytes(header[0..8].try_into().unwrap());
            let nonce = &header[4..16];
            let ok = {
                let mut cache = flow.server_cache.lock().unwrap();
                let need_new = match *cache {
                    Some((sid, _)) => sid != server_sid,
                    None => true,
                };
                if need_new {
                    *cache = Some((server_sid, UdpCipher::new(node.method, &node.key, server_sid)));
                }
                cache.as_ref().unwrap().1.decrypt_packet(nonce, body)
            };
            if !ok {
                return -1;
            }
            let plain = &body[..body.len() - 16];
            if plain[0] != AEAD2022_SERVER_TYPE {
                return -1;
            }
            let ts = u64::from_be_bytes(plain[1..9].try_into().unwrap());
            if unix_now_secs().abs_diff(ts) > AEAD2022_MAX_TS_DIFF {
                return -1;
            }
            let csid = u64::from_be_bytes(plain[9..17].try_into().unwrap());
            if csid != flow.client_session_id {
                return -1;
            }
            let pad_len = u16::from_be_bytes([plain[17], plain[18]]) as usize;
            let addr_off = 19usize.saturating_add(pad_len);
            if addr_off + 7 > plain.len() || plain[addr_off] != 1 {
                return -1;
            }
            *ip = u32::from_be_bytes(plain[addr_off + 1..addr_off + 5].try_into().unwrap());
            *port = u16::from_be_bytes([plain[addr_off + 5], plain[addr_off + 6]]);
            *offset = 16 + addr_off + 7;
            return (plain.len() - (addr_off + 7)) as isize;
        }
        let packet = slice::from_raw_parts_mut(buf, len);
        let Ok((plain_len, addr, control)) =
            decrypt_server_payload(&node.ctx, node.method, &node.key, packet)
        else {
            return -1;
        };
        if let Some(ctrl) = control {
            if ctrl.client_session_id != flow.client_session_id {
                return -1;
            }
        }
        let Address::SocketAddress(SocketAddr::V4(v4)) = addr else {
            return -1;
        };
        *ip = u32::from(*v4.ip());
        *port = v4.port();
        *offset = 0;
        return plain_len as isize;
    }
    let (salt_len, tag_len) = (node.method.salt_len(), node.method.tag_len());
    if len < node.overhead() {
        return -1;
    }
    let packet = slice::from_raw_parts_mut(buf, len);
    let (salt, body) = packet.split_at_mut(salt_len);
    if !Cipher::new(node.method, &node.key, salt).decrypt_packet(body) {
        return -1;
    }
    let plain = &body[..body.len() - tag_len];
    if plain[0] != 1 {
        return -1; // The host only ever answers from an IPv4 address.
    }
    *ip = u32::from_be_bytes(plain[1..5].try_into().unwrap());
    *port = u16::from_be_bytes([plain[5], plain[6]]);
    *offset = salt_len + 7;
    (plain.len() - 7) as isize
}

/// Decrypts a datagram in place and moves its payload to the start of `buf`.
/// Returns the payload length and the original IPv4 sender, or -1 to drop it.
#[no_mangle]
pub unsafe extern "C" fn vss_udp_decrypt(
    flow: *const UdpFlow,
    buf: *mut u8,
    len: usize,
    ip: *mut u32,
    port: *mut u16,
) -> isize {
    let mut start = 0usize;
    let payload = vss_udp_decrypt_view(flow, buf, len, &mut start, ip, port);
    if payload < 0 {
        return -1;
    }
    let payload = payload as usize;
    if start > 0 {
        let packet = slice::from_raw_parts_mut(buf, len);
        packet.copy_within(start..start + payload, 0);
    }
    payload as isize
}

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("moonlight-ss")
            .build()
            .unwrap()
    })
}

/// TCP endpoint for a routed IPv4 destination (host order).
fn tcp_node(routes: &Routes, ip: u32) -> Option<Endpoint> {
    match ip >> 8 {
        0x0a0000 => Some(routes.home_tcp.clone()),
        0x0a0101 => Some(routes.company.clone()),
        _ => None,
    }
}

fn loopback(port: u16) -> SocketAddr {
    (Ipv4Addr::LOCALHOST, port).into()
}

async fn while_connected<T>(
    mut disconnected: watch::Receiver<bool>,
    operation: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = disconnected.wait_for(|closed| *closed) => None,
        result = operation => Some(result),
    }
}

async fn connect_ss_stream(
    ctx: SharedContext,
    node: &Endpoint,
    addr: Address,
) -> Option<ProxyClientStream<shadowsocks::net::TcpStream>> {
    let (if_index, if_name) = current_bypass();
    let cfg = if if_index != 0 {
        let ep = node.clone();
        tokio::task::spawn_blocking(move || ep.resolved_server_config(if_index))
            .await
            .ok()??
    } else {
        let ep = node.clone();
        tokio::task::spawn_blocking(move || ep.resolved_server_config(0))
            .await
            .ok()??
    };
    let mut opts = shadowsocks::net::ConnectOpts::default();
    opts.tcp.nodelay = true;
    opts.tcp.fastopen = node.tfo;
    if if_index != 0 {
        opts.bind_interface = if_name;
    }
    let mut proxy = timeout(
        Duration::from_secs(10),
        ProxyClientStream::connect_with_opts(ctx, &cfg, addr, &opts),
    )
    .await
    .ok()?
    .ok()?;
    // Flush the SS handshake immediately so server-speaks-first protocols do not stall.
    timeout(Duration::from_secs(10), proxy.write(&[]))
        .await
        .ok()?
        .ok()?;
    Some(proxy)
}

/// Opens a one-shot loopback TCP relay that accepts only `source`.
fn forward_tcp(ip: u32, port: u16, source: u16) -> Option<u16> {
    let routes = current()?;
    let node = tcp_node(&routes, ip)?;
    let ctx = routes.ctx.clone();
    let disconnected = routes.disconnected.subscribe();
    let addr = Address::SocketAddress((Ipv4Addr::from(ip), port).into());
    let runtime = runtime();
    let _guard = runtime.enter();
    let listener = std::net::TcpListener::bind(loopback(0)).ok()?;
    let local = listener.local_addr().ok()?.port();
    listener.set_nonblocking(true).ok()?;
    let listener = TcpListener::from_std(listener).ok()?;
    runtime.spawn(while_connected(disconnected, async move {
        let accept = async {
            loop {
                let (s, peer) = listener.accept().await.ok()?;
                if peer == loopback(source) {
                    return Some(s);
                }
            }
        };
        let Ok(Some(mut client)) = timeout(Duration::from_secs(10), accept).await else {
            return;
        };
        drop(listener);
        let _ = client.set_nodelay(true);
        let Some(mut proxy) = connect_ss_stream(ctx, &node, addr).await else {
            return;
        };
        let _ = copy_bidirectional(&mut client, &mut proxy).await;
    }));
    Some(local)
}

#[no_mangle]
pub extern "C" fn vss_open_tcp(ip: u32, port: u16, source: u16) -> u16 {
    forward_tcp(ip, port, source).unwrap_or(0)
}

// ---- SOCKS5 endpoint for Qt networking ----------------------------------------

static SOCKS_PORT: OnceLock<u16> = OnceLock::new();

/// Starts (once) a loopback SOCKS5 server that only CONNECTs to routed IPv4
/// hosts through their SS node. Returns its port, or 0 on failure.
#[no_mangle]
pub extern "C" fn vss_socks_port() -> u16 {
    *SOCKS_PORT.get_or_init(|| start_socks().unwrap_or(0))
}

fn start_socks() -> Option<u16> {
    let runtime = runtime();
    let _guard = runtime.enter();
    let listener = std::net::TcpListener::bind(loopback(0)).ok()?;
    let port = listener.local_addr().ok()?.port();
    listener.set_nonblocking(true).ok()?;
    let listener = TcpListener::from_std(listener).ok()?;
    runtime.spawn(async move {
        loop {
            let Ok((client, peer)) = listener.accept().await else {
                continue;
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            tokio::spawn(async move {
                let _ = socks_session(client).await;
            });
        }
    });
    Some(port)
}

async fn socks_reply(client: &mut TcpStream, code: u8) -> std::io::Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

async fn socks_session(mut client: TcpStream) -> std::io::Result<()> {
    let _ = client.set_nodelay(true);
    let handshake = async {
        let mut head = [0u8; 2];
        client.read_exact(&mut head).await?;
        let mut methods = vec![0u8; head[1] as usize];
        client.read_exact(&mut methods).await?;
        if head[0] != 5 || !methods.contains(&0) {
            client.write_all(&[5, 0xff]).await?;
            return Ok(None);
        }
        client.write_all(&[5, 0]).await?;
        let mut request = [0u8; 4];
        client.read_exact(&mut request).await?;
        if request[1] != 1 {
            socks_reply(&mut client, 7).await?; // command not supported
            return Ok(None);
        }
        if request[3] != 1 {
            socks_reply(&mut client, 8).await?; // only IPv4 destinations are routed
            return Ok(None);
        }
        let mut target = [0u8; 6];
        client.read_exact(&mut target).await?;
        let ip = u32::from_be_bytes([target[0], target[1], target[2], target[3]]);
        let port = u16::from_be_bytes([target[4], target[5]]);
        std::io::Result::Ok(Some((ip, port)))
    };
    let Ok(Ok(Some((ip, port)))) = timeout(Duration::from_secs(10), handshake).await else {
        return Ok(());
    };
    let Some(routes) = current() else {
        return socks_reply(&mut client, 2).await; // not allowed by ruleset
    };
    let Some(node) = tcp_node(&routes, ip) else {
        return socks_reply(&mut client, 2).await;
    };
    let ctx = routes.ctx.clone();
    let disconnected = routes.disconnected.subscribe();
    drop(routes);
    while_connected(disconnected, forward_socks(client, ip, port, node, ctx))
        .await
        .unwrap_or(Ok(()))
}

async fn forward_socks(
    mut client: TcpStream,
    ip: u32,
    port: u16,
    node: Endpoint,
    ctx: SharedContext,
) -> std::io::Result<()> {
    let addr = Address::SocketAddress((Ipv4Addr::from(ip), port).into());
    let Some(mut proxy) = connect_ss_stream(ctx, &node, addr).await else {
        return socks_reply(&mut client, 5).await; // connection refused
    };
    socks_reply(&mut client, 0).await?;
    let _ = copy_bidirectional(&mut client, &mut proxy).await;
    Ok(())
}

// ---- Clash subscription parsing -----------------------------------------------

fn parse_subscription(yaml: &str, udp: bool) -> Result<serde_json::Value, &'static str> {
    let root: serde_yaml::Value =
        serde_yaml::from_str(yaml.trim_start_matches('\u{feff}')).map_err(|_| "yaml_no_proxies")?;
    let proxies = root
        .get("proxies")
        .and_then(|v| v.as_sequence())
        .ok_or("yaml_no_proxies")?;
    let mut found = None;
    for entry in proxies {
        if entry.get("type").and_then(|t| t.as_str()) != Some("ss") {
            continue;
        }
        if udp && entry.get("udp").and_then(|u| u.as_bool()) == Some(false) {
            continue;
        }
        if found.is_some() {
            return Err("yaml_node_count"); // exactly one usable SS node per subscription
        }
        found = Some(entry);
    }
    let entry = found.ok_or("yaml_node_count")?;
    if entry.get("plugin").map_or(false, |p| !p.is_null())
        || entry.get("udp-over-tcp").and_then(|u| u.as_bool()) == Some(true)
    {
        return Err("plugin_unsupported");
    }
    let text = |key: &str| -> Option<String> {
        let value = entry.get(key)?;
        value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.as_u64().map(|n| n.to_string()))
    };
    let port = entry
        .get("port")
        .and_then(|p| p.as_u64().or_else(|| text("port")?.parse().ok()))
        .ok_or("invalid_node")?;
    Ok(serde_json::json!({
        "server": text("server").ok_or("invalid_node")?,
        "port": port,
        "cipher": text("cipher").ok_or("invalid_node")?,
        "password": text("password").ok_or("invalid_node")?,
        "tfo": entry.get("tfo").and_then(|t| t.as_bool()).unwrap_or(false),
    }))
}

/// Returns the single SS node of a Clash subscription as JSON, or `{"error":"..."}`
/// describing why parsing failed (free with `vss_free_string`).
#[no_mangle]
pub unsafe extern "C" fn vss_parse_subscription(yaml: *const c_char, udp: bool) -> *mut c_char {
    if yaml.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(text) = CStr::from_ptr(yaml).to_str() else {
        return std::ptr::null_mut();
    };
    let value = match parse_subscription(text, udp) {
        Ok(node) => node,
        Err(code) => serde_json::json!({ "error": code }),
    };
    match CString::new(value.to_string()) {
        Ok(json) => json.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vss_free_string(text: *mut c_char) {
    if !text.is_null() {
        drop(CString::from_raw(text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks::{
        crypto::CipherKind,
        relay::udprelay::crypto_io::{decrypt_client_payload, encrypt_server_payload},
        ProxyListener, ProxySocket,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpSocket,
    };

    fn test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[test]
    fn subscription_yaml() {
        let yaml = "\u{feff}proxies:\n  - {name: a, type: vmess, server: x}\n  - name: home\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: 2022-blake3-aes-128-gcm\n    password: \"AQIDBAUGBwgJCgsMDQ4PEA==\"\n    udp: true\n";
        let node = parse_subscription(yaml, true).unwrap();
        assert_eq!(node["server"], "1.2.3.4");
        assert_eq!(node["port"], 8388);
        assert_eq!(node["cipher"], "2022-blake3-aes-128-gcm");
        assert_eq!(
            parse_subscription(&yaml.replace("udp: true", "udp: false"), true),
            Err("yaml_node_count")
        );
        assert_eq!(
            parse_subscription(&yaml.replace("udp: true", "plugin: obfs"), false),
            Err("plugin_unsupported")
        );
        assert_eq!(parse_subscription("proxies: []", false), Err("yaml_node_count"));
        assert_eq!(parse_subscription("foo: bar", false), Err("yaml_no_proxies"));
    }

    #[test]
    fn dns_packet_encode_decode_and_fake_ip_filter() {
        assert!(is_fake_ip(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_fake_ip(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(!is_fake_ip(Ipv4Addr::new(198, 20, 0, 1)));
        assert!(!is_fake_ip(Ipv4Addr::new(10, 0, 0, 1)));

        let txid = 0x4242;
        let query = build_dns_a_query("b.crak.cn", txid).unwrap();
        assert_eq!(&query[0..2], &[0x42, 0x42]);
        // Craft a synthetic DNS response containing one Fake-IP A record and one real A record.
        let mut resp = query.clone();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1, NOERROR
        resp[6] = 0x00;
        resp[7] = 0x02; // ANCOUNT=2
        // Answer 1: compressed name 0xc00c, A, IN, TTL 60, RDLEN 4, 198.18.0.55 (must be skipped!)
        resp.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 0, 55]);
        // Answer 2: compressed name 0xc00c, A, IN, TTL 60, RDLEN 4, 203.0.113.9
        resp.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
        assert_eq!(
            parse_dns_a_response(&resp, txid),
            Some(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(parse_dns_a_response(&resp, txid ^ 1), None);
    }

    fn node_json(port: u16, key: &str) -> serde_json::Value {
        serde_json::json!({"server":"127.0.0.1","port":port,"cipher":"aes-256-gcm","password":key})
    }

    async fn assert_relay_closed(stream: &mut TcpStream) {
        match timeout(Duration::from_secs(2), stream.read(&mut [0])).await {
            Ok(Ok(0)) => (),
            Ok(Err(err))
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => (),
            result => panic!("established relay did not close after disconnect: {result:?}"),
        }
    }

    // Distinct listeners and keys make swapping either home subscription observable.
    #[tokio::test(flavor = "multi_thread")]
    async fn split_routes_preserve_destinations_and_return_traffic() {
        let _guard = test_lock().lock().await;
        timeout(Duration::from_secs(10), async {
            let server = Context::new_shared(ServerType::Server);
            let mut nodes = Vec::new();
            for slot in 0..3 {
                let key = format!("local-test-{slot}");
                let mut config =
                    ServerConfig::new(loopback(0), &key, CipherKind::AES_256_GCM).unwrap();
                let tcp = ProxyListener::bind(server.clone(), &config).await.unwrap();
                let addr = tcp.local_addr().unwrap();
                config.set_addr(addr);
                let udp = ProxySocket::bind(server.clone(), &config).await.unwrap();
                nodes.push(node_json(addr.port(), &key));
                let target_ip = if slot == 2 { "10.1.1.70" } else { "10.0.0.80" };
                if slot != 1 {
                    tokio::spawn(async move {
                        while let Ok((mut stream, _)) = tcp.accept().await {
                            tokio::spawn(async move {
                                assert_eq!(
                                    stream.handshake().await.unwrap().to_string(),
                                    format!("{target_ip}:50201")
                                );
                                let mut payload = [0; 4];
                                while stream.read_exact(&mut payload).await.is_ok() {
                                    stream.write_all(&payload).await.unwrap();
                                }
                            });
                        }
                    });
                }
                if slot != 0 {
                    tokio::spawn(async move {
                        let mut payload = vec![0; 65536];
                        let (n, peer, target, _) = udp.recv_from(&mut payload).await.unwrap();
                        assert_eq!(target.to_string(), format!("{target_ip}:50301"));
                        udp.send_to(peer, &target, &payload[..n]).await.unwrap();
                    });
                }
            }
            let json = CString::new(serde_json::to_vec(&nodes).unwrap()).unwrap();
            assert!(unsafe { vss_config(json.as_ptr()) });
            let (mut sip, mut sport) = (0u32, 0u16);
            assert!(unsafe { vss_udp_acquire(0x0a020201, &mut sip, &mut sport) }.is_null());
            let mut tcp_relays = Vec::new();
            for ip in [0x0a000050u32, 0x0a010146] {
                let client = TcpSocket::new_v4().unwrap();
                client.bind(loopback(0)).unwrap();
                let port = vss_open_tcp(ip, 50201, client.local_addr().unwrap().port());
                let mut stream = client.connect(loopback(port)).await.unwrap();
                stream.write_all(b"ping").await.unwrap();
                let mut result = [0; 4];
                stream.read_exact(&mut result).await.unwrap();
                assert_eq!(&result, b"ping");
                tcp_relays.push(stream);

                // Direct UDP: the same socket talks to the SS server with in-place crypto.
                let node = unsafe { vss_udp_acquire(ip, &mut sip, &mut sport) };
                assert!(!node.is_null());
                let socket = std::net::UdpSocket::bind(loopback(0)).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let payload = [0x5a; 1200];
                let mut out = vec![0; 2048];
                let n = unsafe {
                    vss_udp_encrypt(
                        node,
                        ip,
                        50301,
                        payload.as_ptr(),
                        payload.len(),
                        out.as_mut_ptr(),
                        out.len(),
                    )
                };
                assert!(n > 1200);
                let server = SocketAddr::from((Ipv4Addr::from(sip), sport));
                socket.send_to(&out[..n as usize], server).unwrap();
                let mut reply = vec![0; 2048];
                let got = tokio::task::spawn_blocking(move || {
                    let (len, from) = socket.recv_from(&mut reply).unwrap();
                    (reply, len, from)
                })
                .await
                .unwrap();
                assert_eq!(got.2, server);
                let mut reply = got.0;
                let (mut from_ip, mut from_port) = (0u32, 0u16);
                let len = unsafe {
                    vss_udp_decrypt(node, reply.as_mut_ptr(), got.1, &mut from_ip, &mut from_port)
                };
                assert_eq!(len, 1200);
                assert_eq!((from_ip, from_port), (ip, 50301));
                assert_eq!(&reply[..1200], &payload[..]);
                reply[20] ^= 1;
                assert_eq!(
                    unsafe {
                        vss_udp_decrypt(
                            node,
                            reply.as_mut_ptr(),
                            got.1,
                            &mut from_ip,
                            &mut from_port,
                        )
                    },
                    -1
                );
                unsafe { vss_udp_release(node) };
            }
            // Qt path: SOCKS5 CONNECT to a routed host reaches the SS echo server.
            let socks = vss_socks_port();
            assert_ne!(socks, 0);
            let mut stream = TcpStream::connect(loopback(socks)).await.unwrap();
            stream.write_all(&[5, 1, 0]).await.unwrap();
            let mut greet = [0; 2];
            stream.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [5, 0]);
            stream
                .write_all(&[5, 1, 0, 1, 10, 0, 0, 80, 0xc4, 0x19])
                .await
                .unwrap();
            let mut reply = [0; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0);
            stream.write_all(b"ping").await.unwrap();
            let mut echo = [0; 4];
            stream.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"ping");
            tcp_relays.push(stream);
            // Unrouted destinations are refused.
            let mut stream = TcpStream::connect(loopback(socks)).await.unwrap();
            stream.write_all(&[5, 1, 0]).await.unwrap();
            stream.read_exact(&mut greet).await.unwrap();
            stream
                .write_all(&[5, 1, 0, 1, 192, 168, 1, 2, 0, 80])
                .await
                .unwrap();
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 2);

            let ip = 0x0a000050;
            let node = unsafe { vss_udp_acquire(ip, &mut sip, &mut sport) };
            assert!(!node.is_null());
            let mut packet = [0; 128];
            let payload = b"udp";
            let send = |packet: &mut [u8]| unsafe {
                vss_udp_encrypt(
                    node,
                    ip,
                    50301,
                    payload.as_ptr(),
                    payload.len(),
                    packet.as_mut_ptr(),
                    packet.len(),
                )
            };
            let len = send(&mut packet);
            assert!(len > 0);
            let relay_source = TcpSocket::new_v4().unwrap();
            relay_source.bind(loopback(0)).unwrap();
            let pending_relay = vss_open_tcp(ip, 50201, relay_source.local_addr().unwrap().port());
            assert_ne!(pending_relay, 0);

            assert!(unsafe { vss_config(json.as_ptr()) });
            assert!(unsafe { vss_udp_is_active(node) });
            assert!(unsafe { vss_config(std::ptr::null()) });
            for relay in &mut tcp_relays {
                assert_relay_closed(relay).await;
            }
            assert_eq!(vss_open_tcp(ip, 50301, 44000), 0);
            assert!(!unsafe { vss_udp_is_active(node) });
            assert_eq!(send(&mut packet), -1);
            assert_eq!(
                unsafe {
                    vss_udp_decrypt(node, packet.as_mut_ptr(), len as usize, &mut sip, &mut sport)
                },
                -1
            );

            assert!(unsafe { vss_config(json.as_ptr()) });
            if let Ok(mut pending) = relay_source.connect(loopback(pending_relay)).await {
                assert_relay_closed(&mut pending).await;
            }
            assert_eq!(send(&mut packet), -1);
            let new_node = unsafe { vss_udp_acquire(ip, &mut sip, &mut sport) };
            assert!(!new_node.is_null() && unsafe { vss_udp_is_active(new_node) });
            unsafe {
                vss_udp_release(node);
                vss_udp_release(new_node);
                vss_config(std::ptr::null());
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn aead_2022_tcp_socks_and_udp_zero_copy_roundtrip() {
        let _guard = test_lock().lock().await;
        let cases = [
            (
                "2022-blake3-aes-128-gcm",
                CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
                "AQIDBAUGBwgJCgsMDQ4PEA==",
            ),
            (
                "2022-blake3-aes-256-gcm",
                CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
                "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
            ),
            (
                "2022-blake3-chacha20-poly1305",
                CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
                "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
            ),
        ];
        timeout(Duration::from_secs(15), async {
            for (cipher_name, method, psk) in cases {
                let server_ctx = Context::new_shared(ServerType::Server);
                let mut nodes = Vec::new();
                let mut server_task = None;
                let mut udp_key = Vec::new();
                for slot in 0..3 {
                    let mut config = ServerConfig::new(loopback(0), psk, method).unwrap();
                    let tcp = ProxyListener::bind(server_ctx.clone(), &config).await.unwrap();
                    let addr = tcp.local_addr().unwrap();
                    config.set_addr(addr);
                    if slot == 2 {
                        udp_key = config.key().to_vec();
                        server_task = Some(tokio::spawn(async move {
                            let (mut stream, _) = tcp.accept().await.unwrap();
                            assert_eq!(
                                stream.handshake().await.unwrap().to_string(),
                                "10.1.1.20:47984"
                            );
                            // Server-speaks-first banner before reading client bytes
                            stream.write_all(&[0x5a_u8; 16]).await.unwrap();
                            let mut req = [0_u8; 4];
                            stream.read_exact(&mut req).await.unwrap();
                            assert_eq!(&req, b"ping");
                            stream.write_all(b"pong").await.unwrap();
                        }));
                    }
                    nodes.push(serde_json::json!({
                        "server": "127.0.0.1",
                        "port": addr.port(),
                        "cipher": cipher_name,
                        "password": psk,
                    }));
                }
                let json = CString::new(serde_json::to_vec(&nodes).unwrap()).unwrap();
                assert!(
                    unsafe { vss_config(json.as_ptr()) },
                    "vss_config failed for {cipher_name}"
                );

                // 1. TCP relay E2E + server-speaks-first over AEAD-2022
                let client = TcpSocket::new_v4().unwrap();
                client.bind(loopback(0)).unwrap();
                let port = vss_open_tcp(0x0a010114, 47984, client.local_addr().unwrap().port());
                assert_ne!(port, 0);
                let mut stream = client.connect(loopback(port)).await.unwrap();
                let mut banner = [0_u8; 16];
                stream.read_exact(&mut banner).await.unwrap();
                assert_eq!(banner, [0x5a_u8; 16]);
                stream.write_all(b"ping").await.unwrap();
                let mut resp = [0_u8; 4];
                stream.read_exact(&mut resp).await.unwrap();
                assert_eq!(&resp, b"pong");
                server_task.unwrap().await.unwrap();

                // 2. UDP client -> server -> client E2E over AEAD-2022 (zero-copy view)
                let (mut sip, mut sport) = (0u32, 0u16);
                let flow = unsafe { vss_udp_acquire(0x0a010114, &mut sip, &mut sport) };
                assert!(!flow.is_null());
                let overhead = unsafe { vss_udp_overhead(flow) };
                for (pkt_idx, payload_len) in [0usize, 1024, 1024].into_iter().enumerate() {
                    let payload: Vec<u8> = (0..payload_len)
                        .map(|i| ((i + pkt_idx * 17) & 0xff) as u8)
                        .collect();
                    let cap = (if payload_len == 0 { 900 } else { payload_len }) + overhead;
                    let mut wire = vec![0u8; cap];
                    let n = unsafe {
                        vss_udp_encrypt(
                            flow,
                            0x0a010114,
                            47998,
                            payload.as_ptr(),
                            payload.len(),
                            wire.as_mut_ptr(),
                            wire.len(),
                        )
                    };
                    assert!(n > 0);
                    wire.truncate(n as usize);

                    let (plain_len, dst_addr, ctrl) =
                        decrypt_client_payload(&server_ctx, method, &udp_key, &mut wire, None)
                            .expect("server decrypt_client_payload failed");
                    assert_eq!(plain_len, payload.len());
                    assert_eq!(&wire[..plain_len], &payload[..]);
                    assert_eq!(dst_addr.to_string(), "10.1.1.20:47998");
                    let client_ctrl = ctrl.expect("missing AEAD-2022 control data");
                    assert_eq!(client_ctrl.packet_id, pkt_idx as u64);

                    let mut reply_ctrl = UdpSocketControlData::default();
                    reply_ctrl.server_session_id = if pkt_idx == 2 {
                        0x8877665544332211
                    } else {
                        0x1122334455667788
                    };
                    reply_ctrl.client_session_id = client_ctrl.client_session_id;
                    reply_ctrl.packet_id = pkt_idx as u64;
                    let mut reply_wire = BytesMut::with_capacity(2048);
                    encrypt_server_payload(
                        &server_ctx,
                        method,
                        &udp_key,
                        &dst_addr,
                        &reply_ctrl,
                        &payload,
                        &mut reply_wire,
                    );

                    let (mut off, mut from_ip, mut from_port) = (0usize, 0u32, 0u16);
                    let got = unsafe {
                        vss_udp_decrypt_view(
                            flow,
                            reply_wire.as_mut_ptr(),
                            reply_wire.len(),
                            &mut off,
                            &mut from_ip,
                            &mut from_port,
                        )
                    };
                    assert_eq!(got as usize, payload.len());
                    if matches!(
                        method,
                        CipherKind::AEAD2022_BLAKE3_AES_128_GCM
                            | CipherKind::AEAD2022_BLAKE3_AES_256_GCM
                    ) {
                        assert!(off >= 42);
                    } else {
                        assert_eq!(off, 0);
                    }
                    assert_eq!((from_ip, from_port), (0x0a010114, 47998));
                    assert_eq!(&reply_wire[off..off + payload.len()], &payload[..]);

                    // Wrong client_session_id must be rejected
                    reply_ctrl.client_session_id ^= 1;
                    let mut bad_reply = BytesMut::with_capacity(2048);
                    encrypt_server_payload(
                        &server_ctx,
                        method,
                        &udp_key,
                        &dst_addr,
                        &reply_ctrl,
                        &payload,
                        &mut bad_reply,
                    );
                    assert_eq!(
                        unsafe {
                            vss_udp_decrypt_view(
                                flow,
                                bad_reply.as_mut_ptr(),
                                bad_reply.len(),
                                &mut off,
                                &mut from_ip,
                                &mut from_port,
                            )
                        },
                        -1
                    );
                }

                unsafe { vss_udp_release(flow) };
                assert!(unsafe { vss_config(std::ptr::null()) });
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn bypass_interface_and_probe_roundtrip() {
        let name = CString::new("en0").unwrap();
        unsafe { vss_set_bypass_interface(14, name.as_ptr()) };
        assert_eq!(vss_bypass_if_index(), 14);
        assert_eq!(current_bypass(), (14, Some("en0".to_owned())));
        unsafe { vss_set_bypass_interface(0, std::ptr::null()) };
        assert_eq!(vss_bypass_if_index(), 0);
        assert_eq!(current_bypass(), (0, None));

        // Local TCP probe against an ephemeral loopback listener.
        let listener = std::net::TcpListener::bind(loopback(0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let host = CString::new("127.0.0.1").unwrap();
        let latency = unsafe { vss_probe_tcp(host.as_ptr(), port, 1000) };
        assert!(latency >= 0, "expected >= 0 ms, got {latency}");
    }
}
