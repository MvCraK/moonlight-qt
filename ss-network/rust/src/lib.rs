// SS-NETWORK extension (see ss-network/README.md).
// UDP media is encrypted/decrypted in place on moonlight-common-c's own sockets
// (see shim/ss_shim.c). Setup TCP from common-c uses the one-shot loopback relay,
// and Qt networking (HTTP pairing, polling, USB/file tunnels) uses the local
// SOCKS5 endpoint below. Subscription YAML is parsed here as well.
use serde::Deserialize;
use shadowsocks::{
    config::{ServerAddr, ServerType},
    context::{Context, SharedContext},
    crypto::{
        v1::{random_iv_or_salt, Cipher},
        CipherKind,
    },
    relay::socks5::Address,
    ProxyClientStream, ServerConfig,
};
use std::{
    ffi::CStr,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    os::raw::c_char,
    slice,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::watch,
    time::timeout,
};

#[derive(Deserialize)]
struct Node {
    server: String,
    port: u16,
    cipher: String,
    password: String,
    #[serde(default)]
    tfo: bool,
}
impl Node {
    fn config(self) -> Option<Endpoint> {
        if self.server.is_empty()
            || self.port == 0
            || self.password.is_empty()
            || !matches!(
                self.cipher.as_str(),
                "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305"
            )
        {
            return None;
        }
        let address = match self.server.parse::<IpAddr>() {
            Ok(ip) => ServerAddr::SocketAddr(SocketAddr::new(ip, self.port)),
            Err(_) => ServerAddr::DomainName(self.server, self.port),
        };
        Some(Endpoint {
            config: ServerConfig::new(address, self.password, self.cipher.parse().ok()?).ok()?,
            tfo: self.tfo,
        })
    }
}

#[derive(Clone)]
struct Endpoint {
    config: ServerConfig,
    tfo: bool,
}

/// A UDP node shared with C. Every socket using it holds one strong reference.
pub struct UdpNode {
    method: CipherKind,
    key: Box<[u8]>,
    host: ServerAddr,
    resolved: Mutex<Option<SocketAddrV4>>,
    disconnected: watch::Receiver<bool>,
}
impl UdpNode {
    fn new(endpoint: &Endpoint, disconnected: watch::Receiver<bool>) -> Arc<Self> {
        let config = &endpoint.config;
        Arc::new(Self {
            method: config.method(),
            key: config.key().into(),
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
        let mut cached = self.resolved.lock().unwrap();
        if cached.is_none() {
            *cached = match &self.host {
                ServerAddr::SocketAddr(SocketAddr::V4(addr)) => Some(*addr),
                ServerAddr::SocketAddr(SocketAddr::V6(_)) => None,
                ServerAddr::DomainName(host, port) => {
                    (host.as_str(), *port).to_socket_addrs().ok()?.find_map(|a| match a {
                        SocketAddr::V4(v4) => Some(v4),
                        SocketAddr::V6(_) => None,
                    })
                }
            };
        }
        *cached
    }
    fn overhead(&self) -> usize {
        self.method.salt_len() + 7 + self.method.tag_len()
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
    *routes = Some(Arc::new(Routes {
        home_udp_node: UdpNode::new(&home_udp, inactive.clone()),
        company_udp_node: UdpNode::new(&company, inactive),
        home_tcp,
        company,
        ctx: Context::new_shared(ServerType::Local),
        disconnected,
    }));
    true
}

fn current() -> Option<Arc<Routes>> {
    ROUTES.lock().unwrap().clone()
}

/// Selects the UDP node for an IPv4 destination (host order) and resolves its server.
/// Returns a strong reference to release with `vss_udp_release`, or null.
#[no_mangle]
pub unsafe extern "C" fn vss_udp_acquire(ip: u32, server_ip: *mut u32, server_port: *mut u16) -> *const UdpNode {
    let Some(routes) = current() else { return std::ptr::null() };
    let node = match ip >> 8 {
        0x0a0000 => &routes.home_udp_node,
        0x0a0101 => &routes.company_udp_node,
        _ => return std::ptr::null(),
    };
    let Some(server) = node.server() else { return std::ptr::null() };
    if !node.is_active() {
        return std::ptr::null();
    }
    *server_ip = u32::from(*server.ip());
    *server_port = server.port();
    Arc::into_raw(node.clone())
}

#[no_mangle]
pub unsafe extern "C" fn vss_udp_release(node: *const UdpNode) {
    if !node.is_null() {
        drop(Arc::from_raw(node));
    }
}

#[no_mangle]
pub unsafe extern "C" fn vss_udp_overhead(node: *const UdpNode) -> usize {
    (*node).overhead()
}

#[no_mangle]
pub unsafe extern "C" fn vss_udp_is_active(node: *const UdpNode) -> bool {
    (*node).is_active()
}

/// Writes `salt | AEAD(ATYP_V4 ip port | payload) | tag` to `out`.
#[no_mangle]
pub unsafe extern "C" fn vss_udp_encrypt(
    node: *const UdpNode,
    ip: u32,
    port: u16,
    data: *const u8,
    len: usize,
    out: *mut u8,
    cap: usize,
) -> isize {
    let node = &*node;
    let salt_len = node.method.salt_len();
    let total = len + node.overhead();
    if !node.is_active() || total > cap {
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

/// Decrypts a datagram in place and moves its payload to the start of `buf`.
/// Returns the payload length and the original IPv4 sender, or -1 to drop it.
#[no_mangle]
pub unsafe extern "C" fn vss_udp_decrypt(
    node: *const UdpNode,
    buf: *mut u8,
    len: usize,
    ip: *mut u32,
    port: *mut u16,
) -> isize {
    let node = &*node;
    let (salt_len, tag_len) = (node.method.salt_len(), node.method.tag_len());
    if !node.is_active() || len < node.overhead() {
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
    let payload = plain.len() - 7;
    let start = salt_len + 7;
    packet.copy_within(start..start + payload, 0);
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
        let mut opts = shadowsocks::net::ConnectOpts::default();
        opts.tcp.nodelay = true;
        opts.tcp.fastopen = node.tfo;
        let Ok(Ok(mut proxy)) = timeout(
            Duration::from_secs(10),
            ProxyClientStream::connect_with_opts(ctx, &node.config, addr, &opts),
        )
        .await
        else {
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
            let Ok((client, peer)) = listener.accept().await else { continue };
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
    let mut opts = shadowsocks::net::ConnectOpts::default();
    opts.tcp.nodelay = true;
    opts.tcp.fastopen = node.tfo;
    let addr = Address::SocketAddress((Ipv4Addr::from(ip), port).into());
    let Ok(Ok(mut proxy)) = timeout(
        Duration::from_secs(10),
        ProxyClientStream::connect_with_opts(ctx, &node.config, addr, &opts),
    )
    .await
    else {
        return socks_reply(&mut client, 5).await; // connection refused
    };
    socks_reply(&mut client, 0).await?;
    let _ = copy_bidirectional(&mut client, &mut proxy).await;
    Ok(())
}

// ---- Clash subscription parsing --------------------------------------------------

fn parse_subscription(yaml: &str, udp: bool) -> Option<serde_json::Value> {
    let root: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let proxies = root.get("proxies")?.as_sequence()?;
    let mut found = None;
    for entry in proxies {
        if entry.get("type").and_then(|t| t.as_str()) != Some("ss") {
            continue;
        }
        if udp && entry.get("udp").and_then(|u| u.as_bool()) == Some(false) {
            continue;
        }
        if found.is_some() {
            return None; // exactly one usable SS node per subscription
        }
        found = Some(entry);
    }
    let entry = found?;
    if entry.get("plugin").map_or(false, |p| !p.is_null())
        || entry.get("udp-over-tcp").and_then(|u| u.as_bool()) == Some(true)
    {
        return None;
    }
    let text = |key: &str| -> Option<String> {
        let value = entry.get(key)?;
        value.as_str().map(str::to_owned).or_else(|| value.as_u64().map(|n| n.to_string()))
    };
    let port = entry.get("port")?.as_u64().or_else(|| text("port")?.parse().ok())?;
    Some(serde_json::json!({
        "server": text("server")?,
        "port": port,
        "cipher": text("cipher")?,
        "password": text("password")?,
        "tfo": entry.get("tfo").and_then(|t| t.as_bool()).unwrap_or(false),
    }))
}

/// Returns the single SS node of a Clash subscription as JSON (free with
/// `vss_free_string`), or null when the YAML has no unique plain SS node.
#[no_mangle]
pub unsafe extern "C" fn vss_parse_subscription(yaml: *const c_char, udp: bool) -> *mut c_char {
    if yaml.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(text) = CStr::from_ptr(yaml).to_str() else { return std::ptr::null_mut() };
    match parse_subscription(text, udp).and_then(|v| std::ffi::CString::new(v.to_string()).ok()) {
        Some(json) => json.into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vss_free_string(text: *mut c_char) {
    if !text.is_null() {
        drop(std::ffi::CString::from_raw(text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks::{crypto::CipherKind, ProxyListener, ProxySocket};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpSocket,
    };

    #[test]
    fn subscription_yaml() {
        let yaml = "proxies:\n  - {name: a, type: vmess, server: x}\n  - name: home\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-128-gcm\n    password: \"p\"\n    udp: true\n";
        let node = parse_subscription(yaml, true).unwrap();
        assert_eq!(node["server"], "1.2.3.4");
        assert_eq!(node["port"], 8388);
        assert!(parse_subscription(&yaml.replace("udp: true", "udp: false"), true).is_none());
        assert!(parse_subscription(&yaml.replace("udp: true", "plugin: obfs"), false).is_none());
        assert!(parse_subscription("proxies: []", false).is_none());
    }

    fn node_json(port: u16, key: &str) -> serde_json::Value {
        serde_json::json!({"server":"127.0.0.1","port":port,"cipher":"aes-256-gcm","password":key})
    }

    async fn assert_relay_closed(stream: &mut TcpStream) {
        match timeout(Duration::from_secs(2), stream.read(&mut [0])).await {
            Ok(Ok(0)) => (),
            Ok(Err(err)) if matches!(err.kind(), std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted) => (),
            result => panic!("established relay did not close after disconnect: {result:?}"),
        }
    }

    // Distinct listeners and keys make swapping either home subscription observable.
    #[tokio::test(flavor = "multi_thread")]
    async fn split_routes_preserve_destinations_and_return_traffic() {
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
            let json = std::ffi::CString::new(serde_json::to_vec(&nodes).unwrap()).unwrap();
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
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let payload = [0x5a; 1200];
                let mut out = vec![0; 2048];
                let n = unsafe {
                    vss_udp_encrypt(node, ip, 50301, payload.as_ptr(), payload.len(), out.as_mut_ptr(), out.len())
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
                let len = unsafe { vss_udp_decrypt(node, reply.as_mut_ptr(), got.1, &mut from_ip, &mut from_port) };
                assert_eq!(len, 1200);
                assert_eq!((from_ip, from_port), (ip, 50301));
                assert_eq!(&reply[..1200], &payload[..]);
                reply[20] ^= 1;
                assert_eq!(unsafe { vss_udp_decrypt(node, reply.as_mut_ptr(), got.1, &mut from_ip, &mut from_port) }, -1);
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
            stream.write_all(&[5, 1, 0, 1, 10, 0, 0, 80, 0xc4, 0x19]).await.unwrap();
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
            stream.write_all(&[5, 1, 0, 1, 192, 168, 1, 2, 0, 80]).await.unwrap();
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 2);

            let ip = 0x0a000050;
            let node = unsafe { vss_udp_acquire(ip, &mut sip, &mut sport) };
            assert!(!node.is_null());
            let mut packet = [0; 128];
            let payload = b"udp";
            let send = |packet: &mut [u8]| unsafe {
                vss_udp_encrypt(node, ip, 50301, payload.as_ptr(), payload.len(),
                                packet.as_mut_ptr(), packet.len())
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
            assert_eq!(unsafe {
                vss_udp_decrypt(node, packet.as_mut_ptr(), len as usize, &mut sip, &mut sport)
            }, -1);

            assert!(unsafe { vss_config(json.as_ptr()) });
            // If accept raced the cancellation, the stale listener must still close the connection.
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
}
