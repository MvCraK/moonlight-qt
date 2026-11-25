// SS-NETWORK extension (see ss-network/README.md).
#include "ssnetwork.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMetaObject>
#include <QNetworkAccessManager>
#include <QNetworkInterface>
#include <QNetworkProxy>
#include <QNetworkProxyFactory>
#include <QNetworkReply>
#include <QPointer>
#include <QQmlEngine>
#include <QSaveFile>
#include <QStandardPaths>
#include <QThreadPool>
#include <QTimer>

#include <atomic>
#include <memory>

#ifdef SS_NETWORK_ENABLED
extern "C" {
bool ss_shim_configure(const char* json);
uint64_t ss_shim_received_bytes(void);
void vss_set_bypass_interface(uint32_t if_index, const char* if_name);
uint16_t vss_socks_port(void);
int32_t vss_probe_tcp(const char* host, uint16_t port, uint32_t timeout_ms);
char* vss_parse_subscription(const char* yaml, bool udp);
void vss_free_string(char* text);
}
#endif

namespace {

std::atomic<bool> s_Enabled{ false };

constexpr int kMaxConfigBytes = 256 * 1024;
constexpr int kMaxRedirects = 5;
constexpr int kUdpOnlyNode = 1;
constexpr int kProbeTimeoutMs = 3000;
constexpr qint64 kProbeCacheMs = 30000;

QString statePath()
{
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + "/ss-network.json";
}

bool isSupportedCipher(const QString& cipher)
{
    static const QStringList ciphers = {
        "aes-256-gcm",
        "aes-128-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    };
    return ciphers.contains(cipher);
}

// Validates and normalises one SS node. Sets errorCode on failure.
bool normaliseNode(const QJsonObject& in, QJsonObject& out, QString* errorCode = nullptr)
{
    const QString server = in.value("server").toString().trimmed();
    const int port = in.value("port").toInt(in.value("port").toString().toInt());
    const QString cipher = in.value("cipher").toString().trimmed();
    const QString password = in.value("password").toString();
    bool hostOk = !server.isEmpty() && server.size() <= 253;
    for (QChar c : server) {
        if (c.isSpace() || c == '/')
            hostOk = false;
    }
    if (!hostOk || port < 1 || port > 65535 || cipher.isEmpty() || password.isEmpty()) {
        if (errorCode)
            *errorCode = "errInvalidNode";
        return false;
    }
    if (!isSupportedCipher(cipher)) {
        if (errorCode)
            *errorCode = "errUnsupportedCipher";
        return false;
    }
    out = QJsonObject{ { "server", server },
                       { "port", port },
                       { "cipher", cipher },
                       { "password", password },
                       { "tfo", in.value("tfo").toBool() } };
    return true;
}

// Parses optional fixed company-relay home nodes: either a single `homeRelay`
// node (used for both TCP and UDP) or separate `homeRelayTcp` + `homeRelayUdp`.
bool parseRelayNodes(const QJsonObject& config, QJsonArray& relayOut, QString* errorCode = nullptr)
{
    relayOut = QJsonArray();
    const bool hasSingle = config.contains("homeRelay") && !config.value("homeRelay").isNull();
    const bool hasSplit = (config.contains("homeRelayTcp") && !config.value("homeRelayTcp").isNull()) ||
                          (config.contains("homeRelayUdp") && !config.value("homeRelayUdp").isNull());
    if (!hasSingle && !hasSplit) {
        return true; // Relay config is optional.
    }
    if (hasSingle) {
        QJsonObject node;
        if (!normaliseNode(config.value("homeRelay").toObject(), node, errorCode)) {
            return false;
        }
        relayOut.append(node);
        relayOut.append(node);
        return true;
    }
    QJsonObject tcp, udp;
    if (!normaliseNode(config.value("homeRelayTcp").toObject(), tcp, errorCode) ||
        !normaliseNode(config.value("homeRelayUdp").toObject(), udp, errorCode)) {
        return false;
    }
    relayOut.append(tcp);
    relayOut.append(udp);
    return true;
}

bool isFakeIp(quint32 ipv4)
{
    return (ipv4 & 0xfffe0000u) == 0xc6120000u; // 198.18.0.0/15
}

bool isLinkLocalIp(quint32 ipv4)
{
    return (ipv4 & 0xffff0000u) == 0xa9fe0000u; // 169.254.0.0/16
}

bool firstUsableIpv4(const QNetworkInterface& nic, quint32& outIp)
{
    for (const QNetworkAddressEntry& entry : nic.addressEntries()) {
        const QHostAddress ip = entry.ip();
        if (ip.protocol() != QAbstractSocket::IPv4Protocol)
            continue;
        if (ip.isLoopback() || ip.isNull())
            continue;
        const quint32 v4 = ip.toIPv4Address();
        if (v4 == 0 || isLinkLocalIp(v4))
            continue;
        outIp = v4;
        return true;
    }
    return false;
}

bool isLocalVirtualOrInternalName(const QString& lowerName, const QString& lowerHuman)
{
    static const QStringList prefixes = {
        "lo", "bridge", "vmnet", "vmenet", "vnic", "docker", "veth",
        "vboxnet", "awdl", "llw", "anpi", "ap", "pktap", "gif", "stf",
    };
    for (const QString& p : prefixes) {
        if (lowerName.startsWith(p))
            return true;
    }
    static const QStringList substrings = {
        "vethernet", "hyper-v", "wsl", "vmware", "virtualbox", "parallels",
        "bluetooth", "npcap", "loopback", "docker", "qemu",
    };
    for (const QString& s : substrings) {
        if (lowerName.contains(s) || lowerHuman.contains(s))
            return true;
    }
    return false;
}

bool isVpnInterface(const QNetworkInterface& nic, quint32 ipv4)
{
    if (isFakeIp(ipv4))
        return true;
    const QString name = nic.name().toLower();
    const QString human = nic.humanReadableName().toLower();
    if (isLocalVirtualOrInternalName(name, human))
        return false;
    static const QStringList vpnPrefixes = {
        "utun", "tun", "tap", "wg", "ppp", "ipsec", "tailscale", "zt", "feth",
    };
    for (const QString& p : vpnPrefixes) {
        if (name.startsWith(p))
            return true;
    }
    static const QStringList vpnKeywords = {
        "wintun", "flclash", "clash", "mihomo", "sing-box", "singbox",
        "surge", "wireguard", "tailscale", "openvpn", "shadowrocket",
        "nekoray", "vpn", "meta",
    };
    for (const QString& kw : vpnKeywords) {
        if (name.contains(kw) || human.contains(kw))
            return true;
    }
    return false;
}

int scorePhysicalInterface(const QNetworkInterface& nic, quint32 ipv4)
{
    if (nic.index() <= 0)
        return -1;
    const auto flags = nic.flags();
    if (!flags.testFlag(QNetworkInterface::IsUp) || !flags.testFlag(QNetworkInterface::IsRunning))
        return -1;
    if (flags.testFlag(QNetworkInterface::IsLoopBack) || flags.testFlag(QNetworkInterface::IsPointToPoint))
        return -1;
    if (isFakeIp(ipv4) || isLinkLocalIp(ipv4))
        return -1;
    if (isVpnInterface(nic, ipv4))
        return -1;
    const QString name = nic.name().toLower();
    const QString human = nic.humanReadableName().toLower();
    if (isLocalVirtualOrInternalName(name, human))
        return -1;
    if (human.contains("virtual") || human.contains("zerotier") || human.contains("hamachi") ||
        human.contains("radmin")) {
        return -1;
    }
    int score = 0;
    switch (nic.type()) {
    case QNetworkInterface::Ethernet:
        score += 30;
        break;
    case QNetworkInterface::Wifi:
        score += 20;
        break;
    case QNetworkInterface::Virtual:
    case QNetworkInterface::Ppp:
    case QNetworkInterface::Loopback:
        return -1;
    default:
        score += 10;
        break;
    }
    if (flags.testFlag(QNetworkInterface::CanBroadcast))
        score += 5;
#ifdef Q_OS_DARWIN
    if (name.startsWith("en")) {
        score += 15;
        if (name == "en0")
            score += 2;
    }
#endif
    return score;
}

// Sends Qt sockets for routed hosts through the local SOCKS5 endpoint.
class SsProxyFactory : public QNetworkProxyFactory
{
public:
    QList<QNetworkProxy> queryProxy(const QNetworkProxyQuery& query) override
    {
        if (query.queryType() != QNetworkProxyQuery::UdpSocket &&
            query.queryType() != QNetworkProxyQuery::TcpServer &&
            SsNetwork::routes(query.peerHostName())) {
#ifdef SS_NETWORK_ENABLED
            if (quint16 port = vss_socks_port()) {
                QNetworkProxy proxy(QNetworkProxy::Socks5Proxy, "127.0.0.1", port);
                proxy.setCapabilities(QNetworkProxy::TunnelingCapability);
                return { proxy };
            }
#endif
        }
        return { QNetworkProxy(QNetworkProxy::NoProxy) };
    }
};

// Used exclusively by subscription downloads: honours the OS HTTP/SOCKS proxy
// (so FlClash system proxy can fetch subscriptions) while never looping back
// into our own local SS SOCKS5 port.
class SystemProxyOnlyFactory : public QNetworkProxyFactory
{
public:
    QList<QNetworkProxy> queryProxy(const QNetworkProxyQuery& query) override
    {
        const QList<QNetworkProxy> sys = QNetworkProxyFactory::systemProxyForQuery(query);
#ifdef SS_NETWORK_ENABLED
        const quint16 ownPort = vss_socks_port();
#else
        const quint16 ownPort = 0;
#endif
        QList<QNetworkProxy> filtered;
        for (const QNetworkProxy& p : sys) {
            if (ownPort != 0 && p.type() == QNetworkProxy::Socks5Proxy && p.port() == ownPort &&
                (p.hostName() == "127.0.0.1" || p.hostName() == "localhost")) {
                continue;
            }
            filtered.append(p);
        }
        if (filtered.isEmpty())
            filtered.append(QNetworkProxy(QNetworkProxy::NoProxy));
        return filtered;
    }
};

QString mapParseError(const QString& raw)
{
    if (raw == "yaml_no_proxies")
        return "errYamlNoProxies";
    if (raw == "yaml_node_count")
        return "errYamlNodeCount";
    if (raw == "plugin_unsupported")
        return "errPluginUnsupported";
    if (raw == "invalid_node")
        return "errInvalidNode";
    return "errGeneric";
}

void registerSsNetwork()
{
    qmlRegisterSingletonType<SsNetwork>(
        "SsNetwork", 1, 0, "SsNetwork", [](QQmlEngine*, QJSEngine*) -> QObject* {
            SsNetwork* network = SsNetwork::instance();
            QQmlEngine::setObjectOwnership(network, QQmlEngine::CppOwnership);
            return network;
        });
}

} // namespace

Q_COREAPP_STARTUP_FUNCTION(registerSsNetwork)

SsNetwork* SsNetwork::instance()
{
    static SsNetwork* network = new SsNetwork(QCoreApplication::instance());
    return network;
}

SsNetwork::SsNetwork(QObject* parent)
    : QObject(parent), m_Nam(new QNetworkAccessManager(this)), m_TrafficTimer(new QTimer(this))
{
    // Subscription downloads may use the OS proxy (e.g. FlClash system proxy),
    // never our own SS SOCKS5 endpoint.
    m_Nam->setProxyFactory(new SystemProxyOnlyFactory());
    m_TrafficTimer->setInterval(1000);
    connect(m_TrafficTimer, &QTimer::timeout, this, &SsNetwork::onTrafficTick);
    load();
    refreshNetworkState();
}

bool SsNetwork::routes(const QHostAddress& address)
{
    if (!s_Enabled.load(std::memory_order_acquire) ||
        address.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    const quint32 prefix = address.toIPv4Address() >> 8;
    return prefix == 0x0a0000 || prefix == 0x0a0101;
}

bool SsNetwork::routes(const QString& address)
{
    return routes(QHostAddress(address));
}

QNetworkProxyFactory* SsNetwork::createProxyFactory()
{
    return new SsProxyFactory();
}

bool SsNetwork::available() const
{
#ifdef SS_NETWORK_ENABLED
    return true;
#else
    return false;
#endif
}

bool SsNetwork::configured() const
{
    return m_State.contains("companyNode") && (hasDirect() || hasRelay() || hasDirectConfig());
}

bool SsNetwork::enabled() const
{
    return s_Enabled.load();
}

QString SsNetwork::homeMode() const
{
    const QString saved = m_State.value("homeMode").toString();
    if (saved == "relay" && hasRelay())
        return "relay";
    if (saved == "direct" && (hasDirect() || hasDirectConfig()))
        return "direct";
    if (hasDirect())
        return "direct";
    if (hasRelay())
        return "relay";
    return "direct";
}

bool SsNetwork::hasDirect() const
{
    return m_State.value("directNodes").toArray().size() == 2;
}

bool SsNetwork::hasDirectConfig() const
{
    const QJsonObject cfg = m_State.value("config").toObject();
    return !cfg.value("homeTcp").toString().isEmpty() && !cfg.value("homeUdp").toString().isEmpty();
}

bool SsNetwork::hasRelay() const
{
    return m_State.value("relayNodes").toArray().size() == 2;
}

bool SsNetwork::relayUsesSingleEndpoint() const
{
    const QJsonArray relay = m_State.value("relayNodes").toArray();
    if (relay.size() != 2)
        return false;
    const QJsonObject a = relay.at(0).toObject();
    const QJsonObject b = relay.at(1).toObject();
    return a.value("server").toString() == b.value("server").toString() &&
           a.value("port").toInt() == b.value("port").toInt();
}

QJsonArray SsNetwork::activeNodesArray() const
{
    const QJsonObject company = m_State.value("companyNode").toObject();
    if (company.isEmpty())
        return {};
    const QJsonArray home = homeMode() == "relay"
                                ? m_State.value("relayNodes").toArray()
                                : m_State.value("directNodes").toArray();
    if (home.size() != 2)
        return {};
    return QJsonArray{ home.at(0), home.at(1), company };
}

int SsNetwork::status() const
{
    if (!available())
        return Unavailable;
    if (!enabled())
        return Off;
    if (m_Probes.isEmpty())
        return Checking;
    for (const QVariant& latency : m_Probes) {
        if (latency.toInt() == -1)
            return Degraded;
    }
    return Online;
}

QVariantList SsNetwork::nodes() const
{
    QVariantList result;
    const QString mode = homeMode();
    const QJsonObject company = m_State.value("companyNode").toObject();
    const auto latencyFor = [this](int slot, bool skipped) -> int {
        if (skipped)
            return -2;
        return slot < m_Probes.size() ? m_Probes.at(slot).toInt() : -3;
    };

    if (mode == "relay") {
        const QJsonArray relay = m_State.value("relayNodes").toArray();
        if (relay.size() == 2) {
            if (relayUsesSingleEndpoint()) {
                const QJsonObject node = relay.at(0).toObject();
                result.append(QVariantMap{
                    { "role", "homeRelay" },
                    { "host", node.value("server").toString() },
                    { "port", node.value("port").toInt() },
                    { "latency", latencyFor(0, false) },
                });
            } else {
                const QJsonObject tcp = relay.at(0).toObject();
                const QJsonObject udp = relay.at(1).toObject();
                result.append(QVariantMap{
                    { "role", "homeRelayTcp" },
                    { "host", tcp.value("server").toString() },
                    { "port", tcp.value("port").toInt() },
                    { "latency", latencyFor(0, false) },
                });
                result.append(QVariantMap{
                    { "role", "homeRelayUdp" },
                    { "host", udp.value("server").toString() },
                    { "port", udp.value("port").toInt() },
                    { "latency", latencyFor(1, true) },
                });
            }
        }
    } else {
        const QJsonArray direct = m_State.value("directNodes").toArray();
        if (direct.size() == 2) {
            const QJsonObject tcp = direct.at(0).toObject();
            const QJsonObject udp = direct.at(1).toObject();
            result.append(QVariantMap{
                { "role", "homeTcp" },
                { "host", tcp.value("server").toString() },
                { "port", tcp.value("port").toInt() },
                { "latency", latencyFor(0, false) },
            });
            result.append(QVariantMap{
                { "role", "homeUdp" },
                { "host", udp.value("server").toString() },
                { "port", udp.value("port").toInt() },
                { "latency", latencyFor(1, true) },
            });
        }
    }

    if (!company.isEmpty()) {
        result.append(QVariantMap{
            { "role", "company" },
            { "host", company.value("server").toString() },
            { "port", company.value("port").toInt() },
            { "latency", latencyFor(2, false) },
        });
    }
    return result;
}

qint64 SsNetwork::updated() const
{
    return static_cast<qint64>(m_State.value("updated").toDouble());
}

qint64 SsNetwork::receivedBytes() const
{
#ifdef SS_NETWORK_ENABLED
    return enabled() ? static_cast<qint64>(ss_shim_received_bytes()) : 0;
#else
    return 0;
#endif
}

void SsNetwork::migrateLegacyState(QJsonObject& s) const
{
    const QJsonArray legacy = s.value("nodes").toArray();
    if (legacy.size() >= 3) {
        if (!s.contains("directNodes")) {
            s.insert("directNodes", QJsonArray{ legacy.at(0), legacy.at(1) });
        }
        if (!s.contains("companyNode")) {
            s.insert("companyNode", legacy.at(2));
        }
    }
    if (!s.contains("relayNodes")) {
        const QJsonObject cfg = s.value("config").toObject();
        QJsonArray relay;
        if (parseRelayNodes(cfg, relay) && relay.size() == 2) {
            s.insert("relayNodes", relay);
        }
    }
    if (!s.contains("homeMode")) {
        s.insert("homeMode", s.contains("directNodes") ? "direct" : "relay");
    }
}

void SsNetwork::load()
{
    QFile file(statePath());
    if (!file.open(QIODevice::ReadOnly) || file.size() > kMaxConfigBytes)
        return;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (!doc.isObject())
        return;
    // Only the config, resolved nodes, and homeMode persist; every launch starts disconnected.
    QJsonObject loaded = doc.object();
    loaded.remove("enabled");
    migrateLegacyState(loaded);
    m_State = loaded;
}

bool SsNetwork::save(const QJsonObject& state)
{
    QSaveFile file(statePath());
    if (!file.open(QIODevice::WriteOnly))
        return false;
    file.write(QJsonDocument(state).toJson(QJsonDocument::Compact));
    if (!file.commit())
        return false;
    m_State = state;
    return true;
}

void SsNetwork::refreshNetworkState()
{
    bool vpn = false;
    quint32 bestIfIndex = 0;
    QString bestIfName;
    QString bestIfLabel;
    int bestScore = -1;

    const auto all = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& nic : all) {
        const auto flags = nic.flags();
        if (!flags.testFlag(QNetworkInterface::IsUp) ||
            !flags.testFlag(QNetworkInterface::IsRunning) ||
            flags.testFlag(QNetworkInterface::IsLoopBack)) {
            continue;
        }
        quint32 ipv4 = 0;
        if (!firstUsableIpv4(nic, ipv4))
            continue;
        if (isVpnInterface(nic, ipv4)) {
            vpn = true;
            continue;
        }
        const int score = scorePhysicalInterface(nic, ipv4);
        if (score > bestScore) {
            bestScore = score;
            bestIfIndex = static_cast<quint32>(nic.index());
            bestIfName = nic.name();
            bestIfLabel = nic.humanReadableName().isEmpty() ? nic.name() : nic.humanReadableName();
        }
    }

    const bool changedState = (vpn != m_SystemVpnActive) ||
                              (bestIfIndex != m_BypassIfIndex) ||
                              (bestIfName != m_BypassIfName);
    m_SystemVpnActive = vpn;
    m_BypassIfIndex = vpn ? bestIfIndex : 0;
    m_BypassIfName = vpn ? bestIfName : QString();
    m_BypassIfLabel = vpn ? bestIfLabel : QString();

    if (changedState) {
        pushBypassInterface();
        if (enabled()) {
            // Re-apply config so new DNS resolutions pick up the updated bypass state.
            activate();
        }
        emit changed();
    }
}

void SsNetwork::pushBypassInterface() const
{
#ifdef SS_NETWORK_ENABLED
    if (enabled() && m_SystemVpnActive && m_BypassIfIndex != 0 && !m_BypassIfName.isEmpty()) {
        const QByteArray nameUtf8 = m_BypassIfName.toUtf8();
        vss_set_bypass_interface(m_BypassIfIndex, nameUtf8.constData());
    } else {
        vss_set_bypass_interface(0, nullptr);
    }
#endif
}

bool SsNetwork::activate()
{
#ifdef SS_NETWORK_ENABLED
    const QJsonArray active = activeNodesArray();
    if (active.size() != 3)
        return false;

    // Push bypass interface before configuring Rust so new DNS lookups use it.
    if (m_SystemVpnActive && m_BypassIfIndex != 0 && !m_BypassIfName.isEmpty()) {
        const QByteArray nameUtf8 = m_BypassIfName.toUtf8();
        vss_set_bypass_interface(m_BypassIfIndex, nameUtf8.constData());
    } else {
        vss_set_bypass_interface(0, nullptr);
    }

    const QByteArray nodes = QJsonDocument(active).toJson(QJsonDocument::Compact);
    if (!ss_shim_configure(nodes.constData()) || vss_socks_port() == 0) {
        ss_shim_configure(nullptr);
        vss_set_bypass_interface(0, nullptr);
        return false;
    }
    // main.cpp pins the application proxy to NoProxy at startup; replace it with
    // a factory that keeps NoProxy for everything except routed hosts.
    static bool factoryInstalled = false;
    if (!factoryInstalled) {
        QNetworkProxyFactory::setApplicationProxyFactory(new SsProxyFactory());
        factoryInstalled = true;
    }
    s_Enabled.store(true, std::memory_order_release);
    m_Probes.clear();
    m_ProbedAt = 0;
    m_ProbeGeneration++;
    m_TrafficTimer->start();
    return true;
#else
    return false;
#endif
}

void SsNetwork::deactivate()
{
    s_Enabled.store(false, std::memory_order_release);
#ifdef SS_NETWORK_ENABLED
    ss_shim_configure(nullptr);
    vss_set_bypass_interface(0, nullptr);
#endif
    m_Probes.clear();
    m_ProbeGeneration++;
    m_PendingProbes = 0;
    m_TrafficTimer->stop();
}

void SsNetwork::clearMessage()
{
    m_Failed = false;
    m_Warning = false;
    m_ErrorCode.clear();
    m_ErrorArg.clear();
    m_WarningPrefix.clear();
}

void SsNetwork::setBusy(const QString& action)
{
    m_BusyAction = action;
    if (!action.isEmpty())
        clearMessage();
    emit changed();
}

void SsNetwork::fail(const QString& code, const QString& arg)
{
    m_Failed = true;
    m_Warning = false;
    m_ErrorCode = code.isEmpty() ? "errGeneric" : code;
    m_ErrorArg = arg;
    m_WarningPrefix.clear();
    m_BusyAction.clear();
    emit changed();
}

void SsNetwork::onTrafficTick()
{
    emit trafficChanged();
    if (++m_NetworkCheckTick >= 5) {
        m_NetworkCheckTick = 0;
        refreshNetworkState();
    }
}

void SsNetwork::toggle()
{
    if (busy() || !available() || !configured())
        return;
    refreshNetworkState();
    if (enabled()) {
        deactivate();
        clearMessage();
        emit changed();
        return;
    }
    if (homeMode() == "direct" && !hasDirect()) {
        fail("errNoDirect");
        return;
    }
    if (homeMode() == "relay" && !hasRelay()) {
        fail("errNoRelay");
        return;
    }
    if (!activate()) {
        fail("errNativeStart");
        return;
    }
    clearMessage();
    emit changed();
    probe(true);
}

void SsNetwork::setHomeMode(const QString& mode)
{
    if (busy() || !configured())
        return;
    const QString target = (mode == "relay") ? "relay" : "direct";
    if (target == homeMode() &&
        ((target == "relay" && hasRelay()) || (target == "direct" && hasDirect()))) {
        return;
    }
    if (target == "relay" && !hasRelay()) {
        fail("errNoRelay");
        return;
    }
    if (target == "direct" && !hasDirect()) {
        if (!hasDirectConfig()) {
            fail("errNoSubscriptionUrls");
            return;
        }
        // Automatically fetch subscriptions when switching to Direct for the first time;
        // keep current mode intact if the fetch fails.
        m_SwitchToDirectOnRefresh = true;
        refresh();
        return;
    }

    QJsonObject next = m_State;
    next.insert("homeMode", target);
    if (!save(next)) {
        fail("errGeneric");
        return;
    }
    clearMessage();
    if (enabled()) {
        refreshNetworkState();
        if (!activate()) {
            deactivate();
            fail("errNativeStart");
            return;
        }
        emit changed();
        probe(true);
    } else {
        emit changed();
    }
}

void SsNetwork::importConfig(const QUrl& url)
{
    if (busy())
        return;
    QFile file(url.isLocalFile() ? url.toLocalFile() : url.toString());
    if (!file.open(QIODevice::ReadOnly) || file.size() > kMaxConfigBytes) {
        fail("errJsonFormat");
        return;
    }
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
        fail("errJsonFormat");
        return;
    }
    setBusy("import");
    startRefresh(doc.object(), true);
}

void SsNetwork::refresh()
{
    if (busy() || !configured())
        return;
    if (!hasDirectConfig()) {
        fail("errNoSubscriptionUrls");
        return;
    }
    setBusy("refresh");
    startRefresh(m_State.value("config").toObject(), false);
}

void SsNetwork::startRefresh(const QJsonObject& config, bool isImport)
{
    QString errCode;
    QJsonObject company;
    if (!normaliseNode(config.value("company").toObject(), company, &errCode)) {
        fail(errCode);
        return;
    }

    QJsonArray relayNodes;
    if (!parseRelayNodes(config, relayNodes, &errCode)) {
        fail(errCode);
        return;
    }

    const QString homeTcpRaw = config.value("homeTcp").toString().trimmed();
    const QString homeUdpRaw = config.value("homeUdp").toString().trimmed();
    const bool hasUrls = !homeTcpRaw.isEmpty() || !homeUdpRaw.isEmpty();

    QUrl urls[2];
    if (hasUrls) {
        urls[0] = QUrl(homeTcpRaw);
        urls[1] = QUrl(homeUdpRaw);
        if (urls[0].scheme() != "https" || urls[1].scheme() != "https" ||
            urls[0].host().isEmpty() || urls[1].host().isEmpty()) {
            fail("errHttpsOnly");
            return;
        }
    } else if (relayNodes.isEmpty()) {
        fail("errNoSubscriptionUrls");
        return;
    }

    QJsonObject normalisedConfig{ { "company", company } };
    if (hasUrls) {
        normalisedConfig.insert("homeTcp", urls[0].toString());
        normalisedConfig.insert("homeUdp", urls[1].toString());
    }
    if (relayNodes.size() == 2) {
        if (config.contains("homeRelay") && !config.value("homeRelay").isNull()) {
            normalisedConfig.insert("homeRelay", relayNodes.at(0));
        } else {
            normalisedConfig.insert("homeRelayTcp", relayNodes.at(0));
            normalisedConfig.insert("homeRelayUdp", relayNodes.at(1));
        }
    }

    // Relay-only config: save immediately with no subscription download needed.
    if (!hasUrls) {
        QJsonObject next{
            { "config", normalisedConfig },
            { "relayNodes", relayNodes },
            { "companyNode", company },
            { "homeMode", "relay" },
        };
        if (!save(next)) {
            fail("errGeneric");
            return;
        }
        if (enabled() && !activate()) {
            deactivate();
            fail("errNativeStart");
            return;
        }
        m_BusyAction.clear();
        clearMessage();
        emit changed();
        if (enabled())
            probe(true);
        return;
    }

    m_RefreshIsImport = isImport;
    m_PendingConfig = normalisedConfig;
    m_PendingCompany = company;
    m_PendingRelayNodes = relayNodes;
    m_PendingFetches = 2;
    m_FetchFailed = false;
    m_FetchErrorCode.clear();
    m_FetchErrorArg.clear();
    for (int i = 0; i < 2; i++) {
        m_Fetched[i].clear();
        fetchSubscriptionSlot(i, urls[i], kMaxRedirects);
    }
}

void SsNetwork::fetchSubscriptionSlot(int slot, const QUrl& url, int redirectsLeft)
{
    auto recordFetchError = [this](const QString& code, const QString& arg = QString()) {
        if (!m_FetchFailed) {
            m_FetchFailed = true;
            m_FetchErrorCode = code;
            m_FetchErrorArg = arg;
        }
    };

    if (!url.isValid() || url.host().isEmpty()) {
        recordFetchError(redirectsLeft < kMaxRedirects ? "errRedirectInvalid" : "errHttpsOnly");
        if (--m_PendingFetches == 0)
            finishRefresh();
        return;
    }
    if (url.scheme() != "https") {
        recordFetchError(redirectsLeft < kMaxRedirects ? "errRedirectHttpsOnly" : "errHttpsOnly");
        if (--m_PendingFetches == 0)
            finishRefresh();
        return;
    }

    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    request.setTransferTimeout(8000);
    QNetworkReply* reply = m_Nam->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, slot, url, redirectsLeft, recordFetchError] {
        reply->deleteLater();
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();

        // Manually follow bounded HTTPS-only redirects.
        if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
            if (redirectsLeft <= 0) {
                recordFetchError("errRedirectLimit");
                if (--m_PendingFetches == 0)
                    finishRefresh();
                return;
            }
            QUrl loc = reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
            if (!loc.isValid() || loc.isEmpty()) {
                const QByteArray rawLoc = reply->rawHeader("Location").trimmed();
                if (!rawLoc.isEmpty())
                    loc = QUrl::fromEncoded(rawLoc);
            }
            if (!loc.isValid() || loc.isEmpty()) {
                recordFetchError("errRedirectInvalid");
                if (--m_PendingFetches == 0)
                    finishRefresh();
                return;
            }
            const QUrl nextUrl = url.resolved(loc);
            if (!nextUrl.isValid() || nextUrl.host().isEmpty()) {
                recordFetchError("errRedirectInvalid");
                if (--m_PendingFetches == 0)
                    finishRefresh();
                return;
            }
            if (nextUrl.scheme() != "https") {
                recordFetchError("errRedirectHttpsOnly");
                if (--m_PendingFetches == 0)
                    finishRefresh();
                return;
            }
            fetchSubscriptionSlot(slot, nextUrl, redirectsLeft - 1);
            return;
        }

        const QByteArray body = reply->read(kMaxConfigBytes + 1);
        if (reply->error() != QNetworkReply::NoError) {
            switch (reply->error()) {
            case QNetworkReply::HostNotFoundError:
                recordFetchError("errDns");
                break;
            case QNetworkReply::TimeoutError:
            case QNetworkReply::OperationCanceledError:
                recordFetchError("errTimeout");
                break;
            case QNetworkReply::SslHandshakeFailedError:
                recordFetchError("errTls");
                break;
            default:
                if (code >= 400) {
                    recordFetchError("errHttpStatus", QString::number(code));
                } else {
                    recordFetchError("errGeneric");
                }
                break;
            }
        } else if (code < 200 || code > 299) {
            recordFetchError("errHttpStatus", QString::number(code));
        } else if (body.size() > kMaxConfigBytes) {
            recordFetchError("errGeneric");
        } else {
            m_Fetched[slot] = body;
        }
        if (--m_PendingFetches == 0)
            finishRefresh();
    });
}

void SsNetwork::finishRefresh()
{
    QJsonArray directNodes;
#ifdef SS_NETWORK_ENABLED
    for (int i = 0; i < 2 && !m_FetchFailed; i++) {
        char* parsed = vss_parse_subscription(m_Fetched[i].constData(), i == kUdpOnlyNode);
        if (parsed == nullptr) {
            m_FetchFailed = true;
            m_FetchErrorCode = "errYamlNoProxies";
            break;
        }
        const QJsonObject obj = QJsonDocument::fromJson(QByteArray(parsed)).object();
        vss_free_string(parsed);
        if (obj.contains("error")) {
            m_FetchFailed = true;
            m_FetchErrorCode = mapParseError(obj.value("error").toString());
            break;
        }
        QJsonObject node;
        QString errCode;
        if (!normaliseNode(obj, node, &errCode)) {
            m_FetchFailed = true;
            m_FetchErrorCode = errCode;
            break;
        }
        directNodes.append(node);
    }
#else
    m_FetchFailed = true;
    m_FetchErrorCode = "errGeneric";
#endif

    if (m_FetchFailed) {
        m_SwitchToDirectOnRefresh = false;
        // Resilient import: if fixed company relay is present in the config being
        // imported, keep the config & relay nodes and switch to Relay with a warning.
        if (m_RefreshIsImport && m_PendingRelayNodes.size() == 2) {
            QJsonObject next{
                { "config", m_PendingConfig },
                { "relayNodes", m_PendingRelayNodes },
                { "companyNode", m_PendingCompany },
                { "homeMode", "relay" },
            };
            if (!save(next)) {
                fail("errGeneric");
                return;
            }
            if (enabled() && !activate()) {
                deactivate();
                fail("errNativeStart");
                return;
            }
            m_BusyAction.clear();
            m_Failed = false;
            m_Warning = true;
            m_WarningPrefix = "warnRelayOnly";
            m_ErrorCode = m_FetchErrorCode.isEmpty() ? "errGeneric" : m_FetchErrorCode;
            m_ErrorArg = m_FetchErrorArg;
            emit changed();
            if (enabled())
                probe(true);
            return;
        }
        fail(m_FetchErrorCode, m_FetchErrorArg);
        return;
    }

    QString nextMode = (m_RefreshIsImport || m_SwitchToDirectOnRefresh) ? "direct" : homeMode();
    m_SwitchToDirectOnRefresh = false;
    if (nextMode == "relay" && m_PendingRelayNodes.size() != 2)
        nextMode = "direct";

    QJsonObject next{
        { "config", m_PendingConfig },
        { "directNodes", directNodes },
        { "companyNode", m_PendingCompany },
        { "homeMode", nextMode },
        { "updated", static_cast<double>(QDateTime::currentMSecsSinceEpoch()) },
    };
    if (m_PendingRelayNodes.size() == 2) {
        next.insert("relayNodes", m_PendingRelayNodes);
    }
    if (!save(next)) {
        fail("errGeneric");
        return;
    }
    if (enabled() && !activate()) {
        deactivate();
        fail("errNativeStart");
        return;
    }
    m_BusyAction.clear();
    clearMessage();
    emit changed();
    if (enabled())
        probe(true);
}

// TCP handshake to each active node's SS port using the same bypass interface
// and anti-Fake-IP DNS as real SS traffic.
void SsNetwork::probe(bool force)
{
    if (!enabled() || probing())
        return;
    if (!force && !m_Probes.isEmpty() &&
        QDateTime::currentMSecsSinceEpoch() - m_ProbedAt < kProbeCacheMs)
        return;
    const QJsonArray active = activeNodesArray();
    if (active.size() != 3)
        return;

    auto results = std::make_shared<QVariantList>();
    for (int i = 0; i < 3; i++)
        results->append(i == kUdpOnlyNode ? -2 : -1);

    const quint64 gen = ++m_ProbeGeneration;
    m_PendingProbes = 0;
    QPointer<SsNetwork> self(this);

    for (int i = 0; i < 3; i++) {
        if (i == kUdpOnlyNode)
            continue;
        m_PendingProbes++;
        const QJsonObject node = active.at(i).toObject();
        const QByteArray hostUtf8 = node.value("server").toString().toUtf8();
        const quint16 port = static_cast<quint16>(node.value("port").toInt());

        QThreadPool::globalInstance()->start([self, gen, results, i, hostUtf8, port] {
#ifdef SS_NETWORK_ENABLED
            const int latency = vss_probe_tcp(hostUtf8.constData(), port, kProbeTimeoutMs);
#else
            const int latency = -1;
#endif
            if (!self)
                return;
            QMetaObject::invokeMethod(
                self,
                [self, gen, results, i, latency] {
                    if (!self || self->m_ProbeGeneration != gen)
                        return;
                    (*results)[i] = latency;
                    if (--self->m_PendingProbes == 0) {
                        if (self->enabled()) {
                            self->m_Probes = *results;
                            self->m_ProbedAt = QDateTime::currentMSecsSinceEpoch();
                        }
                        emit self->changed();
                    }
                },
                Qt::QueuedConnection);
        });
    }
    emit changed();
}
