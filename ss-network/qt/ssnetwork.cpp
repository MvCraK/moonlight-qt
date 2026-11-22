// SS-NETWORK extension (see ss-network/README.md).
#include "ssnetwork.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkProxyFactory>
#include <QNetworkReply>
#include <QPointer>
#include <QQmlEngine>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QTimer>

#include <atomic>
#include <memory>

#ifdef SS_NETWORK_ENABLED
extern "C" {
bool ss_shim_configure(const char* json);
uint64_t ss_shim_received_bytes(void);
uint16_t vss_socks_port(void);
char* vss_parse_subscription(const char* yaml, bool udp);
void vss_free_string(char* text);
}
#endif

namespace {

std::atomic<bool> s_Enabled{false};

constexpr int kMaxConfigBytes = 256 * 1024;
constexpr int kUdpOnlyNode = 1;   // home UDP subscription: cannot be probed over TCP
constexpr int kProbeTimeoutMs = 3000;
constexpr qint64 kProbeCacheMs = 30000;

QString statePath()
{
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + "/ss-network.json";
}

// Validates and normalises one SS node.
bool normaliseNode(const QJsonObject& in, QJsonObject& out)
{
    static const QStringList ciphers = {"aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"};
    const QString server = in.value("server").toString();
    const int port = in.value("port").toInt(in.value("port").toString().toInt());
    const QString cipher = in.value("cipher").toString();
    const QString password = in.value("password").toString();
    bool hostOk = !server.trimmed().isEmpty() && server.size() <= 253;
    for (QChar c : server) {
        if (c.isSpace() || c == '/') hostOk = false;
    }
    if (!hostOk || port < 1 || port > 65535 || !ciphers.contains(cipher) || password.isEmpty()) {
        return false;
    }
    out = QJsonObject{{"server", server}, {"port", port}, {"cipher", cipher},
                      {"password", password}, {"tfo", in.value("tfo").toBool()}};
    return true;
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
                return {proxy};
            }
#endif
        }
        return {QNetworkProxy(QNetworkProxy::NoProxy)};
    }
};

void registerSsNetwork()
{
    qmlRegisterSingletonType<SsNetwork>("SsNetwork", 1, 0, "SsNetwork",
                                        [](QQmlEngine*, QJSEngine*) -> QObject* {
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
    : QObject(parent),
      m_Nam(new QNetworkAccessManager(this)),
      m_TrafficTimer(new QTimer(this))
{
    // Subscription servers are public; never route their fetches through SS.
    m_Nam->setProxy(QNetworkProxy(QNetworkProxy::NoProxy));
    m_TrafficTimer->setInterval(1000);
    connect(m_TrafficTimer, &QTimer::timeout, this, &SsNetwork::trafficChanged);
    load();
}

bool SsNetwork::routes(const QHostAddress& address)
{
    if (!s_Enabled.load(std::memory_order_acquire) || address.protocol() != QAbstractSocket::IPv4Protocol) {
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

bool SsNetwork::enabled() const
{
    return s_Enabled.load();
}

int SsNetwork::status() const
{
    if (!available()) return Unavailable;
    if (!enabled()) return Off;
    if (m_Probes.isEmpty()) return Checking;
    for (const QVariant& latency : m_Probes) {
        if (latency.toInt() == -1) return Degraded;
    }
    return Online;
}

QVariantList SsNetwork::nodes() const
{
    static const char* roles[] = {"homeTcp", "homeUdp", "company"};
    QVariantList result;
    const QJsonArray nodes = m_State.value("nodes").toArray();
    for (int i = 0; i < nodes.size(); i++) {
        const QJsonObject node = nodes.at(i).toObject();
        result.append(QVariantMap{
            {"role", roles[qMin(i, 2)]},
            {"host", node.value("server").toString()},
            {"port", node.value("port").toInt()},
            {"latency", i < m_Probes.size() ? m_Probes.at(i).toInt() : (i == kUdpOnlyNode ? -2 : -3)},
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

void SsNetwork::load()
{
    QFile file(statePath());
    if (!file.open(QIODevice::ReadOnly) || file.size() > kMaxConfigBytes) return;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    if (!doc.isObject()) return;
    // Only the config and nodes persist; every launch starts disconnected.
    m_State = doc.object();
    m_State.remove("enabled");
}

bool SsNetwork::save(const QJsonObject& state)
{
    QSaveFile file(statePath());
    if (!file.open(QIODevice::WriteOnly)) return false;
    file.write(QJsonDocument(state).toJson(QJsonDocument::Compact));
    if (!file.commit()) return false;
    m_State = state;
    return true;
}

bool SsNetwork::activate()
{
#ifdef SS_NETWORK_ENABLED
    const QByteArray nodes = QJsonDocument(m_State.value("nodes").toArray()).toJson(QJsonDocument::Compact);
    if (!ss_shim_configure(nodes.constData()) || vss_socks_port() == 0) {
        ss_shim_configure(nullptr);
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
#endif
    m_Probes.clear();
    m_TrafficTimer->stop();
}

void SsNetwork::setBusy(const QString& action)
{
    m_BusyAction = action;
    if (!action.isEmpty()) m_Failed = false;
    emit changed();
}

void SsNetwork::fail()
{
    m_Failed = true;
    m_BusyAction.clear();
    emit changed();
}

void SsNetwork::toggle()
{
    if (busy() || !available() || !configured()) return;
    if (enabled()) {
        deactivate();
        m_Failed = false;
        emit changed();
        return;
    }
    if (!activate()) {
        fail();
        return;
    }
    m_Failed = false;
    emit changed();
    probe(true);
}

void SsNetwork::importConfig(const QUrl& url)
{
    if (busy()) return;
    QFile file(url.isLocalFile() ? url.toLocalFile() : url.toString());
    if (!file.open(QIODevice::ReadOnly) || file.size() > kMaxConfigBytes) {
        fail();
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    setBusy("import");
    startRefresh(doc.object());
}

void SsNetwork::refresh()
{
    if (busy() || !configured()) return;
    setBusy("refresh");
    startRefresh(m_State.value("config").toObject());
}

// Fetches both home subscriptions; the result is only applied if both succeed.
void SsNetwork::startRefresh(const QJsonObject& config)
{
    QJsonObject company;
    const QUrl urls[2] = {QUrl(config.value("homeTcp").toString()), QUrl(config.value("homeUdp").toString())};
    if (!normaliseNode(config.value("company").toObject(), company) ||
            urls[0].scheme() != "https" || urls[1].scheme() != "https" ||
            urls[0].host().isEmpty() || urls[1].host().isEmpty()) {
        fail();
        return;
    }
    m_PendingConfig = QJsonObject{{"homeTcp", urls[0].toString()}, {"homeUdp", urls[1].toString()}, {"company", company}};
    m_PendingFetches = 2;
    m_FetchFailed = false;
    for (int i = 0; i < 2; i++) {
        m_Fetched[i].clear();
        QNetworkRequest request(urls[i]);
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        request.setTransferTimeout(8000);
        QNetworkReply* reply = m_Nam->get(request);
        connect(reply, &QNetworkReply::finished, this, [this, reply, i] {
            reply->deleteLater();
            const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QByteArray body = reply->read(kMaxConfigBytes + 1);
            if (reply->error() != QNetworkReply::NoError || code < 200 || code > 299 || body.size() > kMaxConfigBytes) {
                m_FetchFailed = true;
            } else {
                m_Fetched[i] = body;
            }
            if (--m_PendingFetches == 0) finishRefresh();
        });
    }
}

void SsNetwork::finishRefresh()
{
    QJsonArray nodes;
#ifdef SS_NETWORK_ENABLED
    for (int i = 0; i < 2 && !m_FetchFailed; i++) {
        char* parsed = vss_parse_subscription(m_Fetched[i].constData(), i == kUdpOnlyNode);
        QJsonObject node;
        if (parsed == nullptr ||
                !normaliseNode(QJsonDocument::fromJson(QByteArray(parsed)).object(), node)) {
            m_FetchFailed = true;
        } else {
            nodes.append(node);
        }
        vss_free_string(parsed);
    }
#else
    m_FetchFailed = true;
#endif
    if (m_FetchFailed) {
        fail();
        return;
    }
    nodes.append(m_PendingConfig.value("company"));
    const QJsonObject next{{"nodes", nodes},
                           {"updated", static_cast<double>(QDateTime::currentMSecsSinceEpoch())},
                           {"config", m_PendingConfig}};
    if (!save(next)) {
        fail();
        return;
    }
    if (enabled() && !activate()) {
        deactivate();
        fail();
        return;
    }
    m_BusyAction.clear();
    emit changed();
    if (enabled()) probe(true);
}

// TCP handshake to each node's SS port (the UDP-only home node is skipped).
void SsNetwork::probe(bool force)
{
    if (!enabled() || probing()) return;
    if (!force && !m_Probes.isEmpty() && QDateTime::currentMSecsSinceEpoch() - m_ProbedAt < kProbeCacheMs) return;
    const QJsonArray nodes = m_State.value("nodes").toArray();
    if (nodes.isEmpty()) return;
    auto results = std::make_shared<QVariantList>();
    for (int i = 0; i < nodes.size(); i++) results->append(i == kUdpOnlyNode ? -2 : -1);
    m_PendingProbes = 0;
    for (int i = 0; i < nodes.size(); i++) {
        if (i == kUdpOnlyNode) continue;
        m_PendingProbes++;
        const QJsonObject node = nodes.at(i).toObject();
        auto* socket = new QTcpSocket(this);
        socket->setProxy(QNetworkProxy::NoProxy);
        auto timer = std::make_shared<QElapsedTimer>();
        auto done = std::make_shared<bool>(false);
        auto finish = [this, socket, results, i, done](int latency) {
            if (*done) return;
            *done = true;
            (*results)[i] = latency;
            socket->abort();
            socket->deleteLater();
            if (--m_PendingProbes == 0) {
                if (enabled()) {
                    m_Probes = *results;
                    m_ProbedAt = QDateTime::currentMSecsSinceEpoch();
                }
                emit changed();
            }
        };
        connect(socket, &QTcpSocket::connected, this, [finish, timer] { finish(static_cast<int>(timer->elapsed())); });
        connect(socket, &QTcpSocket::errorOccurred, this, [finish] { finish(-1); });
        QTimer::singleShot(kProbeTimeoutMs, socket, [finish] { finish(-1); });
        timer->start();
        socket->connectToHost(node.value("server").toString(), static_cast<quint16>(node.value("port").toInt()));
    }
    emit changed();
}
