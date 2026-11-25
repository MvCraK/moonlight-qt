// SS-NETWORK extension (see ss-network/README.md).
#pragma once

#ifndef SS_NETWORK_APP
// Builds without the extension (Steam Link on Qt 5.14, test projects): header-only
// stub providing just what the upstream hooks call.
#include <QHostAddress>
#include <QString>

class QNetworkProxyFactory;

class SsNetwork
{
public:
    static bool routes(const QHostAddress&) { return false; }
    static bool routes(const QString&) { return false; }
    static QNetworkProxyFactory* createProxyFactory() { return nullptr; }
};
#else

#include <QObject>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonObject>
#include <QUrl>
#include <QVariantList>

class QNetworkProxyFactory;
class QNetworkAccessManager;
class QTimer;

// Built-in Shadowsocks routing: 10.0.0.0/24 -> home (switchable between direct Clash
// subscriptions and fixed company relay), 10.1.1.0/24 -> company node. Exposed to QML
// as the "SsNetwork" singleton. The connection is never persisted: every launch starts
// disconnected, only the imported config, resolved nodes, and homeMode are kept.
class SsNetwork : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool available READ available CONSTANT)
    Q_PROPERTY(bool configured READ configured NOTIFY changed)
    Q_PROPERTY(bool enabled READ enabled NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString busyAction READ busyAction NOTIFY changed)
    Q_PROPERTY(bool failed READ failed NOTIFY changed)
    Q_PROPERTY(bool warning READ warning NOTIFY changed)
    Q_PROPERTY(QString errorCode READ errorCode NOTIFY changed)
    Q_PROPERTY(QString errorArg READ errorArg NOTIFY changed)
    Q_PROPERTY(QString warningPrefix READ warningPrefix NOTIFY changed)
    Q_PROPERTY(bool probing READ probing NOTIFY changed)
    Q_PROPERTY(int status READ status NOTIFY changed)
    Q_PROPERTY(QString homeMode READ homeMode NOTIFY changed)
    Q_PROPERTY(bool hasDirect READ hasDirect NOTIFY changed)
    Q_PROPERTY(bool hasDirectConfig READ hasDirectConfig NOTIFY changed)
    Q_PROPERTY(bool hasRelay READ hasRelay NOTIFY changed)
    Q_PROPERTY(bool systemVpnActive READ systemVpnActive NOTIFY changed)
    Q_PROPERTY(bool hasBypassInterface READ hasBypassInterface NOTIFY changed)
    Q_PROPERTY(QString bypassInterfaceLabel READ bypassInterfaceLabel NOTIFY changed)
    Q_PROPERTY(QVariantList nodes READ nodes NOTIFY changed)
    Q_PROPERTY(qint64 updated READ updated NOTIFY changed)
    Q_PROPERTY(qint64 receivedBytes READ receivedBytes NOTIFY trafficChanged)

public:
    enum Status
    {
        Unavailable,
        Off,
        Checking,
        Online,
        Degraded
    };
    Q_ENUM(Status)

    static SsNetwork* instance();

    // Thread-safe; true while connected and the address is in a routed /24.
    static bool routes(const QHostAddress& address);
    static bool routes(const QString& address);
    // Per-QNetworkAccessManager factory (the manager takes ownership).
    static QNetworkProxyFactory* createProxyFactory();

    bool available() const;
    bool configured() const;
    bool enabled() const;
    bool busy() const { return !m_BusyAction.isEmpty(); }
    QString busyAction() const { return m_BusyAction; }
    bool failed() const { return m_Failed; }
    bool warning() const { return m_Warning; }
    QString errorCode() const { return m_ErrorCode; }
    QString errorArg() const { return m_ErrorArg; }
    QString warningPrefix() const { return m_WarningPrefix; }
    bool probing() const { return m_PendingProbes > 0; }
    int status() const;
    QString homeMode() const;
    bool hasDirect() const;
    bool hasDirectConfig() const;
    bool hasRelay() const;
    bool systemVpnActive() const { return m_SystemVpnActive; }
    bool hasBypassInterface() const { return m_SystemVpnActive && m_BypassIfIndex != 0; }
    QString bypassInterfaceLabel() const { return m_BypassIfLabel; }
    QVariantList nodes() const;
    qint64 updated() const;
    qint64 receivedBytes() const;

    Q_INVOKABLE void toggle();
    Q_INVOKABLE void setHomeMode(const QString& mode);
    Q_INVOKABLE void importConfig(const QUrl& file);
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void probe(bool force = true);
    Q_INVOKABLE void refreshNetworkState();

signals:
    void changed();
    void trafficChanged();

private:
    explicit SsNetwork(QObject* parent = nullptr);
    void load();
    void migrateLegacyState(QJsonObject& state) const;
    bool save(const QJsonObject& state);
    QJsonArray activeNodesArray() const;
    bool relayUsesSingleEndpoint() const;
    void pushBypassInterface() const;
    bool activate();
    void deactivate();
    void startRefresh(const QJsonObject& config, bool isImport);
    void fetchSubscriptionSlot(int slot, const QUrl& url, int redirectsLeft);
    void finishRefresh();
    void clearMessage();
    void fail(const QString& code, const QString& arg = QString());
    void setBusy(const QString& action);
    void onTrafficTick();

    // {config, directNodes, relayNodes, companyNode, homeMode, updated}
    QJsonObject m_State;
    QString m_BusyAction;
    bool m_Failed = false;
    bool m_Warning = false;
    QString m_ErrorCode;
    QString m_ErrorArg;
    QString m_WarningPrefix;
    int m_PendingProbes = 0;
    quint64 m_ProbeGeneration = 0;
    qint64 m_ProbedAt = 0;
    QVariantList m_Probes; // 3 slots matching activeNodesArray(): latency ms, -1 unreachable, -2 skipped
    bool m_SystemVpnActive = false;
    quint32 m_BypassIfIndex = 0;
    QString m_BypassIfName;
    QString m_BypassIfLabel;
    int m_NetworkCheckTick = 0;
    QNetworkAccessManager* m_Nam = nullptr;
    QTimer* m_TrafficTimer = nullptr;

    // In-flight subscription refresh
    bool m_RefreshIsImport = false;
    bool m_SwitchToDirectOnRefresh = false;
    QJsonObject m_PendingConfig;
    QJsonObject m_PendingCompany;
    QJsonArray m_PendingRelayNodes;
    QByteArray m_Fetched[2];
    int m_PendingFetches = 0;
    bool m_FetchFailed = false;
    QString m_FetchErrorCode;
    QString m_FetchErrorArg;
};

#endif // SS_NETWORK_APP
