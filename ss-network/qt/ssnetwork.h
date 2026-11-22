// SS-NETWORK extension (see ss-network/README.md).
#pragma once

#include <QObject>
#include <QHostAddress>
#include <QJsonObject>
#include <QUrl>
#include <QVariantList>

class QNetworkProxyFactory;
class QNetworkAccessManager;
class QTimer;

// Built-in Shadowsocks routing: 10.0.0.0/24 -> home (TCP node / UDP node from two
// Clash subscriptions), 10.1.1.0/24 -> company node. Exposed to QML as the
// "SsNetwork" singleton. The connection is never persisted: every launch starts
// disconnected, only the imported config and resolved nodes are kept.
class SsNetwork : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool available READ available CONSTANT)
    Q_PROPERTY(bool configured READ configured NOTIFY changed)
    Q_PROPERTY(bool enabled READ enabled NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString busyAction READ busyAction NOTIFY changed)
    Q_PROPERTY(bool failed READ failed NOTIFY changed)
    Q_PROPERTY(bool probing READ probing NOTIFY changed)
    Q_PROPERTY(int status READ status NOTIFY changed)
    Q_PROPERTY(QVariantList nodes READ nodes NOTIFY changed)
    Q_PROPERTY(qint64 updated READ updated NOTIFY changed)
    Q_PROPERTY(qint64 receivedBytes READ receivedBytes NOTIFY trafficChanged)

public:
    enum Status { Unavailable, Off, Checking, Online, Degraded };
    Q_ENUM(Status)

    static SsNetwork* instance();

    // Thread-safe; true while connected and the address is in a routed /24.
    static bool routes(const QHostAddress& address);
    static bool routes(const QString& address);
    // Per-QNetworkAccessManager factory (the manager takes ownership).
    static QNetworkProxyFactory* createProxyFactory();

    bool available() const;
    bool configured() const { return m_State.contains("nodes"); }
    bool enabled() const;
    bool busy() const { return !m_BusyAction.isEmpty(); }
    QString busyAction() const { return m_BusyAction; }
    bool failed() const { return m_Failed; }
    bool probing() const { return m_PendingProbes > 0; }
    int status() const;
    QVariantList nodes() const;
    qint64 updated() const;
    qint64 receivedBytes() const;

    Q_INVOKABLE void toggle();
    Q_INVOKABLE void importConfig(const QUrl& file);
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void probe(bool force = true);

signals:
    void changed();
    void trafficChanged();

private:
    explicit SsNetwork(QObject* parent = nullptr);
    void load();
    bool save(const QJsonObject& state);
    bool activate();
    void deactivate();
    void startRefresh(const QJsonObject& config);
    void finishRefresh();
    void fail();
    void setBusy(const QString& action);

    QJsonObject m_State;         // {nodes:[tcp,udp,company], updated, config:{homeTcp,homeUdp,company}}
    QString m_BusyAction;
    bool m_Failed = false;
    int m_PendingProbes = 0;
    qint64 m_ProbedAt = 0;
    QVariantList m_Probes;       // per node: latency ms, -1 unreachable, -2 not probed (UDP only)
    QNetworkAccessManager* m_Nam = nullptr;
    QTimer* m_TrafficTimer = nullptr;

    // In-flight subscription refresh
    QJsonObject m_PendingConfig;
    QByteArray m_Fetched[2];
    int m_PendingFetches = 0;
    bool m_FetchFailed = false;
};
