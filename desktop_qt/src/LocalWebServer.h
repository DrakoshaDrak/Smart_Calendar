#pragma once

#include <QObject>
#include <QTcpServer>
#include <QHostAddress>

class LocalWebServer : public QObject {
    Q_OBJECT
public:
    explicit LocalWebServer(QString distDir, QObject *parent = nullptr);
    ~LocalWebServer();

    Q_INVOKABLE bool start();
    quint16 port() const;

signals:
    void started(quint16 port);

private slots:
    void onNewConnection();

private:
    QString m_distDir;
    QTcpServer *m_server = nullptr;
    QHostAddress m_address = QHostAddress::LocalHost;
    quint16 m_port = 0;
};


LocalWebServer* createServerForTest(const QString &distDir);
