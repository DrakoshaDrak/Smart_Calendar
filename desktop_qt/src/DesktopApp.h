#pragma once

#include <QObject>
#include <QString>
#include <QSet>
#include <QUrl>

class LocalWebServer;
class QWebEngineView;

struct AppOptions {
    QString devUrl;
    QString apiBaseUrl;
    QString distDir;
    bool disableExternalOpen = false;
    bool devtools = false;
};

class DesktopApp : public QObject {
    Q_OBJECT
public:
    explicit DesktopApp(const AppOptions &opts, QObject *parent = nullptr);
    int run(int argc, char **argv);

private slots:
    void onServerStarted(quint16 port);

private:
    AppOptions m_opts;
    LocalWebServer *m_server = nullptr;
    quint16 m_serverPort = 0;
};
