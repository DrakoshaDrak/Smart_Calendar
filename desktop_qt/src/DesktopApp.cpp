#include "DesktopApp.h"
#include "LocalWebServer.h"
#include "CustomWebPage.h"

#include <QApplication>
#include <QMainWindow>
#include <QWebEngineView>
#include <QWebEngineProfile>
#include <QWebEngineScriptCollection>
#include <QJsonDocument>
#include <QJsonObject>
#include <QWebEngineScript>
#include <QStandardPaths>
#include <QDir>
#include <QDebug>

DesktopApp::DesktopApp(const AppOptions &opts, QObject *parent)
    : QObject(parent), m_opts(opts)
{
}

void addAppConfigScript(QWebEngineProfile *profile, const QString &apiBaseUrl) {
    
    QJsonObject obj;
    obj.insert("apiBaseUrl", apiBaseUrl);
    obj.insert("desktop", true);
    QJsonDocument doc(obj);
    QString json = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
    QString js = QString("window.__APP_CONFIG__ = %1;\n").arg(json);

    QWebEngineScript script;
    script.setName("app_config_inject");
    script.setInjectionPoint(QWebEngineScript::DocumentCreation);
    script.setRunsOnSubFrames(false);
    script.setWorldId(QWebEngineScript::MainWorld);
    script.setSourceCode(js);
    profile->scripts()->insert(script);
}

int DesktopApp::run(int argc, char **argv) {
    QApplication app(argc, argv);

    
    QString storage = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(storage);
    QWebEngineProfile *profile = new QWebEngineProfile("calendar_desktop", this);
    profile->setPersistentStoragePath(storage);

    addAppConfigScript(profile, m_opts.apiBaseUrl);

    QMainWindow mainWin;
    QWebEngineView *view = new QWebEngineView(&mainWin);

    
    QSet<QUrl> allow;
    if (!m_opts.devUrl.isEmpty()) {
        QUrl u(m_opts.devUrl);
        QUrl origin = u;
        origin.setPath(QString()); origin.setQuery(QString()); origin.setFragment(QString());
        allow.insert(origin);
    }

    m_server = nullptr;
    if (m_opts.devUrl.isEmpty()) {
        
        QString dist = m_opts.distDir.isEmpty() ? QDir(QCoreApplication::applicationDirPath()).filePath("../web_frontend/dist") : m_opts.distDir;
        m_server = new LocalWebServer(dist, this);
        connect(m_server, &LocalWebServer::started, this, &DesktopApp::onServerStarted);
        if (!m_server->start()) {
            qWarning() << "Failed to start local server";
            return 2;
        }
        
        m_serverPort = m_server->port();
        QUrl origin(QString("http://127.0.0.1:%1").arg(m_serverPort));
        allow.insert(origin);
        view->setPage(new CustomWebPage(profile, allow, m_opts.disableExternalOpen, view));
        view->load(QUrl(QString("http://127.0.0.1:%1/").arg(m_serverPort)));
    } else {
        QUrl origin(m_opts.devUrl);
        origin.setPath(QString()); origin.setQuery(QString()); origin.setFragment(QString());
        allow.insert(origin);
        view->setPage(new CustomWebPage(profile, allow, m_opts.disableExternalOpen, view));
        view->load(QUrl(m_opts.devUrl));
    }

    mainWin.setCentralWidget(view);
    mainWin.resize(1200, 800);
    mainWin.show();

    
    QMainWindow *devtoolsWindow = nullptr;
    if (m_opts.devtools) {
        devtoolsWindow = new QMainWindow(&mainWin);
        devtoolsWindow->setWindowTitle("DevTools");
        QWebEngineView *devView = new QWebEngineView(devtoolsWindow);
        
        QWebEnginePage *devPage = new QWebEnginePage(profile, devView);
        devView->setPage(devPage);
        view->page()->setDevToolsPage(devPage);
        devtoolsWindow->setCentralWidget(devView);
        devtoolsWindow->resize(1000, 700);
        devtoolsWindow->show();
    }

    return app.exec();
}

void DesktopApp::onServerStarted(quint16 port) {
    m_serverPort = port;
    qInfo() << "Server started callback, port=" << port;
}
