#include <QCoreApplication>
#include <QTcpSocket>
#include <QTimer>
#include <QFile>
#include <QDir>
#include <QDebug>
#include <cstdlib>
#include "../src/LocalWebServer.h"
#include <QThread>


static bool sendRequestAndRead(const QString &host, quint16 port, const QByteArray &req, QByteArray &out) {
    QTcpSocket s;
    s.connectToHost(host, port);
    if (!s.waitForConnected(2000)) {
        qWarning() << "connect failed" << s.errorString();
        return false;
    }
    
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    s.write(req);
    if (!s.waitForBytesWritten(2000)) {
        qWarning() << "write failed";
        return false;
    }
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    
    int totalWait = 0;
    const int step = 50;
    while (totalWait < 3000) {
        
        QCoreApplication::processEvents(QEventLoop::AllEvents, step);
        if (s.waitForReadyRead(step)) {
            out += s.readAll();
            if (s.state() == QAbstractSocket::UnconnectedState) break;
            totalWait = 0;
        } else {
            totalWait += step;
        }
    }
    if (out.isEmpty()) {
        qWarning() << "no response";
        return false;
    }
    s.disconnectFromHost();
    return true;
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);

    
    QDir tmp(QDir::tempPath());
    QString base = tmp.filePath("localwebserver_smoke_test_dist");
    QDir(base).removeRecursively();
    QDir().mkpath(base + "/assets");
    QFile fIndex(base + "/index.html"); fIndex.open(QIODevice::WriteOnly); fIndex.write("<html>ok</html>"); fIndex.close();
    QFile fAsset(base + "/assets/app.abcdef.js"); fAsset.open(QIODevice::WriteOnly); fAsset.write("console.log('asset');"); fAsset.close();

    
        
        LocalWebServer *server = createServerForTest(base);
        if (!server) { qWarning() << "failed to create server"; return 1; }

        QThread *srvThread = new QThread;
        server->moveToThread(srvThread);

        quint16 port = 0;
        QObject::connect(server, &LocalWebServer::started, [&](quint16 p){ port = p; qInfo() << "server port" << port; });
        QObject::connect(srvThread, &QThread::started, [server]() {
            
            QMetaObject::invokeMethod(server, "start", Qt::QueuedConnection);
        });

        srvThread->start();

        
        int waited = 0;
        while (port == 0 && waited < 5000) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
            QThread::msleep(50);
            waited += 50;
        }
        if (port == 0) { qWarning() << "server did not start in time"; return 1; }

    auto check = [&](const QByteArray &req, const QString &mustContain, int expectedCode)->bool{
        QByteArray resp;
        if (!sendRequestAndRead("127.0.0.1", port, req, resp)) return false;
        QString s = QString::fromUtf8(resp);
        qInfo().noquote() << s;
        if (!s.contains(mustContain)) { qWarning() << "missing" << mustContain; return false; }
        
        if (!s.startsWith(QString("HTTP/1.1 %1").arg(expectedCode))) { qWarning() << "status mismatch" << s.left(64); return false; }
        return true;
    };

    bool ok = true;
    ok &= check(QByteArray("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"), "Content-Type: text/html", 200);
    ok &= check(QByteArray("GET /foo/bar HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"), "Content-Type: text/html", 200);
    ok &= check(QByteArray("GET /assets/app.abcdef.js HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"), "immutable", 200);
    ok &= check(QByteArray("GET /assets/nope.js HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"), "Not Found", 404);

    qInfo() << "smoke test result" << ok;

    
    QMetaObject::invokeMethod(server, "deleteLater", Qt::QueuedConnection);
    srvThread->quit();
    srvThread->wait(2000);
    delete srvThread;

    QDir(base).removeRecursively();
    return ok ? 0 : 1;
}
