#include "LocalWebServer.h"

#include <QTcpSocket>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QUrl>
#include <QDateTime>
#include <QCoreApplication>
#include <QStandardPaths>
#include <QDebug>
#include <memory>
#include <QRegularExpression>

static QByteArray reasonPhrase(int code) {
    switch (code) {
    case 200: return "OK";
    case 404: return "Not Found";
    case 400: return "Bad Request";
    case 500: return "Internal Server Error";
    default: return "";
    }
}


LocalWebServer* createServerForTest(const QString &distDir) {
    return new LocalWebServer(distDir);
}

static QByteArray contentTypeForPath(const QString &path) {
    if (path.endsWith(".html")) return "text/html; charset=utf-8";
    if (path.endsWith(".js")) return "application/javascript; charset=utf-8";
    if (path.endsWith(".css")) return "text/css; charset=utf-8";
    if (path.endsWith(".svg")) return "image/svg+xml";
    if (path.endsWith(".png")) return "image/png";
    if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
    if (path.endsWith(".woff2")) return "font/woff2";
    if (path.endsWith(".woff")) return "font/woff";
    if (path.endsWith(".ttf")) return "font/ttf";
    if (path.endsWith(".ico")) return "image/x-icon";
    return "application/octet-stream";
}

static bool isHashedAsset(const QString &requestPath, const QString &fileName) {
    
    if (!requestPath.startsWith("/assets/")) return false;
    
    static const QRegularExpression re(".*\\.([a-fA-F0-9]{6,})\\.[^./]+$");
    return re.match(fileName).hasMatch();
}

LocalWebServer::LocalWebServer(QString distDir, QObject *parent)
    : QObject(parent), m_distDir(std::move(distDir))
{
}

LocalWebServer::~LocalWebServer() {
    if (m_server) {
        m_server->close();
        m_server->deleteLater();
    }
}

bool LocalWebServer::start() {
    if (m_server) return true;

    m_server = new QTcpServer(this);
    connect(m_server, &QTcpServer::newConnection, this, &LocalWebServer::onNewConnection);

    if (!m_server->listen(m_address, 0)) {
        qWarning() << "LocalWebServer: failed to listen:" << m_server->errorString();
        return false;
    }

    m_port = m_server->serverPort();
    qInfo() << "LocalWebServer listening on" << m_address.toString() << ":" << m_port;
    emit started(m_port);
    return true;
}

quint16 LocalWebServer::port() const { return m_port; }


static bool parseRequestLine(const QByteArray &line, QByteArray &method, QByteArray &path) {
    
    QList<QByteArray> parts = line.split(' ');
    if (parts.size() < 3) return false;
    method = parts.at(0);
    path = parts.at(1);
    return true;
}

void LocalWebServer::onNewConnection() {
    while (m_server->hasPendingConnections()) {
        QTcpSocket *sock = m_server->nextPendingConnection();
        sock->setSocketOption(QAbstractSocket::LowDelayOption, 1);


        
        struct ReqState { std::shared_ptr<QByteArray> buf; bool handled = false; ReqState(): buf(std::make_shared<QByteArray>()) {} };
        auto state = std::make_shared<ReqState>();

        connect(sock, &QTcpSocket::readyRead, [this, sock, state]() {
            const qint64 MAX_HEADERS = 8*1024; 
            if (state->handled) return; 
            state->buf->append(sock->readAll());

            if (state->buf->size() > MAX_HEADERS) {
                
                QByteArray msg = "Too Large\n";
                QByteArray statusLine = "HTTP/1.1 413 Request Entity Too Large\r\n";
                QByteArray headers;
                headers += "Content-Type: text/plain; charset=utf-8\r\n";
                headers += "Connection: close\r\n";
                headers += QString("Content-Length: %1\r\n\r\n").arg(msg.size()).toUtf8();
                sock->write(statusLine);
                sock->write(headers);
                sock->write(msg);
                sock->disconnectFromHost();
                state->handled = true;
                return;
            }

            int hdrEnd = state->buf->indexOf("\r\n\r\n");
            if (hdrEnd == -1) {
                
                return;
            }

            QByteArray headerBlock = state->buf->left(hdrEnd);
            QList<QByteArray> lines = headerBlock.split('\n');
            if (lines.isEmpty()) {
                QByteArray statusLine = "HTTP/1.1 400 Bad Request\r\n";
                QByteArray headers = "Connection: close\r\nContent-Length: 0\r\n\r\n";
                sock->write(statusLine);
                sock->write(headers);
                sock->disconnectFromHost();
                state->handled = true;
                return;
            }

            QByteArray method, rawPath;
            if (!parseRequestLine(lines.at(0).trimmed(), method, rawPath)) {
                QByteArray msg = "Bad Request\n";
                QByteArray statusLine = "HTTP/1.1 400 Bad Request\r\n";
                QByteArray headers;
                headers += "Content-Type: text/plain; charset=utf-8\r\n";
                headers += "Connection: close\r\n";
                headers += QString("Content-Length: %1\r\n\r\n").arg(msg.size()).toUtf8();
                sock->write(statusLine);
                sock->write(headers);
                sock->write(msg);
                sock->disconnectFromHost();
                state->handled = true;
                return;
            }

            bool isHead = (method == "HEAD");
            if (!(method == "GET" || method == "HEAD")) {
                QByteArray msg = "Method Not Allowed\n";
                QByteArray statusLine = "HTTP/1.1 405 Method Not Allowed\r\n";
                QByteArray headers;
                headers += "Content-Type: text/plain; charset=utf-8\r\n";
                headers += "Connection: close\r\n";
                headers += QString("Content-Length: %1\r\n\r\n").arg(msg.size()).toUtf8();
                sock->write(statusLine);
                sock->write(headers);
                sock->write(msg);
                sock->disconnectFromHost();
                state->handled = true;
                return;
            }

            
            QString path = QUrl::fromPercentEncoding(rawPath);

            
            int qpos = path.indexOf('?');
            if (qpos >= 0) path = path.left(qpos);

            
            
            if (path.isEmpty() || !path.startsWith('/')) {
                QByteArray msg = "Bad Request\n";
                QByteArray statusLine = "HTTP/1.1 400 Bad Request\r\n";
                QByteArray headers;
                headers += "Content-Type: text/plain; charset=utf-8\r\n";
                headers += "Connection: close\r\n";
                headers += QString("Content-Length: %1\r\n\r\n").arg(msg.size()).toUtf8();
                sock->write(statusLine);
                sock->write(headers);
                sock->write(msg);
                sock->disconnectFromHost();
                state->handled = true;
                return;
            }

            QDir base(m_distDir);
            QString targetAbs;
            bool targetIsFile = false;

            if (path == "/") {
                targetAbs = base.filePath("index.html");
                targetIsFile = true;
            } else {
                QString candidate = base.filePath(path.mid(1));
                QFileInfo candInfo(candidate);
                if (candInfo.exists() && candInfo.isFile()) {
                    targetAbs = candInfo.absoluteFilePath();
                    targetIsFile = true;
                } else {
                    
                    if (QFileInfo(path).suffix().isEmpty()) {
                        targetAbs = base.filePath("index.html");
                        targetIsFile = true;
                    } else {
                        targetIsFile = false;
                    }
                }
            }

            int status = 200;
            QByteArray contentType;
            QByteArray bodyToSend;
            QString cacheHeader;

            if (!targetIsFile) {
                status = 404;
                bodyToSend = "Not Found\n";
                contentType = "text/plain; charset=utf-8";
            } else {
                
                QString baseCanonical = QFileInfo(base.absolutePath()).canonicalFilePath();
                QString targetCanonical = QFileInfo(targetAbs).canonicalFilePath();
                if (targetCanonical.isEmpty() || baseCanonical.isEmpty() || !targetCanonical.startsWith(baseCanonical + QDir::separator())) {
                    qWarning() << "LocalWebServer: path traversal or outside dist:" << path << "->" << targetCanonical;
                    status = 404;
                    bodyToSend = "Not Found\n";
                    contentType = "text/plain; charset=utf-8";
                } else {
                    QFile f(targetCanonical);
                        if (!f.open(QFile::ReadOnly)) {
                            status = 500;
                            bodyToSend = "Internal Server Error\n";
                            contentType = "text/plain; charset=utf-8";
                        } else {
                            QByteArray data = f.readAll();
                            bodyToSend = data;
                            QString fileName = QFileInfo(targetCanonical).fileName();
                            contentType = contentTypeForPath(fileName);
                            
                            
                            if (contentType.startsWith("text/html")) {
                                cacheHeader = "no-cache";
                            } else if (isHashedAsset(path, fileName)) {
                                cacheHeader = "public, max-age=31536000, immutable";
                            } else {
                                cacheHeader = "public, max-age=0";
                            }
                        }
                }
            }

            QByteArray statusLine = QByteArray("HTTP/1.1 ") + QByteArray::number(status) + " " + reasonPhrase(status) + "\r\n";
            QByteArray headers;
            headers += "Content-Type: " + contentType + "\r\n";
            headers += "X-Content-Type-Options: nosniff\r\n";
            if (status == 200) {
                if (cacheHeader.isEmpty()) {
                    if (contentType.startsWith("text/html")) cacheHeader = "no-cache";
                    else cacheHeader = "public, max-age=0";
                }
                headers += QString("Cache-Control: %1\r\n").arg(cacheHeader).toUtf8();
            }
            headers += "Connection: close\r\n";
            headers += QString("Content-Length: %1\r\n").arg(bodyToSend.size()).toUtf8();
            headers += "\r\n";

            sock->write(statusLine);
            sock->write(headers);
            if (!isHead && !bodyToSend.isEmpty()) {
                sock->write(bodyToSend);
            }

            sock->disconnectFromHost();
            state->handled = true;
        });

        connect(sock, &QTcpSocket::disconnected, sock, &QTcpSocket::deleteLater);
    }
}
