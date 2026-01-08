#pragma once

#include <QWebEnginePage>
#include <QUrl>
#include <QSet>

#include <QString>

struct OriginTuple {
    QString scheme;
    QString host;
    quint16 port;
    bool operator==(OriginTuple const& o) const {
        return scheme == o.scheme && host == o.host && port == o.port;
    }
};

#include <QSet>

class CustomWebPage : public QWebEnginePage {
    Q_OBJECT
public:
    explicit CustomWebPage(const QSet<QUrl> &allowOrigins, bool disableExternalOpen = false, QObject *parent = nullptr);
    
    explicit CustomWebPage(QWebEngineProfile *profile, const QSet<QUrl> &allowOrigins, bool disableExternalOpen = false, QObject *parent = nullptr);

protected:
    bool acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame) override;

private:
    QSet<QUrl> m_allowOrigins;
    bool m_disableExternalOpen = false;
};
