#include "CustomWebPage.h"
#include <QDesktopServices>
#include <QDebug>


static OriginTuple originTupleForUrl(const QUrl &u) {
    OriginTuple t;
    t.scheme = u.scheme().toLower();
    t.host = u.host().toLower();
    int p = u.port();
    if (p <= 0) {
        
        if (t.scheme == "http") p = 80;
        else if (t.scheme == "https") p = 443;
    }
    t.port = static_cast<quint16>(p);
    return t;
}

CustomWebPage::CustomWebPage(const QSet<QUrl> &allowOrigins, bool disableExternalOpen, QObject *parent)
    : QWebEnginePage(parent), m_disableExternalOpen(disableExternalOpen)
{
    
    for (const QUrl &u : allowOrigins) {
        if (u.isEmpty()) continue;
        QUrl o = u;
        o.setPath(QString()); o.setQuery(QString()); o.setFragment(QString());
        m_allowOrigins.insert(QUrl(o)); 
    }
}

CustomWebPage::CustomWebPage(QWebEngineProfile *profile, const QSet<QUrl> &allowOrigins, bool disableExternalOpen, QObject *parent)
    : QWebEnginePage(profile, parent), m_disableExternalOpen(disableExternalOpen)
{
    for (const QUrl &u : allowOrigins) {
        if (u.isEmpty()) continue;
        QUrl o = u;
        o.setPath(QString()); o.setQuery(QString()); o.setFragment(QString());
        m_allowOrigins.insert(QUrl(o));
    }
}

bool CustomWebPage::acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame) {
    Q_UNUSED(type);
    
    OriginTuple target = originTupleForUrl(url);

    
    for (const QUrl &a : m_allowOrigins) {
        OriginTuple ao = originTupleForUrl(a);
        if (ao == target) return true;
    }

    if (isMainFrame) {
        
        if (!m_disableExternalOpen) {
            qInfo() << "Opening external URL in system browser:" << url.toString();
            QDesktopServices::openUrl(url);
        } else {
            qInfo() << "Blocked external URL (disabled):" << url;
        }
        return false;
    }

    
    if (url.scheme() == "data" || url.scheme() == "blob") return true;
    OriginTuple res = originTupleForUrl(url);
    for (const QUrl &a : m_allowOrigins) {
        OriginTuple ao = originTupleForUrl(a);
        if (ao == res) return true;
    }

    qWarning() << "Blocked subresource from non-allowlisted origin:" << url;
    return false;
}
