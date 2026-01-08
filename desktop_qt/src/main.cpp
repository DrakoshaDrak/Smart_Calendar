#include "DesktopApp.h"

#include <QString>
#include <QDebug>

static QString parseArgValue(const QString &arg, const QString &prefix) {
    if (arg.startsWith(prefix)) return arg.mid(prefix.size());
    return QString();
}

int main(int argc, char **argv) {
    AppOptions opts;

    for (int i = 1; i < argc; ++i) {
        QString a = QString::fromLocal8Bit(argv[i]);
        if (a.startsWith("--dev-url=")) {
            opts.devUrl = parseArgValue(a, "--dev-url=");
        } else if (a.startsWith("--api-base-url=")) {
            opts.apiBaseUrl = parseArgValue(a, "--api-base-url=");
        } else if (a.startsWith("--dist-dir=")) {
            opts.distDir = parseArgValue(a, "--dist-dir=");
        } else if (a == "--disable-external-open") {
            opts.disableExternalOpen = true;
        } else if (a == "--devtools") {
            opts.devtools = true;
        } else if (a == "--help" || a == "-h") {
            qInfo() << "Usage: desktop_app [--dev-url=URL] [--api-base-url=URL] [--dist-dir=PATH] [--disable-external-open] [--devtools]";
            return 0;
        }
    }

    DesktopApp app(opts);
    return app.run(argc, argv);
}
