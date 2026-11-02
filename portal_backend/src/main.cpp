#include "portal_backend.hpp"

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDebug>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("linux-mcp-portal"));
    QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));

    auto bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()) {
        qCritical() << "failed to connect to session bus";
        return 1;
    }

    constexpr auto serviceName = "org.freedesktop.impl.portal.desktop.linux_mcp";
    if (!bus.registerService(QString::fromLatin1(serviceName))) {
        qCritical() << "failed to own D-Bus service" << serviceName << bus.lastError().message();
        return 1;
    }

    hkcf::PortalBackend backend;
    if (!bus.registerVirtualObject(QStringLiteral("/org/freedesktop/portal/desktop"), &backend, QDBusConnection::SubPath)) {
        qCritical() << "failed to export portal object" << bus.lastError().message();
        return 1;
    }

    qInfo() << "linux-mcp RemoteDesktop portal backend running";
    return app.exec();
}
