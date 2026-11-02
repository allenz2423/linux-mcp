#include "portal_backend.hpp"
#include "security_policy.hpp"
#include "wayland_input.hpp"

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusArgument>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusVariant>
#include <QEventLoop>
#include <QTimer>

#include <iostream>
#include <stdexcept>

namespace {

int inputEvents = 0;

void check(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

QString senderPathSegment(const QString& uniqueName) {
    QString segment = uniqueName;
    if (segment.startsWith(QLatin1Char(':')))
        segment.remove(0, 1);
    segment.replace(QLatin1Char('.'), QLatin1Char('_'));
    return segment;
}

class Portal {
  public:
    QString connectionSuffix = QString::number(++nextId);
    QDBusConnection backendBus = QDBusConnection::connectToBus(QDBusConnection::SessionBus, QStringLiteral("backend-%1").arg(connectionSuffix));
    QDBusConnection frontend = QDBusConnection::connectToBus(QDBusConnection::SessionBus, QStringLiteral("frontend-%1").arg(connectionSuffix));
    QDBusConnection owner = QDBusConnection::connectToBus(QDBusConnection::SessionBus, QStringLiteral("owner-%1").arg(connectionSuffix));
    QString service;
    hkcf::PortalBackend backend;
    int serial = 0;

    static int nextId;

    Portal(QString serviceName, const QString& permissionPrompt)
        : service(std::move(serviceName)), backend(permissionPrompt) {
        check(frontend.registerService(QStringLiteral("org.freedesktop.portal.Desktop")), "private portal frontend service");
        check(backendBus.registerService(service), "private portal backend service");
        check(backendBus.registerVirtualObject(QStringLiteral("/org/freedesktop/portal/desktop"), &backend, QDBusConnection::SubPath),
              "export portal backend object");
    }

    ~Portal() {
        backendBus.unregisterObject(QStringLiteral("/org/freedesktop/portal/desktop"));
        backendBus.unregisterService(service);
        frontend.unregisterService(QStringLiteral("org.freedesktop.portal.Desktop"));
        QDBusConnection::disconnectFromBus(QStringLiteral("backend-%1").arg(connectionSuffix));
        QDBusConnection::disconnectFromBus(QStringLiteral("frontend-%1").arg(connectionSuffix));
        QDBusConnection::disconnectFromBus(QStringLiteral("owner-%1").arg(connectionSuffix));
    }

    QDBusMessage call(const QString& path, const QString& interface, const QString& method, const QList<QVariant>& args = {}) {
        QDBusMessage message = QDBusMessage::createMethodCall(service, path, interface, method);
        message.setArguments(args);
        QDBusPendingCallWatcher watcher(frontend.asyncCall(message, 5000));
        QEventLoop loop;
        QObject::connect(&watcher, &QDBusPendingCallWatcher::finished, &loop, &QEventLoop::quit);
        QTimer::singleShot(6000, &loop, &QEventLoop::quit);
        if (!watcher.isFinished())
            loop.exec();
        check(watcher.isFinished(), "portal method timed out");
        return watcher.reply();
    }

    QString makeSession(uint32_t deviceTypes = 1, const QString& appId = QStringLiteral("org.example.linux_mcp")) {
        const QString sender = senderPathSegment(owner.baseService());
        const QString base = QStringLiteral("/org/freedesktop/portal/desktop");
        const QString sessionPath = base + QStringLiteral("/session/") + sender + QStringLiteral("/case") + QString::number(++serial);
        const QString requestPath = base + QStringLiteral("/request/") + sender + QStringLiteral("/case") + QString::number(serial);
        const auto request = QVariant::fromValue(QDBusObjectPath(requestPath));
        const auto session = QVariant::fromValue(QDBusObjectPath(sessionPath));
        const QDBusMessage created = call(base, QStringLiteral("org.freedesktop.impl.portal.RemoteDesktop"), QStringLiteral("CreateSession"),
                                          {request, session, appId, QVariantMap{}});
        check(created.type() != QDBusMessage::ErrorMessage && !created.arguments().isEmpty() && created.arguments().first().toUInt() == 0,
              "CreateSession succeeded");
        const QDBusMessage selected = call(base, QStringLiteral("org.freedesktop.impl.portal.RemoteDesktop"), QStringLiteral("SelectDevices"),
                                           {request, session, appId, QVariantMap{{QStringLiteral("types"), deviceTypes}}});
        check(selected.type() != QDBusMessage::ErrorMessage && !selected.arguments().isEmpty() && selected.arguments().first().toUInt() == 0,
              "SelectDevices succeeded");
        return sessionPath;
    }

    QDBusMessage start(const QString& path, const QString& appId = QStringLiteral("org.example.linux_mcp")) {
        const QString base = QStringLiteral("/org/freedesktop/portal/desktop");
        const QString sender = senderPathSegment(owner.baseService());
        const auto request = QVariant::fromValue(QDBusObjectPath(base + QStringLiteral("/request/") + sender + QStringLiteral("/start") + QString::number(serial)));
        return call(base, QStringLiteral("org.freedesktop.impl.portal.RemoteDesktop"), QStringLiteral("Start"),
                    {request, QVariant::fromValue(QDBusObjectPath(path)), appId, QString(), QVariantMap{}});
    }

    QDBusMessage notify(const QString& path, const QString& method, const QList<QVariant>& values) {
        QList<QVariant> args{QVariant::fromValue(QDBusObjectPath(path)), QVariantMap{}};
        args.append(values);
        return call(QStringLiteral("/org/freedesktop/portal/desktop"), QStringLiteral("org.freedesktop.impl.portal.RemoteDesktop"), method, args);
    }

    void close(const QString& path) {
        const QDBusMessage reply = call(path, QStringLiteral("org.freedesktop.impl.portal.Session"), QStringLiteral("Close"));
        check(reply.type() != QDBusMessage::ErrorMessage, "Session.Close succeeded");
    }
};

int Portal::nextId = 0;

void testPermissionGrantAndRevocation(const QString& promptExecutable) {
    Portal portal(QStringLiteral("org.freedesktop.impl.portal.desktop.accept"), promptExecutable);
    const QString path = portal.makeSession(1);

    const int beforeUnapprovedInput = inputEvents;
    check(portal.notify(path, QStringLiteral("NotifyKeyboardKeycode"), {int(KEY_A), 1u}).type() != QDBusMessage::ErrorMessage,
          "pre-start input request handled");
    check(inputEvents == beforeUnapprovedInput, "input is not injected before the permission prompt accepts");

    const QDBusMessage started = portal.start(path);
    check(started.type() != QDBusMessage::ErrorMessage && started.arguments().size() == 2, "Start returned portal response");
    check(started.arguments().at(0).toUInt() == 0, "user-approved Start succeeded");
    QVariantMap startResults;
    if (started.arguments().at(1).metaType() == QMetaType::fromType<QDBusArgument>())
        started.arguments().at(1).value<QDBusArgument>() >> startResults;
    else
        startResults = started.arguments().at(1).toMap();
    QVariant devicesValue = startResults.value(QStringLiteral("devices"));
    if (devicesValue.metaType() == QMetaType::fromType<QDBusVariant>())
        devicesValue = devicesValue.value<QDBusVariant>().variant();
    check(devicesValue.toUInt() == 1,
          "Start granted only the selected keyboard device");

    const int beforePress = inputEvents;
    check(portal.notify(path, QStringLiteral("NotifyKeyboardKeycode"), {int(KEY_A), 1u}).type() != QDBusMessage::ErrorMessage,
          "approved keyboard input succeeded");
    check(inputEvents == beforePress + 1, "approved input reached the compositor adapter");
    check(portal.notify(path, QStringLiteral("NotifyPointerButton"), {int(BTN_LEFT), 1u}).type() == QDBusMessage::ErrorMessage,
          "keyboard-only grant cannot inject pointer input");

    portal.close(path);
    check(inputEvents == beforePress + 2, "session close released the held key");
}

void testDenialAndIdentityChecks(const QString& denyExecutable) {
    Portal portal(QStringLiteral("org.freedesktop.impl.portal.desktop.deny"), denyExecutable);
    const QString path = portal.makeSession(3);
    const QDBusMessage denied = portal.start(path);
    check(denied.type() != QDBusMessage::ErrorMessage && !denied.arguments().isEmpty(), "denied Start returned a portal response");
    check(denied.arguments().first().toUInt() == 1, "closed or denied prompt does not grant input");
    const int before = inputEvents;
    check(portal.notify(path, QStringLiteral("NotifyKeyboardKeycode"), {int(KEY_A), 1u}).type() != QDBusMessage::ErrorMessage,
          "input request to an unstarted session handled");
    check(inputEvents == before, "denied session cannot inject input");

    const QString mismatchedPath = portal.makeSession(1);
    const QDBusMessage mismatched = portal.start(mismatchedPath, QStringLiteral("org.example.other_app"));
    check(mismatched.type() == QDBusMessage::ErrorMessage, "Start cannot change the session app id");
    portal.close(mismatchedPath);
}

void testUnsupportedDeviceMask(const QString& promptExecutable) {
    Portal portal(QStringLiteral("org.freedesktop.impl.portal.desktop.mask"), promptExecutable);
    const QString sender = senderPathSegment(portal.owner.baseService());
    const QString base = QStringLiteral("/org/freedesktop/portal/desktop");
    const QString path = base + QStringLiteral("/session/") + sender + QStringLiteral("/unsupported");
    const QString requestPath = base + QStringLiteral("/request/") + sender + QStringLiteral("/unsupported");
    const auto request = QVariant::fromValue(QDBusObjectPath(requestPath));
    const auto session = QVariant::fromValue(QDBusObjectPath(path));
    const QString appId = QStringLiteral("org.example.linux_mcp");
    const QDBusMessage created = portal.call(base, QStringLiteral("org.freedesktop.impl.portal.RemoteDesktop"), QStringLiteral("CreateSession"),
                                             {request, session, appId, QVariantMap{}});
    check(created.type() != QDBusMessage::ErrorMessage && created.arguments().first().toUInt() == 0, "mask test CreateSession succeeded");
    const QDBusMessage selected = portal.call(base, QStringLiteral("org.freedesktop.impl.portal.RemoteDesktop"), QStringLiteral("SelectDevices"),
                                              {request, session, appId, QVariantMap{{QStringLiteral("types"), 4u}}});
    check(selected.type() != QDBusMessage::ErrorMessage && selected.arguments().first().toUInt() == 2,
          "unsupported device bits are rejected");
    portal.close(path);
}

} // namespace

namespace hkcf {

WaylandInput::WaylandInput() = default;
WaylandInput::~WaylandInput() = default;
bool WaylandInput::ensureReady() { return true; }
QString WaylandInput::lastError() const { return {}; }
QRect WaylandInput::logicalBounds() const { return {0, 0, 1920, 1080}; }
bool WaylandInput::pointerMotion(double, double) { ++inputEvents; return true; }
bool WaylandInput::pointerMotionAbsolute(double, double) { ++inputEvents; return true; }
bool WaylandInput::pointerButton(std::uint32_t, bool) { ++inputEvents; return true; }
bool WaylandInput::pointerAxis(double, double) { ++inputEvents; return true; }
bool WaylandInput::pointerAxisDiscrete(std::uint32_t, int) { ++inputEvents; return true; }
bool WaylandInput::keyboardKeycode(std::uint32_t, bool, bool) { ++inputEvents; return true; }
bool WaylandInput::keyboardKeysym(std::uint32_t, bool) { ++inputEvents; return true; }

} // namespace hkcf

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        check(qEnvironmentVariableIsSet("DBUS_SESSION_BUS_ADDRESS"), "test runs on a private dbus-run-session bus");
        const QString acceptExecutable = QString::fromLocal8Bit(TEST_ACCEPT_PROMPT);
        const QString denyExecutable = QString::fromLocal8Bit(TEST_DENY_PROMPT);
        testPermissionGrantAndRevocation(acceptExecutable);
        testDenialAndIdentityChecks(denyExecutable);
        testUnsupportedDeviceMask(acceptExecutable);
        std::cout << "Linux MCP portal session and permission tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
