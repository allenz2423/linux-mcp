#include "portal_backend.hpp"

#include "security_policy.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <optional>
#include <type_traits>
#include <utility>

#include <QDBusArgument>
#include <QDBusConnectionInterface>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusReply>
#include <QDBusVariant>
#include <QDebug>
#include <QFileInfo>
#include <QProcessEnvironment>
#include <unistd.h>
#include <QTimer>

namespace hkcf {

namespace {

constexpr auto kDesktopPath = "/org/freedesktop/portal/desktop";
constexpr auto kRemoteDesktopInterface = "org.freedesktop.impl.portal.RemoteDesktop";
constexpr auto kSessionInterface = "org.freedesktop.impl.portal.Session";
constexpr auto kPropertiesInterface = "org.freedesktop.DBus.Properties";
constexpr auto kIntrospectableInterface = "org.freedesktop.DBus.Introspectable";
constexpr auto kPeerInterface = "org.freedesktop.DBus.Peer";
constexpr auto kNotSupported = "org.freedesktop.DBus.Error.NotSupported";
constexpr auto kPortalFrontendService = "org.freedesktop.portal.Desktop";
constexpr int kPortalRequestResponseDelayMs = 75;

template <typename T>
std::optional<T> typedArg(const QList<QVariant>& args, int index) {
    if (index < 0 || index >= args.size())
        return std::nullopt;
    if constexpr (std::is_same_v<T, QDBusObjectPath>) {
        if (args[index].canConvert<QDBusObjectPath>())
            return args[index].value<QDBusObjectPath>();
    } else if constexpr (std::is_same_v<T, QVariantMap>) {
        if (args[index].canConvert<QVariantMap>())
            return args[index].toMap();
        if (args[index].metaType() == QMetaType::fromType<QDBusArgument>()) {
            QVariantMap map;
            args[index].value<QDBusArgument>() >> map;
            return map;
        }
    } else if constexpr (std::is_same_v<T, QString>) {
        if (args[index].canConvert<QString>())
            return args[index].toString();
    } else if constexpr (std::is_same_v<T, double>) {
        bool ok = false;
        const double value = args[index].toDouble(&ok);
        if (ok)
            return value;
    } else if constexpr (std::is_same_v<T, std::uint32_t>) {
        bool ok = false;
        const uint value = args[index].toUInt(&ok);
        if (ok)
            return value;
    } else if constexpr (std::is_same_v<T, int>) {
        bool ok = false;
        const int value = args[index].toInt(&ok);
        if (ok)
            return value;
    }
    return std::nullopt;
}

QVariant unwrapDbusVariant(const QVariant& value) {
    if (value.metaType() == QMetaType::fromType<QDBusVariant>())
        return value.value<QDBusVariant>().variant();
    return value;
}

std::optional<std::uint32_t> uintOption(const QVariantMap& options, const QString& key, std::uint32_t fallback) {
    if (!options.contains(key))
        return fallback;

    bool ok = false;
    const uint value = unwrapDbusVariant(options.value(key)).toUInt(&ok);
    if (!ok)
        return std::nullopt;
    return value;
}

std::optional<double> boundedDoubleArg(const QList<QVariant>& args, int index, double maxAbs) {
    const auto value = typedArg<double>(args, index);
    if (!value)
        return std::nullopt;
    return hkcf::security::boundedFinite(*value, maxAbs);
}

std::optional<std::uint32_t> processIdForBusService(const QDBusConnection& connection, const QString& serviceName) {
    QDBusConnectionInterface* bus = connection.interface();
    if (!bus || serviceName.isEmpty())
        return std::nullopt;

    const QDBusReply<uint> pid = bus->servicePid(serviceName);
    if (!pid.isValid() || pid.value() == 0)
        return std::nullopt;

    return pid.value();
}

QString safeForPrompt(QString value, qsizetype maxLength = 180) {
    value = value.left(maxLength);
    for (QChar& ch : value) {
        if (ch.unicode() < 0x20 || ch.unicode() == 0x7f)
            ch = QLatin1Char(' ');
    }
    return value.simplified();
}

void sendPortalRequestResponse(const QDBusConnection& connection, const QDBusMessage& response) {
    QTimer::singleShot(kPortalRequestResponseDelayMs, [connection, response]() {
        connection.send(response);
    });
}

} // namespace

PortalBackend::PortalBackend(QString permissionPromptExecutable, QObject* parent)
    : QDBusVirtualObject(parent)
    , m_permissionPromptExecutable(std::move(permissionPromptExecutable))
    , m_inputs(m_input) {
#ifdef HKCF_ZENITY_EXECUTABLE
    if (m_permissionPromptExecutable.isEmpty())
        m_permissionPromptExecutable = QStringLiteral(HKCF_ZENITY_EXECUTABLE);
#endif
    m_rateTimer.start();
}

bool PortalBackend::handleMessage(const QDBusMessage& message, const QDBusConnection& connection) {
    const QString interface = message.interface();

    if (interface == QString::fromLatin1(kRemoteDesktopInterface))
        return handleRemoteDesktop(message, connection);
    if (interface == QString::fromLatin1(kSessionInterface))
        return handleSession(message, connection);
    if (interface == QString::fromLatin1(kPropertiesInterface))
        return handleProperties(message, connection);
    if (interface == QString::fromLatin1(kIntrospectableInterface))
        return handleIntrospectable(message, connection);
    if (interface == QString::fromLatin1(kPeerInterface))
        return handlePeer(message, connection);

    connection.send(error(message, QDBusError::UnknownInterface, QStringLiteral("unknown interface %1").arg(interface)));
    return true;
}

QString PortalBackend::introspect(const QString& path) const {
    if (path == QString::fromLatin1(kDesktopPath)) {
        return QStringLiteral(R"XML(
<node>
  <interface name="org.freedesktop.impl.portal.RemoteDesktop">
    <method name="CreateSession">
      <arg type="o" name="handle" direction="in"/>
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="s" name="app_id" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="u" name="response" direction="out"/>
      <arg type="a{sv}" name="results" direction="out"/>
    </method>
    <method name="SelectDevices">
      <arg type="o" name="handle" direction="in"/>
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="s" name="app_id" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="u" name="response" direction="out"/>
      <arg type="a{sv}" name="results" direction="out"/>
    </method>
    <method name="Start">
      <arg type="o" name="handle" direction="in"/>
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="s" name="app_id" direction="in"/>
      <arg type="s" name="parent_window" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="u" name="response" direction="out"/>
      <arg type="a{sv}" name="results" direction="out"/>
    </method>
    <method name="NotifyPointerMotion">
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="d" name="dx" direction="in"/>
      <arg type="d" name="dy" direction="in"/>
    </method>
    <method name="NotifyPointerMotionAbsolute">
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="u" name="stream" direction="in"/>
      <arg type="d" name="x" direction="in"/>
      <arg type="d" name="y" direction="in"/>
    </method>
    <method name="NotifyPointerButton">
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="i" name="button" direction="in"/>
      <arg type="u" name="state" direction="in"/>
    </method>
    <method name="NotifyPointerAxis">
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="d" name="dx" direction="in"/>
      <arg type="d" name="dy" direction="in"/>
    </method>
    <method name="NotifyPointerAxisDiscrete">
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="u" name="axis" direction="in"/>
      <arg type="i" name="steps" direction="in"/>
    </method>
    <method name="NotifyKeyboardKeycode">
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="i" name="keycode" direction="in"/>
      <arg type="u" name="state" direction="in"/>
    </method>
    <method name="NotifyKeyboardKeysym">
      <arg type="o" name="session_handle" direction="in"/>
      <arg type="a{sv}" name="options" direction="in"/>
      <arg type="i" name="keysym" direction="in"/>
      <arg type="u" name="state" direction="in"/>
    </method>
    <property name="AvailableDeviceTypes" type="u" access="read"/>
    <property name="version" type="u" access="read"/>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get">
      <arg type="s" name="interface_name" direction="in"/>
      <arg type="s" name="property_name" direction="in"/>
      <arg type="v" name="value" direction="out"/>
    </method>
    <method name="GetAll">
      <arg type="s" name="interface_name" direction="in"/>
      <arg type="a{sv}" name="properties" direction="out"/>
    </method>
  </interface>
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg type="s" name="xml_data" direction="out"/>
    </method>
  </interface>
</node>
)XML");
    }

    if (isSessionPath(path)) {
        return QStringLiteral(R"XML(
<node>
  <interface name="org.freedesktop.impl.portal.Session">
    <method name="Close"/>
    <signal name="Closed"/>
    <property name="version" type="u" access="read"/>
  </interface>
  <interface name="org.freedesktop.DBus.Properties">
    <method name="Get">
      <arg type="s" name="interface_name" direction="in"/>
      <arg type="s" name="property_name" direction="in"/>
      <arg type="v" name="value" direction="out"/>
    </method>
    <method name="GetAll">
      <arg type="s" name="interface_name" direction="in"/>
      <arg type="a{sv}" name="properties" direction="out"/>
    </method>
  </interface>
</node>
)XML");
    }

    return QStringLiteral("<node/>");
}

bool PortalBackend::handleRemoteDesktop(const QDBusMessage& message, const QDBusConnection& connection) {
    if (!isTrustedPortalCaller(message, connection)) {
        connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("RemoteDesktop backend accepts calls only from xdg-desktop-portal")));
        return true;
    }

    const auto args = message.arguments();
    const QString member = message.member();

    if (member == QStringLiteral("CreateSession")) {
        const auto requestHandle = typedArg<QDBusObjectPath>(args, 0);
        const auto sessionHandle = typedArg<QDBusObjectPath>(args, 1);
        const auto appId = typedArg<QString>(args, 2);
        const auto options = typedArg<QVariantMap>(args, 3);
        if (args.size() != 4 || !requestHandle || !sessionHandle || !appId || !options) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid CreateSession arguments")));
            return true;
        }

        const QString path = sessionHandle->path();
        if (!isSessionPath(path)) {
            connection.send(error(message, QDBusError::InvalidObjectPath, QStringLiteral("invalid session handle path")));
            return true;
        }
        if (!security::isPlausibleAppId(*appId)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid app id")));
            return true;
        }
        if (m_sessions.contains(path)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("session handle already exists")));
            return true;
        }
        if (m_sessions.size() >= security::kMaxSessions) {
            connection.send(error(message, QDBusError::LimitsExceeded, QStringLiteral("too many active sessions")));
            return true;
        }

        Session session;
        session.owner = message.service();
        session.appId = security::normalizedAppId(*appId);
        session.clientOwner = security::senderBusNameFromSessionPath(path).value_or(QString());
        watchSessionOwners(session, connection);
        m_sessions.insert(path, session);

        QVariantMap results;
        results.insert(QStringLiteral("session"), path);
        results.insert(QStringLiteral("session_id"), path);
        sendPortalRequestResponse(connection, response(message, 0, results));
        return true;
    }

    if (member == QStringLiteral("SelectDevices")) {
        const auto sessionHandle = typedArg<QDBusObjectPath>(args, 1);
        const auto options = typedArg<QVariantMap>(args, 3);
        if (args.size() != 4 || !typedArg<QDBusObjectPath>(args, 0) || !sessionHandle || !typedArg<QString>(args, 2) || !options) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid SelectDevices arguments")));
            return true;
        }

        auto session = m_sessions.find(sessionHandle->path());
        if (session == m_sessions.end()) {
            sendPortalRequestResponse(connection, response(message, 2));
            return true;
        }
        if (!isSessionOwner(message, *session)) {
            connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("session belongs to another D-Bus caller")));
            return true;
        }

        if (session->started) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("devices cannot be selected after Start")));
            return true;
        }

        const auto requestedTypes = uintOption(*options, QStringLiteral("types"), kSupportedDevices);
        if (!requestedTypes) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid device type mask")));
            return true;
        }

        if ((*requestedTypes & ~kSupportedDevices) != 0) {
            sendPortalRequestResponse(connection, response(message, 2, {{QStringLiteral("error"), QStringLiteral("unsupported device type requested")}}));
            return true;
        }
        session->requestedTypes = *requestedTypes;
        if (!session->requestedTypes) {
            sendPortalRequestResponse(connection, response(message, 2, {{QStringLiteral("error"), QStringLiteral("no supported devices selected")}}));
            return true;
        }
        session->devicesSelected = true;
        sendPortalRequestResponse(connection, response(message, 0));
        return true;
    }

    if (member == QStringLiteral("Start")) {
        const auto sessionHandle = typedArg<QDBusObjectPath>(args, 1);
        const auto appId = typedArg<QString>(args, 2);
        if (args.size() != 5 || !typedArg<QDBusObjectPath>(args, 0) || !sessionHandle || !appId || !typedArg<QString>(args, 3) ||
            !typedArg<QVariantMap>(args, 4)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid Start arguments")));
            return true;
        }

        auto session = m_sessions.find(sessionHandle->path());
        if (session == m_sessions.end()) {
            sendPortalRequestResponse(connection, response(message, 2));
            return true;
        }
        if (!isSessionOwner(message, *session)) {
            connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("session belongs to another D-Bus caller")));
            return true;
        }

        if (session->started || session->permissionPending) {
            sendPortalRequestResponse(connection, response(message, 2, {{QStringLiteral("error"), QStringLiteral("session has already been started or is awaiting permission")}}));
            return true;
        }
        if (!session->devicesSelected) {
            sendPortalRequestResponse(connection, response(message, 2, {{QStringLiteral("error"), QStringLiteral("devices were not selected")}}));
            return true;
        }
        if (!security::isPlausibleAppId(*appId)) {
            sendPortalRequestResponse(connection, response(message, 2, {{QStringLiteral("error"), QStringLiteral("invalid app id")}}));
            return true;
        }
        const QString requestedAppId = security::normalizedAppId(*appId);
        if (!requestedAppId.isEmpty() && !session->appId.isEmpty() && requestedAppId != session->appId) {
            connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("app id does not match the created session")));
            return true;
        }
        if (!requestedAppId.isEmpty())
            session->appId = requestedAppId;
        if (!ensureInputReady(message, connection))
            return true;
        requestPermission(message, connection, sessionHandle->path(), session->appId, session->requestedTypes);
        return true;
    }

    const auto sessionHandle = typedArg<QDBusObjectPath>(args, 0);
    if (!sessionHandle) {
        connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("missing session handle")));
        return true;
    }
    auto session = m_sessions.find(sessionHandle->path());
    if (session == m_sessions.end() || !session->started) {
        connection.send(message.createReply());
        return true;
    }
    if (!isSessionOwner(message, *session)) {
        connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("session belongs to another D-Bus caller")));
        return true;
    }
    if (member == QStringLiteral("NotifyPointerMotion")) {
        if (args.size() != 4 || !typedArg<QVariantMap>(args, 1) || !hasDevice(*session, kPointer)) {
            connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("pointer device was not selected")));
            return true;
        }
        const auto dx = boundedDoubleArg(args, 2, security::kMaxPointerDelta);
        const auto dy = boundedDoubleArg(args, 3, security::kMaxPointerDelta);
        if (!dx || !dy) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid pointer motion delta")));
            return true;
        }
        if (!checkNotifyRate(message, connection, *session))
            return true;
        return sendInputResult(message, connection, m_input.pointerMotion(*dx, *dy));
    }

    if (member == QStringLiteral("NotifyPointerMotionAbsolute")) {
        if (args.size() != 5 || !typedArg<QVariantMap>(args, 1) || !typedArg<std::uint32_t>(args, 2) || !hasDevice(*session, kPointer)) {
            connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("pointer device was not selected")));
            return true;
        }
        const auto x = boundedDoubleArg(args, 3, security::kMaxAbsoluteCoordinate);
        const auto y = boundedDoubleArg(args, 4, security::kMaxAbsoluteCoordinate);
        if (!x || !y) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid absolute pointer coordinates")));
            return true;
        }
        if (!checkNotifyRate(message, connection, *session))
            return true;
        return sendInputResult(message, connection, m_input.pointerMotionAbsolute(*x, *y));
    }

    if (member == QStringLiteral("NotifyPointerButton")) {
        const auto button = typedArg<int>(args, 2);
        const auto state = typedArg<std::uint32_t>(args, 3);
        if (args.size() != 4 || !typedArg<QVariantMap>(args, 1) || !button || !state || *button < 0 || !hasDevice(*session, kPointer)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid pointer button arguments")));
            return true;
        }
        const auto buttonCode = static_cast<std::uint32_t>(*button);
        if (!security::isAllowedPointerButton(buttonCode) || !security::isValidState(*state)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid pointer button or state")));
            return true;
        }
        // Releases are validated above but never consume the motion/press budget.
        if (*state != 0 && !checkNotifyRate(message, connection, *session))
            return true;
        return sendInputResult(message, connection, m_inputs.pointerButton(session->inputOwner.data(), buttonCode, security::stateToPressed(*state)));
    }

    if (member == QStringLiteral("NotifyPointerAxis")) {
        if (args.size() != 4 || !typedArg<QVariantMap>(args, 1) || !hasDevice(*session, kPointer)) {
            connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("pointer device was not selected")));
            return true;
        }
        const auto dx = boundedDoubleArg(args, 2, security::kMaxAxisDelta);
        const auto dy = boundedDoubleArg(args, 3, security::kMaxAxisDelta);
        if (!dx || !dy) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid pointer axis delta")));
            return true;
        }
        if (!checkNotifyRate(message, connection, *session))
            return true;
        return sendInputResult(message, connection, m_input.pointerAxis(*dx, *dy));
    }

    if (member == QStringLiteral("NotifyPointerAxisDiscrete")) {
        const auto axis = typedArg<std::uint32_t>(args, 2);
        const auto steps = typedArg<int>(args, 3);
        if (args.size() != 4 || !typedArg<QVariantMap>(args, 1) || !axis || !steps || !hasDevice(*session, kPointer)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid discrete axis arguments")));
            return true;
        }
        if (!security::isAllowedDiscreteAxis(*axis)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid discrete axis")));
            return true;
        }
        if (!checkNotifyRate(message, connection, *session))
            return true;
        return sendInputResult(message, connection, m_input.pointerAxisDiscrete(*axis, *steps));
    }

    if (member == QStringLiteral("NotifyKeyboardKeycode")) {
        const auto keycode = typedArg<int>(args, 2);
        const auto state = typedArg<std::uint32_t>(args, 3);
        if (args.size() != 4 || !typedArg<QVariantMap>(args, 1) || !keycode || !state || *keycode < 0 || !hasDevice(*session, kKeyboard)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid keyboard keycode arguments")));
            return true;
        }
        const auto keycodeValue = static_cast<std::uint32_t>(*keycode);
        if (!security::isAllowedKeyboardKeycode(keycodeValue) || !security::isValidState(*state)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid keyboard keycode or state")));
            return true;
        }
        // Releases are validated above but never consume the motion/press budget.
        if (*state != 0 && !checkNotifyRate(message, connection, *session))
            return true;
        return sendInputResult(message, connection, m_inputs.keyboardKeycode(session->inputOwner.data(), keycodeValue, security::stateToPressed(*state)));
    }

    if (member == QStringLiteral("NotifyKeyboardKeysym")) {
        const auto keysym = typedArg<int>(args, 2);
        const auto state = typedArg<std::uint32_t>(args, 3);
        if (args.size() != 4 || !typedArg<QVariantMap>(args, 1) || !keysym || !state || *keysym < 0 || !hasDevice(*session, kKeyboard)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid keyboard keysym arguments")));
            return true;
        }
        const auto keysymValue = static_cast<std::uint32_t>(*keysym);
        if (!security::isAllowedKeysym(keysymValue) || !security::isValidState(*state)) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("invalid keyboard keysym or state")));
            return true;
        }
        // Releases are validated above but never consume the motion/press budget.
        if (*state != 0 && !checkNotifyRate(message, connection, *session))
            return true;
        return sendInputResult(message, connection, m_inputs.keyboardKeysym(session->inputOwner.data(), keysymValue, security::stateToPressed(*state)));
    }

    connection.send(error(message, QDBusError::UnknownMethod, QStringLiteral("unknown RemoteDesktop method %1").arg(member)));
    return true;
}

bool PortalBackend::handleSession(const QDBusMessage& message, const QDBusConnection& connection) {
    if (!isTrustedPortalCaller(message, connection)) {
        connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("Session backend accepts calls only from xdg-desktop-portal")));
        return true;
    }

    if (message.member() != QStringLiteral("Close")) {
        connection.send(error(message, QDBusError::UnknownMethod, QStringLiteral("unknown Session method")));
        return true;
    }

    auto session = m_sessions.find(message.path());
    if (session == m_sessions.end()) {
        connection.send(message.createReply());
        return true;
    }
    if (!isSessionOwner(message, *session)) {
        connection.send(error(message, QDBusError::AccessDenied, QStringLiteral("session belongs to another D-Bus caller")));
        return true;
    }

    closeSession(message.path());
    connection.send(message.createReply());
    connection.send(QDBusMessage::createSignal(message.path(), QString::fromLatin1(kSessionInterface), QStringLiteral("Closed")));
    return true;
}

void PortalBackend::closeSession(const QString& path) {
    auto pending = m_pendingStarts.find(path);
    if (pending != m_pendingStarts.end()) {
        const PendingStart start = pending.value();
        m_pendingStarts.erase(pending);
        if (auto* prompt = start.prompt.data()) {
            prompt->disconnect(this);
            if (prompt->state() != QProcess::NotRunning)
                prompt->kill();
            prompt->deleteLater();
        }
        if (start.connection)
            sendPortalRequestResponse(*start.connection,
                                  response(start.message, 1, {{QStringLiteral("error"), QStringLiteral("session closed before permission was granted")}}));
    }
    const auto session = m_sessions.take(path);
    m_inputs.releaseOwner(session.inputOwner.data());
    if (!m_ownerWatcher)
        return;
    for (const auto& owner : {session.owner, session.clientOwner}) {
        bool inUse = false;
        for (const auto& active : std::as_const(m_sessions)) {
            if (active.owner == owner || active.clientOwner == owner) {
                inUse = true;
                break;
            }
        }
        if (!inUse && !owner.isEmpty())
            m_ownerWatcher->removeWatchedService(owner);
    }
}

void PortalBackend::watchSessionOwners(const Session& session, const QDBusConnection& connection) {
    if (!m_ownerWatcher) {
        m_ownerWatcher = new QDBusServiceWatcher(QString::fromLatin1(kPortalFrontendService), connection,
                                               QDBusServiceWatcher::WatchForOwnerChange, this);
        connect(m_ownerWatcher, &QDBusServiceWatcher::serviceOwnerChanged, this,
                [this](const QString& name, const QString& oldOwner, const QString& newOwner) {
            if (!newOwner.isEmpty() && name != QString::fromLatin1(kPortalFrontendService))
                return;
            const auto paths = m_sessions.keys();
            for (const auto& path : paths) {
                const auto& session = m_sessions[path];
                if (session.owner == oldOwner || session.clientOwner == oldOwner)
                    closeSession(path);
            }
        });
    }
    m_ownerWatcher->addWatchedService(session.owner);
    if (!session.clientOwner.isEmpty())
        m_ownerWatcher->addWatchedService(session.clientOwner);
}

bool PortalBackend::clientIdentity(const QString& sessionPath, const QDBusConnection& connection,
                                   std::uint32_t* pid, QString* executablePath, QString* failureReason) const {
    const auto senderBusName = security::senderBusNameFromSessionPath(sessionPath);
    QDBusConnectionInterface* bus = connection.interface();
    if (!senderBusName) {
        if (failureReason)
            *failureReason = QStringLiteral("portal session path did not contain the caller's unique bus name");
        return false;
    }
    if (!bus || !pid || !executablePath || !failureReason) {
        if (failureReason)
            *failureReason = QStringLiteral("session bus identity lookup was unavailable");
        return false;
    }

    const QDBusReply<uint> uidReply = bus->serviceUid(*senderBusName);
    const auto senderPid = processIdForBusService(connection, *senderBusName);
    if (!uidReply.isValid()) {
        *failureReason = QStringLiteral("session bus could not confirm the requesting user's identity");
        return false;
    }
    if (uidReply.value() != static_cast<uint>(::getuid())) {
        *failureReason = QStringLiteral("requesting application runs under a different user");
        return false;
    }
    if (!senderPid) {
        *failureReason = QStringLiteral("session bus could not confirm the requesting process");
        return false;
    }

    char buffer[4096];
    const QByteArray procExePath = QStringLiteral("/proc/%1/exe").arg(*senderPid).toLocal8Bit();
    const ssize_t length = ::readlink(procExePath.constData(), buffer, sizeof(buffer) - 1);
    if (length <= 0) {
        const int readlinkError = errno;
        qWarning() << "could not read the verified executable link for D-Bus requester PID"
                   << *senderPid << "errno" << readlinkError << std::strerror(readlinkError);
        if (readlinkError == EACCES) {
            // Some session sandboxes prevent a same-user portal helper from
            // reading another process's /proc/<pid>/exe link. The bus has
            // already verified the peer's UID and PID. Keep the explicit
            // consent gate, and make the missing executable path visible in
            // that prompt instead of silently substituting an untrusted argv.
            *pid = *senderPid;
            executablePath->clear();
            return true;
        }
        *failureReason = QStringLiteral("requesting process executable could not be verified");
        return false;
    }
    buffer[length] = '\0';
    const QString resolvedPath = QString::fromLocal8Bit(buffer, static_cast<int>(length));
    if (resolvedPath.isEmpty() || !QFileInfo(resolvedPath).isAbsolute()) {
        *failureReason = QStringLiteral("requesting process executable path was invalid");
        return false;
    }

    *pid = *senderPid;
    *executablePath = resolvedPath;
    return true;
}

bool PortalBackend::requestPermission(const QDBusMessage& message, const QDBusConnection& connection,
                                     const QString& sessionPath, const QString& appId, std::uint32_t devices) {
    std::uint32_t pid = 0;
    QString executablePath;
    QString identityFailure;
    if (!clientIdentity(sessionPath, connection, &pid, &executablePath, &identityFailure)) {
        qWarning() << "could not verify RemoteDesktop requester:" << identityFailure;
        sendPortalRequestResponse(connection, response(message, 2, {{QStringLiteral("error"), identityFailure}}));
        return false;
    }

    const QFileInfo promptInfo(m_permissionPromptExecutable);
    if (!promptInfo.isAbsolute() || !promptInfo.isExecutable()) {
        sendPortalRequestResponse(connection, response(message, 2, {{QStringLiteral("error"), QStringLiteral("desktop permission prompt is unavailable")}}));
        return false;
    }

    QStringList requestedDevices;
    if ((devices & kKeyboard) != 0)
        requestedDevices.append(QStringLiteral("keyboard"));
    if ((devices & kPointer) != 0)
        requestedDevices.append(QStringLiteral("pointer"));
    const QString deviceLabel = requestedDevices.join(QStringLiteral(" and "));
    const QString appLabel = safeForPrompt(appId, security::kMaxAppIdLength);
    const QString programLabel = executablePath.isEmpty()
        ? QStringLiteral("(path unavailable to portal helper; D-Bus user and process ID verified)")
        : safeForPrompt(executablePath);
    const QString text = QStringLiteral(
        "Application ID: %1\nProgram: %2\nD-Bus-verified process ID: %3\nRequested access: %4\n\n"
        "Allow this application to control your desktop for this session?")
                             .arg(appLabel.isEmpty() ? QStringLiteral("(application ID unavailable)") : appLabel,
                                  programLabel, QString::number(pid), deviceLabel);

    auto* prompt = new QProcess(this);
    QProcessEnvironment promptEnvironment;
    const QProcessEnvironment sourceEnvironment = QProcessEnvironment::systemEnvironment();
    const QStringList environmentAllowlist = {
        QStringLiteral("WAYLAND_DISPLAY"), QStringLiteral("XDG_RUNTIME_DIR"), QStringLiteral("DISPLAY"),
        QStringLiteral("XAUTHORITY"), QStringLiteral("XDG_CURRENT_DESKTOP"), QStringLiteral("XDG_SESSION_TYPE"),
        QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), QStringLiteral("LANG"), QStringLiteral("LC_ALL"),
        QStringLiteral("HOME"), QStringLiteral("USER"), QStringLiteral("LOGNAME")
    };
    for (const QString& key : environmentAllowlist) {
        if (sourceEnvironment.contains(key))
            promptEnvironment.insert(key, sourceEnvironment.value(key));
    }
    promptEnvironment.insert(QStringLiteral("PATH"), QStringLiteral("/usr/bin:/bin"));
    promptEnvironment.insert(QStringLiteral("GDK_BACKEND"), QStringLiteral("wayland"));
    prompt->setProcessEnvironment(promptEnvironment);
    prompt->setProgram(m_permissionPromptExecutable);
    prompt->setArguments({
        QStringLiteral("--question"), QStringLiteral("--modal"), QStringLiteral("--no-markup"),
        QStringLiteral("--no-wrap"), QStringLiteral("--default-cancel"),
        QStringLiteral("--title=Desktop input permission"), QStringLiteral("--width=520"),
        QStringLiteral("--ok-label=Allow"), QStringLiteral("--cancel-label=Deny"),
        QStringLiteral("--timeout=90"), QStringLiteral("--text=%1").arg(text)
    });
    prompt->setStandardOutputFile(QStringLiteral("/dev/null"));
    prompt->setStandardErrorFile(QStringLiteral("/dev/null"));

    auto session = m_sessions.find(sessionPath);
    if (session == m_sessions.end()) {
        prompt->deleteLater();
        sendPortalRequestResponse(connection, response(message, 2));
        return false;
    }
    session->permissionPending = true;
    m_pendingStarts.insert(sessionPath, PendingStart{prompt, message, connection});
    connect(prompt, &QProcess::finished, this,
            [this, sessionPath, prompt](int exitCode, QProcess::ExitStatus exitStatus) {
                finishStart(sessionPath, prompt, exitCode, exitStatus);
            });
    connect(prompt, &QProcess::errorOccurred, this,
            [this, sessionPath, prompt](QProcess::ProcessError error) {
                if (error == QProcess::FailedToStart)
                    finishStart(sessionPath, prompt, 127, QProcess::CrashExit);
            });

    auto* deadline = new QTimer(prompt);
    deadline->setSingleShot(true);
    connect(deadline, &QTimer::timeout, this, [this, sessionPath, prompt]() {
        const auto pending = m_pendingStarts.constFind(sessionPath);
        if (pending == m_pendingStarts.cend() || pending->prompt.data() != prompt)
            return;
        prompt->kill();
        finishStart(sessionPath, prompt, 124, QProcess::CrashExit);
    });
    deadline->start(95000);
    prompt->start();
    return true;
}

void PortalBackend::finishStart(const QString& sessionPath, QProcess* prompt, int exitCode, QProcess::ExitStatus exitStatus) {
    auto pending = m_pendingStarts.find(sessionPath);
    if (pending == m_pendingStarts.end() || pending->prompt != prompt)
        return;
    const PendingStart start = pending.value();
    m_pendingStarts.erase(pending);

    auto session = m_sessions.find(sessionPath);
    const bool sessionUsable = session != m_sessions.end() && session->permissionPending && !session->started;
    if (session != m_sessions.end())
        session->permissionPending = false;

    const bool accepted = sessionUsable && exitCode == 0 && exitStatus == QProcess::NormalExit;
    if (accepted) {
        session->started = true;
        QVariantMap results;
        results.insert(QStringLiteral("devices"), session->requestedTypes & kSupportedDevices);
        results.insert(QStringLiteral("clipboard_enabled"), false);
        if (start.connection)
            sendPortalRequestResponse(*start.connection, response(start.message, 0, results));
    } else {
        const uint responseCode = exitCode == 1 && exitStatus == QProcess::NormalExit ? 1u : 2u;
        if (start.connection)
            sendPortalRequestResponse(*start.connection, response(start.message, responseCode,
                                      {{QStringLiteral("error"), responseCode == 1u
                                            ? QStringLiteral("desktop input permission was denied")
                                            : QStringLiteral("desktop input permission could not be established")}}));
    }

    if (prompt) {
        if (prompt->state() != QProcess::NotRunning)
            prompt->kill();
        prompt->deleteLater();
    }
}

bool PortalBackend::handleProperties(const QDBusMessage& message, const QDBusConnection& connection) {
    const auto args = message.arguments();
    if (message.member() == QStringLiteral("Get")) {
        const auto interface = typedArg<QString>(args, 0).value_or(QString());
        const auto property = typedArg<QString>(args, 1).value_or(QString());
        const QVariant value = propertyValue(interface, property);
        if (!value.isValid()) {
            connection.send(error(message, QDBusError::InvalidArgs, QStringLiteral("unknown property")));
            return true;
        }
        connection.send(message.createReply(QVariant::fromValue(QDBusVariant(value))));
        return true;
    }

    if (message.member() == QStringLiteral("GetAll")) {
        const auto interface = typedArg<QString>(args, 0).value_or(QString());
        connection.send(message.createReply(propertiesFor(interface)));
        return true;
    }

    connection.send(error(message, QDBusError::UnknownMethod, QStringLiteral("unknown Properties method")));
    return true;
}

bool PortalBackend::handleIntrospectable(const QDBusMessage& message, const QDBusConnection& connection) {
    if (message.member() != QStringLiteral("Introspect")) {
        connection.send(error(message, QDBusError::UnknownMethod, QStringLiteral("unknown Introspectable method")));
        return true;
    }
    connection.send(message.createReply(introspect(message.path())));
    return true;
}

bool PortalBackend::handlePeer(const QDBusMessage& message, const QDBusConnection& connection) {
    if (message.member() == QStringLiteral("Ping")) {
        connection.send(message.createReply());
        return true;
    }
    if (message.member() == QStringLiteral("GetMachineId")) {
        connection.send(message.createReply(QString()));
        return true;
    }
    connection.send(error(message, QDBusError::UnknownMethod, QStringLiteral("unknown Peer method")));
    return true;
}

QVariant PortalBackend::propertyValue(const QString& interface, const QString& property) const {
    if (interface == QString::fromLatin1(kRemoteDesktopInterface)) {
        if (property == QStringLiteral("AvailableDeviceTypes"))
            return QVariant::fromValue(kSupportedDevices);
        if (property == QStringLiteral("version"))
            return QVariant::fromValue(2u);
    }
    if (interface == QString::fromLatin1(kSessionInterface) && property == QStringLiteral("version"))
        return QVariant::fromValue(1u);
    return {};
}

QVariantMap PortalBackend::propertiesFor(const QString& interface) const {
    QVariantMap map;
    if (interface == QString::fromLatin1(kRemoteDesktopInterface)) {
        map.insert(QStringLiteral("AvailableDeviceTypes"), kSupportedDevices);
        map.insert(QStringLiteral("version"), 2u);
    } else if (interface == QString::fromLatin1(kSessionInterface)) {
        map.insert(QStringLiteral("version"), 1u);
    }
    return map;
}

bool PortalBackend::ensureInputReady(const QDBusMessage& message, const QDBusConnection& connection) {
    if (m_input.ensureReady())
        return true;
    qWarning() << "failed to initialize Wayland input:" << m_input.lastError();
    sendPortalRequestResponse(connection, response(message, 2, {{QStringLiteral("error"), QStringLiteral("input backend unavailable")}}));
    return false;
}

bool PortalBackend::sendInputResult(const QDBusMessage& message, const QDBusConnection& connection, bool ok) {
    if (ok) {
        connection.send(message.createReply());
        return true;
    }

    qWarning() << "input injection failed:" << m_input.lastError();
    connection.send(error(message, QDBusError::Failed, QStringLiteral("input injection failed")));
    return true;
}

bool PortalBackend::checkNotifyRate(const QDBusMessage& message, const QDBusConnection& connection, Session& session) {
    const qint64 now = m_rateTimer.elapsed();
    if (now - session.rateWindowStartMs >= security::kNotifyRateWindowMs) {
        session.rateWindowStartMs = now;
        session.eventsInRateWindow = 0;
    }

    if (session.eventsInRateWindow < security::kMaxNotifyEventsPerWindow) {
        ++session.eventsInRateWindow;
        return true;
    }

    connection.send(error(message, QDBusError::LimitsExceeded, QStringLiteral("too many input events")));
    return false;
}

bool PortalBackend::isTrustedPortalCaller(const QDBusMessage& message, const QDBusConnection& connection) const {
    const QString sender = message.service();
    if (sender.isEmpty())
        return false;

    QDBusConnectionInterface* bus = connection.interface();
    if (!bus)
        return false;

    const QDBusReply<QString> owner = bus->serviceOwner(QString::fromLatin1(kPortalFrontendService));
    return owner.isValid() && !owner.value().isEmpty() && owner.value() == sender;
}

bool PortalBackend::isSessionOwner(const QDBusMessage& message, const Session& session) const {
    return !session.owner.isEmpty() && session.owner == message.service();
}

bool PortalBackend::isSessionPath(const QString& path) const {
    return security::isValidSessionPath(path);
}

bool PortalBackend::hasDevice(const Session& session, std::uint32_t device) const {
    return session.devicesSelected && (session.requestedTypes & device) == device;
}

QDBusMessage PortalBackend::response(const QDBusMessage& message, std::uint32_t code, const QVariantMap& results) const {
    return message.createReply(QList<QVariant>{QVariant::fromValue(code), results});
}

QDBusMessage PortalBackend::error(const QDBusMessage& message, const QString& name, const QString& text) const {
    return message.createErrorReply(name, text);
}

QDBusMessage PortalBackend::error(const QDBusMessage& message, QDBusError::ErrorType type, const QString& text) const {
    return message.createErrorReply(type, text);
}

} // namespace hkcf
