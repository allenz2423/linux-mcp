#pragma once

#include "input_state.hpp"
#include "wayland_input.hpp"

#include <QDBusConnection>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QDBusServiceWatcher>
#include <QDBusVirtualObject>
#include <QElapsedTimer>
#include <QHash>
#include <QPointer>
#include <QProcess>
#include <QVariantMap>

#include <optional>

namespace hkcf {

class PortalBackend : public QDBusVirtualObject {
    Q_OBJECT

  public:
    explicit PortalBackend(QString permissionPromptExecutable = {}, QObject* parent = nullptr);

    bool handleMessage(const QDBusMessage& message, const QDBusConnection& connection) override;
    QString introspect(const QString& path) const override;

  private:
    struct Session {
        QSharedPointer<int> inputOwner = QSharedPointer<int>::create(0);
        QString owner;
        QString appId;
        QString clientOwner;
        std::uint32_t requestedTypes = 0;
        qint64 rateWindowStartMs = 0;
        int eventsInRateWindow = 0;
        bool devicesSelected = false;
        bool started = false;
        bool permissionPending = false;
    };

    struct PendingStart {
        QPointer<QProcess> prompt;
        QDBusMessage message;
        std::optional<QDBusConnection> connection;
    };

    static constexpr std::uint32_t kKeyboard = 1;
    static constexpr std::uint32_t kPointer = 2;
    static constexpr std::uint32_t kSupportedDevices = kKeyboard | kPointer;

    [[nodiscard]] bool clientIdentity(const QString& sessionPath, const QDBusConnection& connection,
                                      std::uint32_t* pid, QString* executablePath, QString* failureReason) const;
    bool requestPermission(const QDBusMessage& message, const QDBusConnection& connection,
                           const QString& sessionPath, const QString& appId, std::uint32_t devices);
    void finishStart(const QString& sessionPath, QProcess* prompt, int exitCode, QProcess::ExitStatus exitStatus);
    [[nodiscard]] bool isTrustedPortalCaller(const QDBusMessage& message, const QDBusConnection& connection) const;
    [[nodiscard]] bool isSessionOwner(const QDBusMessage& message, const Session& session) const;
    [[nodiscard]] bool isSessionPath(const QString& path) const;
    [[nodiscard]] bool hasDevice(const Session& session, std::uint32_t device) const;
    [[nodiscard]] QDBusMessage response(const QDBusMessage& message, std::uint32_t code, const QVariantMap& results = {}) const;
    [[nodiscard]] QDBusMessage error(const QDBusMessage& message, const QString& name, const QString& text) const;
    [[nodiscard]] QDBusMessage error(const QDBusMessage& message, QDBusError::ErrorType type, const QString& text) const;

    bool handleRemoteDesktop(const QDBusMessage& message, const QDBusConnection& connection);
    bool handleSession(const QDBusMessage& message, const QDBusConnection& connection);
    bool handleProperties(const QDBusMessage& message, const QDBusConnection& connection);
    bool handleIntrospectable(const QDBusMessage& message, const QDBusConnection& connection);
    bool handlePeer(const QDBusMessage& message, const QDBusConnection& connection);

    QVariant propertyValue(const QString& interface, const QString& property) const;
    QVariantMap propertiesFor(const QString& interface) const;
    bool ensureInputReady(const QDBusMessage& message, const QDBusConnection& connection);
    bool sendInputResult(const QDBusMessage& message, const QDBusConnection& connection, bool ok);
    bool checkNotifyRate(const QDBusMessage& message, const QDBusConnection& connection, Session& session);

    void closeSession(const QString& path);
    void watchSessionOwners(const Session& session, const QDBusConnection& connection);

    QDBusServiceWatcher* m_ownerWatcher = nullptr;
    QHash<QString, Session> m_sessions;
    QHash<QString, PendingStart> m_pendingStarts;
    QString m_permissionPromptExecutable;
    WaylandInput m_input;
    InputState m_inputs;
    QElapsedTimer m_rateTimer;
};

} // namespace hkcf
