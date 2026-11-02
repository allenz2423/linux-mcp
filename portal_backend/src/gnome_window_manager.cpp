#include <QDBusConnection>
#include <QDBusError>
#include <QDBusInterface>
#include <QDBusMessage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QStringList>

#include <cstdio>

namespace {

constexpr int kMaxOutputBytes = 2 * 1024 * 1024;
const QString kBusName = QStringLiteral("org.linuxmcp.GnomeWindowControl");
const QString kObjectPath = QStringLiteral("/org/linuxmcp/GnomeWindowControl");
const QString kInterface = QStringLiteral("org.linuxmcp.GnomeWindowControl");

QJsonObject failure(const QString &message) {
    return {{"success", false}, {"message", message.left(300)}};
}

QJsonObject parseReply(const QString &value) {
    if (value.toUtf8().size() > kMaxOutputBytes)
        return failure("The GNOME extension response exceeded the two-megabyte limit.");
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(value.toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        return failure("The GNOME extension returned invalid JSON.");
    return document.object();
}

QJsonObject getState(QDBusInterface &interface) {
    const QDBusMessage reply = interface.call(QDBus::Block, QStringLiteral("GetState"));
    if (reply.type() == QDBusMessage::ErrorMessage)
        return failure(QStringLiteral("GNOME Shell extension is unavailable: %1").arg(reply.errorMessage()));
    if (reply.arguments().size() != 1 || !reply.arguments().front().canConvert<QString>())
        return failure("GNOME Shell extension returned an invalid D-Bus response.");
    return parseReply(reply.arguments().front().toString());
}

QJsonObject runAction(QDBusInterface &interface, const QString &operation,
                      const QString &windowId, const QString &workspaceId) {
    const QDBusMessage reply = interface.callWithArgumentList(
        QDBus::Block, QStringLiteral("PerformAction"),
        {operation, windowId, workspaceId});
    if (reply.type() == QDBusMessage::ErrorMessage)
        return failure(QStringLiteral("GNOME Shell action failed: %1").arg(reply.errorMessage()));
    if (reply.arguments().size() != 1 || !reply.arguments().front().canConvert<QString>())
        return failure("GNOME Shell extension returned an invalid action response.");
    return parseReply(reply.arguments().front().toString());
}

QJsonObject resultFor(const QString &command, const QStringList &arguments) {
    QDBusConnection bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()) return failure("The user's session D-Bus is unavailable.");
    QDBusInterface interface(kBusName, kObjectPath, kInterface, bus);
    interface.setTimeout(2500);
    if (!interface.isValid()) return failure("The optional GNOME Shell window-control extension is not enabled.");

    const QJsonObject state = getState(interface);
    if (!state.value("success").toBool()) return state;
    if (command == "probe") {
        return {{"success", true}, {"compositor", "gnome"},
                {"capabilities", QJsonArray{"window_list", "window_detail", "focus", "close",
                                             "minimize", "maximize", "workspace_list", "output_list",
                                             "workspace_switch", "window_move"}}};
    }
    if (command == "list") return state;
    if (command == "workspaces") {
        return {{"success", true}, {"compositor", "gnome"},
                {"workspaces", state.value("workspaces")},
                {"active_workspace", state.value("active_workspace")},
                {"total_workspaces", state.value("total_workspaces")}};
    }
    if (command == "outputs") {
        return {{"success", true}, {"compositor", "gnome"},
                {"outputs", state.value("outputs")},
                {"total_outputs", state.value("total_outputs")}};
    }

    QString operation;
    QString windowId;
    QString workspaceId;
    if (command == "focus" || command == "close" || command == "minimize" || command == "maximize") {
        if (arguments.size() != 1) return failure("An exact observed GNOME window ID is required.");
        operation = command;
        windowId = arguments.front();
    } else if (command == "switch-workspace") {
        if (arguments.size() != 1) return failure("An exact observed GNOME workspace ID is required.");
        operation = command;
        workspaceId = arguments.front();
    } else if (command == "move-window") {
        if (arguments.size() != 2) return failure("An exact GNOME window ID and workspace ID are required.");
        operation = command;
        windowId = arguments.at(0);
        workspaceId = arguments.at(1);
    } else {
        return failure("Unknown GNOME window-manager operation.");
    }
    QJsonObject response = runAction(interface, operation, windowId, workspaceId);
    response.insert("compositor", "gnome");
    return response;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2 || argc > 4) {
        std::fprintf(stderr, "usage: linux-mcp-gnome-wm probe|list|workspaces|outputs|focus|close|minimize|maximize|switch-workspace|move-window [id] [workspace-id]\n");
        return 2;
    }
    QStringList arguments;
    for (int index = 2; index < argc; ++index) arguments.append(QString::fromLocal8Bit(argv[index]));
    const QJsonObject response = resultFor(QString::fromLocal8Bit(argv[1]), arguments);
    QByteArray bytes = QJsonDocument(response).toJson(QJsonDocument::Compact);
    std::fwrite(bytes.constData(), 1, static_cast<size_t>(bytes.size()), stdout);
    std::fwrite("\n", 1, 1, stdout);
    return response.value("success").toBool() ? 0 : 1;
}
