#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <wayland-client.h>
#include "cosmic-toplevel-info-unstable-v1-client-protocol.h"
#include "cosmic-toplevel-management-unstable-v1-client-protocol.h"
#include "ext-foreign-toplevel-list-v1-client-protocol.h"
#include "ext-workspace-v1-client-protocol.h"

namespace {

constexpr size_t kMaxWindows = 512;
constexpr size_t kMaxWorkspaces = 256;
constexpr size_t kMaxOutputs = 64;
constexpr int kStringLimit = 1024;

QString clipped(const char *value, int limit = kStringLimit) {
    return QString::fromUtf8(value ? value : "").left(limit);
}

struct Output {
    wl_output *proxy = nullptr;
    uint32_t global_name = 0;
    QString name;
    QString description;
    QString make;
    QString model;
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
    int32_t refresh = 0;
    int32_t scale = 1;
    int32_t transform = WL_OUTPUT_TRANSFORM_NORMAL;
    bool has_geometry = false;
    bool available = true;
};

struct Workspace;

struct Group {
    ext_workspace_group_handle_v1 *proxy = nullptr;
    std::vector<Output *> outputs;
    std::vector<Workspace *> workspaces;
    std::vector<ext_workspace_handle_v1 *> workspace_proxies;
};

struct Workspace {
    ext_workspace_handle_v1 *proxy = nullptr;
    QString protocol_id;
    QString name;
    uint32_t state = 0;
    uint32_t capabilities = 0;
    Group *group = nullptr;
};

struct Toplevel {
    ext_foreign_toplevel_handle_v1 *foreign = nullptr;
    zcosmic_toplevel_handle_v1 *cosmic = nullptr;
    QString identifier;
    QString title;
    QString app_id;
    bool focused = false;
    bool minimized = false;
    bool maximized = false;
    bool fullscreen = false;
    bool has_state = false;
    bool closed = false;
    Output *geometry_output = nullptr;
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
    std::vector<Workspace *> workspaces;
    std::vector<ext_workspace_handle_v1 *> workspace_proxies;
};

class Client {
public:
    Client(const char *action, const char *target, const char *destination)
        : action_(QString::fromLocal8Bit(action)), target_(QString::fromLocal8Bit(target ? target : "")),
          destination_(QString::fromLocal8Bit(destination ? destination : "")) {}

    ~Client() {
        if (display_) wl_display_disconnect(display_);
    }

    bool connect() {
        display_ = wl_display_connect(nullptr);
        if (!display_) return fail("Cannot connect to the current Wayland display.");
        registry_ = wl_display_get_registry(display_);
        if (!registry_) return fail("Cannot obtain the Wayland registry.");
        static const wl_registry_listener listener = {registry_global, registry_remove};
        if (wl_registry_add_listener(registry_, &listener, this) != 0 || wl_display_roundtrip(display_) < 0)
            return fail("Cannot read the Wayland registry.");

        if (!foreign_list_global_ || !toplevel_info_global_ || !management_global_ || !workspace_global_)
            return fail("COSMIC toplevel and workspace Wayland protocols are unavailable.");

        foreign_list_ = static_cast<ext_foreign_toplevel_list_v1 *>(
            wl_registry_bind(registry_, foreign_list_global_, &ext_foreign_toplevel_list_v1_interface, 1));
        toplevel_info_ = static_cast<zcosmic_toplevel_info_v1 *>(
            wl_registry_bind(registry_, toplevel_info_global_, &zcosmic_toplevel_info_v1_interface, std::min(toplevel_info_version_, 3u)));
        management_ = static_cast<zcosmic_toplevel_manager_v1 *>(
            wl_registry_bind(registry_, management_global_, &zcosmic_toplevel_manager_v1_interface, std::min(management_version_, 4u)));
        workspace_manager_ = static_cast<ext_workspace_manager_v1 *>(
            wl_registry_bind(registry_, workspace_global_, &ext_workspace_manager_v1_interface, 1));
        if (!foreign_list_ || !toplevel_info_ || !management_ || !workspace_manager_)
            return fail("Cannot bind the required COSMIC Wayland protocols.");

        if (seat_global_) {
            seat_ = static_cast<wl_seat *>(wl_registry_bind(registry_, seat_global_, &wl_seat_interface, std::min(seat_version_, 1u)));
        }
        static const ext_foreign_toplevel_list_v1_listener foreign_listener = {foreign_toplevel, foreign_finished};
        static const zcosmic_toplevel_info_v1_listener info_listener = {info_toplevel, info_finished, info_done};
        static const zcosmic_toplevel_manager_v1_listener management_listener = {management_capabilities};
        static const ext_workspace_manager_v1_listener workspace_listener = {
            workspace_group, workspace_created, workspace_done, workspace_finished
        };
        if (ext_foreign_toplevel_list_v1_add_listener(foreign_list_, &foreign_listener, this) != 0 ||
            zcosmic_toplevel_info_v1_add_listener(toplevel_info_, &info_listener, this) != 0 ||
            zcosmic_toplevel_manager_v1_add_listener(management_, &management_listener, this) != 0 ||
            ext_workspace_manager_v1_add_listener(workspace_manager_, &workspace_listener, this) != 0)
            return fail("Cannot subscribe to COSMIC toplevel and workspace events.");

        // First roundtrip receives toplevel/workspace handles. Subsequent
        // roundtrips receive their initial properties and linked info objects.
        for (int i = 0; i < 3; ++i) {
            if (wl_display_roundtrip(display_) < 0)
                return fail("The Wayland compositor stopped responding during discovery.");
        }
        resolve_workspace_links();
        if (wl_display_get_error(display_) != 0)
            return fail("The Wayland compositor closed the connection during discovery.");
        return true;
    }

    QJsonObject result() {
        if (action_ == "probe") return probe();
        if (action_ == "list") return list_windows();
        if (action_ == "workspaces") return list_workspaces();
        if (action_ == "outputs") return list_outputs();
        return perform_action();
    }

    bool is_failed() const { return !error_.isEmpty(); }
    QString error() const { return error_; }

private:
    QString action_;
    QString target_;
    QString destination_;
    QString error_;
    wl_display *display_ = nullptr;
    wl_registry *registry_ = nullptr;
    wl_seat *seat_ = nullptr;
    ext_foreign_toplevel_list_v1 *foreign_list_ = nullptr;
    zcosmic_toplevel_info_v1 *toplevel_info_ = nullptr;
    zcosmic_toplevel_manager_v1 *management_ = nullptr;
    ext_workspace_manager_v1 *workspace_manager_ = nullptr;
    uint32_t foreign_list_global_ = 0;
    uint32_t toplevel_info_global_ = 0;
    uint32_t toplevel_info_version_ = 1;
    uint32_t management_global_ = 0;
    uint32_t management_version_ = 1;
    uint32_t workspace_global_ = 0;
    uint32_t seat_global_ = 0;
    uint32_t seat_version_ = 1;
    uint32_t manager_capabilities_ = 0;
    bool capabilities_received_ = false;
    bool protocol_finished_ = false;
    std::vector<std::unique_ptr<Output>> outputs_;
    std::vector<std::unique_ptr<Toplevel>> toplevels_;
    std::vector<std::unique_ptr<Workspace>> workspaces_;
    std::vector<std::unique_ptr<Group>> groups_;

    bool fail(const QString &message) {
        error_ = message;
        return false;
    }

    static Output *find_output(Client *self, wl_output *proxy) {
        for (auto &output : self->outputs_) if (output->proxy == proxy) return output.get();
        return nullptr;
    }

    static Toplevel *find_toplevel(Client *self, ext_foreign_toplevel_handle_v1 *proxy) {
        for (auto &window : self->toplevels_) if (window->foreign == proxy) return window.get();
        return nullptr;
    }

    static Workspace *find_workspace(Client *self, ext_workspace_handle_v1 *proxy) {
        for (auto &workspace : self->workspaces_) if (workspace->proxy == proxy) return workspace.get();
        return nullptr;
    }

    static void registry_global(void *data, wl_registry *registry, uint32_t name, const char *interface, uint32_t version) {
        auto *self = static_cast<Client *>(data);
        const QString interface_name = QString::fromLatin1(interface ? interface : "");
        if (interface_name == QStringLiteral("ext_foreign_toplevel_list_v1")) self->foreign_list_global_ = name;
        else if (interface_name == QStringLiteral("zcosmic_toplevel_info_v1")) {
            self->toplevel_info_global_ = name;
            self->toplevel_info_version_ = version;
        } else if (interface_name == QStringLiteral("zcosmic_toplevel_manager_v1")) {
            self->management_global_ = name;
            self->management_version_ = version;
        } else if (interface_name == QStringLiteral("ext_workspace_manager_v1")) self->workspace_global_ = name;
        else if (interface_name == QStringLiteral("wl_seat")) {
            self->seat_global_ = name;
            self->seat_version_ = version;
        } else if (interface_name == QStringLiteral("wl_output") && self->outputs_.size() < kMaxOutputs) {
            auto output = std::make_unique<Output>();
            output->global_name = name;
            output->proxy = static_cast<wl_output *>(wl_registry_bind(registry, name, &wl_output_interface, std::min(version, 4u)));
            if (output->proxy) {
                wl_output_set_user_data(output->proxy, output.get());
                static const wl_output_listener listener = {
                    output_geometry, output_mode, output_done, output_scale, output_name, output_description
                };
                if (wl_output_add_listener(output->proxy, &listener, output.get()) == 0)
                    self->outputs_.push_back(std::move(output));
            }
        }
    }

    static void registry_remove(void *data, wl_registry *, uint32_t name) {
        auto *self = static_cast<Client *>(data);
        for (auto &output : self->outputs_) if (output->global_name == name) output->available = false;
    }
    static void output_geometry(void *data, wl_output *, int32_t x, int32_t y, int32_t,
                                int32_t, int32_t, const char *make, const char *model, int32_t transform) {
        auto *output = static_cast<Output *>(data);
        output->x = x;
        output->y = y;
        output->make = clipped(make, 256);
        output->model = clipped(model, 256);
        output->transform = transform;
        output->has_geometry = true;
    }
    static void output_mode(void *data, wl_output *, uint32_t flags, int32_t width, int32_t height, int32_t refresh) {
        if ((flags & WL_OUTPUT_MODE_CURRENT) == 0) return;
        auto *output = static_cast<Output *>(data);
        output->width = width;
        output->height = height;
        output->refresh = refresh;
    }
    static void output_done(void *, wl_output *) {}
    static void output_scale(void *data, wl_output *, int32_t factor) {
        if (factor > 0) static_cast<Output *>(data)->scale = factor;
    }
    static void output_name(void *data, wl_output *, const char *name) {
        static_cast<Output *>(data)->name = clipped(name, 256);
    }
    static void output_description(void *data, wl_output *, const char *description) {
        static_cast<Output *>(data)->description = clipped(description, 512);
    }

    static void foreign_toplevel(void *data, ext_foreign_toplevel_list_v1 *, ext_foreign_toplevel_handle_v1 *proxy) {
        auto *self = static_cast<Client *>(data);
        if (self->toplevels_.size() >= kMaxWindows) return;
        auto window = std::make_unique<Toplevel>();
        window->foreign = proxy;
        Toplevel *row = window.get();
        wl_proxy_set_user_data(reinterpret_cast<wl_proxy *>(proxy), self);
        self->toplevels_.push_back(std::move(window));
        static const ext_foreign_toplevel_handle_v1_listener listener = {
            foreign_closed, foreign_done, foreign_title, foreign_app_id, foreign_identifier
        };
        ext_foreign_toplevel_handle_v1_add_listener(proxy, &listener, row);
        row->cosmic = zcosmic_toplevel_info_v1_get_cosmic_toplevel(self->toplevel_info_, proxy);
        if (row->cosmic) {
            static const zcosmic_toplevel_handle_v1_listener cosmic_listener = {
                cosmic_closed, cosmic_done, cosmic_title, cosmic_app_id, cosmic_output_enter,
                cosmic_output_leave, cosmic_workspace_enter_deprecated, cosmic_workspace_leave_deprecated,
                cosmic_state, cosmic_geometry, cosmic_workspace_enter, cosmic_workspace_leave
            };
            zcosmic_toplevel_handle_v1_add_listener(row->cosmic, &cosmic_listener, row);
        }
    }
    static void foreign_finished(void *data, ext_foreign_toplevel_list_v1 *) {
        static_cast<Client *>(data)->protocol_finished_ = true;
    }
    static void foreign_closed(void *data, ext_foreign_toplevel_handle_v1 *) {
        static_cast<Toplevel *>(data)->closed = true;
    }
    static void foreign_done(void *, ext_foreign_toplevel_handle_v1 *) {}
    static void foreign_title(void *data, ext_foreign_toplevel_handle_v1 *, const char *title) {
        static_cast<Toplevel *>(data)->title = clipped(title);
    }
    static void foreign_app_id(void *data, ext_foreign_toplevel_handle_v1 *, const char *app_id) {
        static_cast<Toplevel *>(data)->app_id = clipped(app_id, 512);
    }
    static void foreign_identifier(void *data, ext_foreign_toplevel_handle_v1 *, const char *id) {
        static_cast<Toplevel *>(data)->identifier = clipped(id, 32);
    }
    static void cosmic_closed(void *, zcosmic_toplevel_handle_v1 *) {}
    static void cosmic_done(void *, zcosmic_toplevel_handle_v1 *) {}
    static void cosmic_title(void *data, zcosmic_toplevel_handle_v1 *, const char *title) {
        static_cast<Toplevel *>(data)->title = clipped(title);
    }
    static void cosmic_app_id(void *data, zcosmic_toplevel_handle_v1 *, const char *app_id) {
        static_cast<Toplevel *>(data)->app_id = clipped(app_id, 512);
    }
    static void cosmic_output_enter(void *, zcosmic_toplevel_handle_v1 *, wl_output *) {}
    static void cosmic_output_leave(void *, zcosmic_toplevel_handle_v1 *, wl_output *) {}
    static void cosmic_workspace_enter_deprecated(void *, zcosmic_toplevel_handle_v1 *, zcosmic_workspace_handle_v1 *) {}
    static void cosmic_workspace_leave_deprecated(void *, zcosmic_toplevel_handle_v1 *, zcosmic_workspace_handle_v1 *) {}
    static void cosmic_state(void *data, zcosmic_toplevel_handle_v1 *, wl_array *states) {
        auto *window = static_cast<Toplevel *>(data);
        window->focused = window->minimized = window->maximized = window->fullscreen = false;
        if (states && states->data) {
            auto *state = static_cast<uint32_t *>(states->data);
            auto *end = reinterpret_cast<uint32_t *>(static_cast<char *>(states->data) + states->size);
            for (; state < end; ++state) {
                if (*state == ZCOSMIC_TOPLEVEL_HANDLE_V1_STATE_ACTIVATED) window->focused = true;
                if (*state == ZCOSMIC_TOPLEVEL_HANDLE_V1_STATE_MINIMIZED) window->minimized = true;
                if (*state == ZCOSMIC_TOPLEVEL_HANDLE_V1_STATE_MAXIMIZED) window->maximized = true;
                if (*state == ZCOSMIC_TOPLEVEL_HANDLE_V1_STATE_FULLSCREEN) window->fullscreen = true;
            }
        }
        window->has_state = true;
    }
    static void cosmic_geometry(void *data, zcosmic_toplevel_handle_v1 *, wl_output *output_proxy,
                                int32_t x, int32_t y, int32_t width, int32_t height) {
        auto *window = static_cast<Toplevel *>(data);
        Output *output = nullptr;
        // Output proxies are discovered by the registry callback, which runs
        // before the toplevel geometry event is delivered.
        // The client pointer is retained in the proxy's user data below.
        if (output_proxy) output = static_cast<Output *>(wl_output_get_user_data(output_proxy));
        window->geometry_output = output;
        window->x = x;
        window->y = y;
        window->width = width;
        window->height = height;
    }
    static void cosmic_workspace_enter_deprecated_ext(void *, zcosmic_toplevel_handle_v1 *, ext_workspace_handle_v1 *) {}
    static void cosmic_workspace_enter(void *data, zcosmic_toplevel_handle_v1 *, ext_workspace_handle_v1 *proxy) {
        auto *window = static_cast<Toplevel *>(data);
        if (std::find(window->workspace_proxies.begin(), window->workspace_proxies.end(), proxy) == window->workspace_proxies.end())
            window->workspace_proxies.push_back(proxy);
    }
    static void cosmic_workspace_leave(void *data, zcosmic_toplevel_handle_v1 *, ext_workspace_handle_v1 *proxy) {
        auto *window = static_cast<Toplevel *>(data);
        auto &rows = window->workspace_proxies;
        rows.erase(std::remove(rows.begin(), rows.end(), proxy), rows.end());
    }
    static void info_toplevel(void *, zcosmic_toplevel_info_v1 *, zcosmic_toplevel_handle_v1 *) {}
    static void info_finished(void *, zcosmic_toplevel_info_v1 *) {}
    static void info_done(void *, zcosmic_toplevel_info_v1 *) {}
    static void management_capabilities(void *data, zcosmic_toplevel_manager_v1 *, wl_array *values) {
        auto *self = static_cast<Client *>(data);
        self->manager_capabilities_ = 0;
        if (values && values->data) {
            auto *value = static_cast<uint32_t *>(values->data);
            auto *end = reinterpret_cast<uint32_t *>(static_cast<char *>(values->data) + values->size);
            for (; value < end; ++value) self->manager_capabilities_ |= (1u << *value);
        }
        self->capabilities_received_ = true;
    }
    static void workspace_group(void *data, ext_workspace_manager_v1 *, ext_workspace_group_handle_v1 *proxy) {
        auto *self = static_cast<Client *>(data);
        auto group = std::make_unique<Group>();
        group->proxy = proxy;
        Group *row = group.get();
        wl_proxy_set_user_data(reinterpret_cast<wl_proxy *>(proxy), self);
        self->groups_.push_back(std::move(group));
        static const ext_workspace_group_handle_v1_listener listener = {
            group_capabilities, group_output_enter, group_output_leave, group_workspace_enter,
            group_workspace_leave, group_removed
        };
        ext_workspace_group_handle_v1_add_listener(proxy, &listener, row);
    }
    static void workspace_created(void *data, ext_workspace_manager_v1 *, ext_workspace_handle_v1 *proxy) {
        auto *self = static_cast<Client *>(data);
        if (self->workspaces_.size() >= kMaxWorkspaces) return;
        auto workspace = std::make_unique<Workspace>();
        workspace->proxy = proxy;
        Workspace *row = workspace.get();
        self->workspaces_.push_back(std::move(workspace));
        static const ext_workspace_handle_v1_listener listener = {
            workspace_id, workspace_name, workspace_coordinates, workspace_state,
            workspace_capabilities, workspace_removed
        };
        ext_workspace_handle_v1_add_listener(proxy, &listener, row);
    }
    static void workspace_done(void *, ext_workspace_manager_v1 *) {}
    static void workspace_finished(void *data, ext_workspace_manager_v1 *) {
        static_cast<Client *>(data)->protocol_finished_ = true;
    }
    static void group_capabilities(void *, ext_workspace_group_handle_v1 *, uint32_t) {}
    static void group_output_enter(void *data, ext_workspace_group_handle_v1 *, wl_output *proxy) {
        auto *group = static_cast<Group *>(data);
        auto *output = static_cast<Output *>(wl_output_get_user_data(proxy));
        if (output && std::find(group->outputs.begin(), group->outputs.end(), output) == group->outputs.end())
            group->outputs.push_back(output);
    }
    static void group_output_leave(void *data, ext_workspace_group_handle_v1 *, wl_output *proxy) {
        auto *group = static_cast<Group *>(data);
        auto *output = static_cast<Output *>(wl_output_get_user_data(proxy));
        group->outputs.erase(std::remove(group->outputs.begin(), group->outputs.end(), output), group->outputs.end());
    }
    static void group_workspace_enter(void *data, ext_workspace_group_handle_v1 *, ext_workspace_handle_v1 *proxy) {
        auto *group = static_cast<Group *>(data);
        if (std::find(group->workspace_proxies.begin(), group->workspace_proxies.end(), proxy) == group->workspace_proxies.end())
            group->workspace_proxies.push_back(proxy);
    }
    static void group_workspace_leave(void *data, ext_workspace_group_handle_v1 *, ext_workspace_handle_v1 *proxy) {
        auto *group = static_cast<Group *>(data);
        group->workspace_proxies.erase(std::remove(group->workspace_proxies.begin(), group->workspace_proxies.end(), proxy),
                                       group->workspace_proxies.end());
        auto *client = static_cast<Client *>(wl_proxy_get_user_data(reinterpret_cast<wl_proxy *>(group->proxy)));
        if (!client) return;
        Workspace *workspace = find_workspace(client, proxy);
        if (workspace && workspace->group == group) workspace->group = nullptr;
        group->workspaces.erase(std::remove(group->workspaces.begin(), group->workspaces.end(), workspace), group->workspaces.end());
    }
    static void group_removed(void *, ext_workspace_group_handle_v1 *) {}
    static void workspace_id(void *data, ext_workspace_handle_v1 *, const char *id) {
        static_cast<Workspace *>(data)->protocol_id = clipped(id, 256);
    }
    static void workspace_name(void *data, ext_workspace_handle_v1 *, const char *name) {
        static_cast<Workspace *>(data)->name = clipped(name, 256);
    }
    static void workspace_coordinates(void *, ext_workspace_handle_v1 *, wl_array *) {}
    static void workspace_state(void *data, ext_workspace_handle_v1 *, uint32_t state) {
        static_cast<Workspace *>(data)->state = state;
    }
    static void workspace_capabilities(void *data, ext_workspace_handle_v1 *, uint32_t capabilities) {
        static_cast<Workspace *>(data)->capabilities = capabilities;
    }
    static void workspace_removed(void *, ext_workspace_handle_v1 *) {}

    QString workspace_identifier(const Workspace *workspace) const {
        if (!workspace->protocol_id.isEmpty()) return QStringLiteral("id:") + workspace->protocol_id;
        if (!workspace->name.isEmpty()) {
            int same_name = 0;
            for (const auto &candidate : workspaces_) if (candidate->name == workspace->name) ++same_name;
            if (same_name == 1) return QStringLiteral("name:") + workspace->name;
        }
        return {};
    }

    void resolve_workspace_links() {
        for (auto &group : groups_) {
            for (ext_workspace_handle_v1 *proxy : group->workspace_proxies) {
                Workspace *workspace = find_workspace(this, proxy);
                if (workspace) {
                    workspace->group = group.get();
                    if (std::find(group->workspaces.begin(), group->workspaces.end(), workspace) == group->workspaces.end())
                        group->workspaces.push_back(workspace);
                }
            }
        }
        for (auto &window : toplevels_) {
            for (ext_workspace_handle_v1 *proxy : window->workspace_proxies) {
                Workspace *workspace = find_workspace(this, proxy);
                if (workspace && std::find(window->workspaces.begin(), window->workspaces.end(), workspace) == window->workspaces.end())
                    window->workspaces.push_back(workspace);
            }
        }
    }

    QJsonArray capability_names() const {
        QJsonArray rows;
        auto has = [this](uint32_t value) { return (manager_capabilities_ & (1u << value)) != 0; };
        if (has(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_CLOSE)) rows.append("close");
        if (has(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_ACTIVATE) && seat_) rows.append("focus");
        if (has(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_MINIMIZE)) rows.append("minimize");
        if (has(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_MAXIMIZE)) rows.append("maximize");
        bool can_switch = std::any_of(workspaces_.begin(), workspaces_.end(), [](const auto &workspace) {
            return (workspace->capabilities & EXT_WORKSPACE_HANDLE_V1_WORKSPACE_CAPABILITIES_ACTIVATE) != 0;
        });
        if (can_switch) rows.append("workspace_switch");
        if (has(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_MOVE_TO_EXT_WORKSPACE) &&
            management_version_ >= 4 && std::any_of(workspaces_.begin(), workspaces_.end(), [](const auto &workspace) {
                return workspace->group && std::any_of(workspace->group->outputs.begin(), workspace->group->outputs.end(),
                    [](const Output *output) { return output->available; });
            })) rows.append("window_move");
        rows.append("window_list");
        rows.append("window_detail");
        rows.append("workspace_list");
        rows.append("output_list");
        return rows;
    }

    QJsonObject probe() const {
        return {{"success", true}, {"compositor", "cosmic"}, {"capabilities", capability_names()}};
    }

    QJsonObject list_windows() const {
        QJsonArray rows;
        for (const auto &row : toplevels_) {
            QJsonObject item = window_json(*row);
            if (!item.isEmpty()) rows.append(item);
        }
        QJsonValue focused;
        for (const auto &row : toplevels_) {
            if (row->focused && !row->closed && !row->identifier.isEmpty()) {
                focused = window_json(*row);
                break;
            }
        }
        return {{"success", true}, {"compositor", "cosmic"}, {"windows", rows},
                {"focused_window", focused}, {"total_windows", rows.size()},
                {"capabilities", capability_names()}};
    }

    QJsonObject list_workspaces() const {
        QJsonArray rows;
        for (const auto &row : workspaces_) {
            const Workspace &workspace = *row;
            QString id = workspace_identifier(&workspace);
            if (id.isEmpty()) continue;
            QJsonObject item{
                {"id", id}, {"name", workspace.name.isEmpty() ? id : workspace.name},
                {"is_active", (workspace.state & EXT_WORKSPACE_HANDLE_V1_STATE_ACTIVE) != 0},
                {"is_focused", (workspace.state & EXT_WORKSPACE_HANDLE_V1_STATE_ACTIVE) != 0}
            };
            if (workspace.group && workspace.group->outputs.size() == 1 && workspace.group->outputs.front()->available &&
                !workspace.group->outputs.front()->name.isEmpty())
                item.insert("monitor", workspace.group->outputs.front()->name);
            int count = 0;
            for (const auto &window : toplevels_)
                if (!window->closed &&
                    std::find(window->workspaces.begin(), window->workspaces.end(), &workspace) != window->workspaces.end()) ++count;
            item.insert("windows_count", count);
            rows.append(item);
        }
        QJsonValue active;
        for (const auto &row : workspaces_) if ((row->state & EXT_WORKSPACE_HANDLE_V1_STATE_ACTIVE) != 0) {
            QString id = workspace_identifier(row.get());
            if (!id.isEmpty()) active = QJsonObject{{"id", id}, {"name", row->name.isEmpty() ? id : row->name},
                                                    {"is_active", true}, {"is_focused", true}};
            break;
        }
        return {{"success", true}, {"compositor", "cosmic"}, {"workspaces", rows},
                {"active_workspace", active}, {"total_workspaces", rows.size()},
                {"capabilities", capability_names()}};
    }

    QJsonObject list_outputs() const {
        QJsonArray rows;
        for (const auto &row : outputs_) {
            const Output &output = *row;
            if (!output.available) continue;
            QString id = output.name.isEmpty() ? QStringLiteral("output-%1").arg(rows.size() + 1) : output.name;
            QJsonObject item{
                {"id", id}, {"name", output.name.isEmpty() ? id : output.name}, {"enabled", true}, {"is_focused", false}
            };
            if (!output.make.isEmpty()) item.insert("make", output.make);
            if (!output.model.isEmpty()) item.insert("model", output.model);
            if (output.width > 0 && output.height > 0) {
                item.insert("width_pixels", output.width);
                item.insert("height_pixels", output.height);
            }
            if (output.refresh > 0) item.insert("refresh_rate_hz", output.refresh / 1000.0);
            item.insert("scale", output.scale);
            if (output.has_geometry && output.width > 0 && output.height > 0 && output.scale > 0 &&
                output.width % output.scale == 0 && output.height % output.scale == 0) {
                int32_t logical_width = output.width / output.scale;
                int32_t logical_height = output.height / output.scale;
                if (output.transform == WL_OUTPUT_TRANSFORM_90 || output.transform == WL_OUTPUT_TRANSFORM_270 ||
                    output.transform == WL_OUTPUT_TRANSFORM_FLIPPED_90 || output.transform == WL_OUTPUT_TRANSFORM_FLIPPED_270)
                    std::swap(logical_width, logical_height);
                item.insert("logical_geometry", QJsonObject{{"x", output.x}, {"y", output.y},
                                                            {"width", logical_width}, {"height", logical_height}});
            }
            rows.append(item);
        }
        return {{"success", true}, {"compositor", "cosmic"}, {"outputs", rows},
                {"total_outputs", rows.size()}, {"capabilities", capability_names()}};
    }

    Toplevel *match_window(const QString &identifier) const {
        Toplevel *found = nullptr;
        for (const auto &row : toplevels_) if (!row->closed && row->identifier == identifier) {
            if (found) return nullptr;
            found = row.get();
        }
        return found;
    }

    Workspace *match_workspace(const QString &identifier) const {
        Workspace *found = nullptr;
        for (const auto &row : workspaces_) if (workspace_identifier(row.get()) == identifier) {
            if (found) return nullptr;
            found = row.get();
        }
        return found;
    }

    bool has_capability(uint32_t capability) const { return (manager_capabilities_ & (1u << capability)) != 0; }

    QJsonObject window_json(const Toplevel &window) const {
        if (window.identifier.isEmpty() || window.closed) return {};
        QJsonObject item{
            {"id", window.identifier},
            {"app_id", window.app_id.isEmpty() ? QStringLiteral("Unknown") : window.app_id},
            {"title", window.title}, {"is_focused", window.focused},
            {"state", QJsonObject{
                {"is_focused", window.focused}, {"is_minimized", window.minimized},
                {"is_maximized", window.has_state ? QJsonValue(window.maximized) : QJsonValue(QJsonValue::Null)},
                {"is_fullscreen", window.fullscreen}, {"is_floating", false}
            }}
        };
        if (window.workspaces.size() == 1) {
            QString id = workspace_identifier(window.workspaces.front());
            if (!id.isEmpty()) {
                item.insert("workspace_id", id);
                item.insert("workspace_name", window.workspaces.front()->name);
            }
        }
        if (window.geometry_output && window.geometry_output->available && window.width > 0 && window.height > 0) {
            item.insert("geometry", QJsonObject{
                {"x", window.geometry_output->x + window.x}, {"y", window.geometry_output->y + window.y},
                {"width", window.width}, {"height", window.height}
            });
        }
        return item;
    }

    QJsonObject action_result(bool ok, const QString &message) const {
        return {{"success", ok}, {"message", message}};
    }

    QJsonObject perform_action() {
        const QString &target = target_;
        const QString &destination = destination_;
        if (action_ == "focus" || action_ == "close" || action_ == "minimize" || action_ == "maximize") {
            Toplevel *window = match_window(target);
            if (!window || !window->cosmic) return action_result(false, "The exact observed COSMIC window identifier is no longer present.");
            if (action_ == "focus") {
                if (!seat_ || !has_capability(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_ACTIVATE))
                    return action_result(false, "COSMIC focus activation is unavailable.");
                zcosmic_toplevel_manager_v1_activate(management_, window->cosmic, seat_);
            } else if (action_ == "close") {
                if (!has_capability(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_CLOSE))
                    return action_result(false, "COSMIC window close is unavailable.");
                zcosmic_toplevel_manager_v1_close(management_, window->cosmic);
            } else if (action_ == "minimize") {
                if (!has_capability(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_MINIMIZE))
                    return action_result(false, "COSMIC window minimization is unavailable.");
                zcosmic_toplevel_manager_v1_set_minimized(management_, window->cosmic);
            } else {
                if (!has_capability(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_MAXIMIZE))
                    return action_result(false, "COSMIC window maximization is unavailable.");
                zcosmic_toplevel_manager_v1_set_maximized(management_, window->cosmic);
            }
        } else if (action_ == "switch-workspace") {
            Workspace *workspace = match_workspace(target);
            if (!workspace || (workspace->capabilities & EXT_WORKSPACE_HANDLE_V1_WORKSPACE_CAPABILITIES_ACTIVATE) == 0)
                return action_result(false, "The exact observed COSMIC workspace is no longer available for activation.");
            ext_workspace_handle_v1_activate(workspace->proxy);
            ext_workspace_manager_v1_commit(workspace_manager_);
        } else if (action_ == "move-window") {
            Toplevel *window = match_window(target);
            Workspace *workspace = match_workspace(destination);
            if (!window || !window->cosmic) return action_result(false, "The exact observed COSMIC window identifier is no longer present.");
            if (!workspace || !workspace->group || workspace->group->outputs.empty())
                return action_result(false, "The exact destination workspace has no current output assignment.");
            if (!has_capability(ZCOSMIC_TOPLEVEL_MANAGER_V1_ZCOSMIC_TOPLELEVEL_MANAGEMENT_CAPABILITIES_V1_MOVE_TO_EXT_WORKSPACE) || management_version_ < 4)
                return action_result(false, "COSMIC window movement to workspaces is unavailable.");
            Output *output = nullptr;
            if (window->geometry_output && window->geometry_output->available &&
                std::find(workspace->group->outputs.begin(), workspace->group->outputs.end(), window->geometry_output) != workspace->group->outputs.end())
                output = window->geometry_output;
            else {
                std::vector<Output *> eligible;
                for (Output *candidate : workspace->group->outputs) if (candidate->available) eligible.push_back(candidate);
                if (eligible.size() == 1) output = eligible.front();
            }
            if (!output) return action_result(false, "The destination workspace has multiple outputs and no unambiguous target output.");
            zcosmic_toplevel_manager_v1_move_to_ext_workspace(management_, window->cosmic, workspace->proxy, output->proxy);
        } else {
            return action_result(false, "Unknown COSMIC window-manager operation.");
        }
        if (wl_display_flush(display_) < 0) return action_result(false, "The COSMIC request could not be sent to the compositor.");
        return action_result(true, QStringLiteral("COSMIC accepted the %1 request.").arg(action_));
    }
};

} // namespace

int main(int argc, char **argv) {
    if (argc < 2 || argc > 4) {
        std::fprintf(stderr, "usage: linux-mcp-cosmic-wm probe|list|workspaces|outputs|focus|close|minimize|maximize|switch-workspace|move-window [id] [workspace-id]\n");
        return 2;
    }
    Client client(argv[1], argc >= 3 ? argv[2] : "", argc >= 4 ? argv[3] : "");
    if (!client.connect()) {
        QByteArray bytes = QJsonDocument(QJsonObject{{"success", false}, {"message", client.error()}}).toJson(QJsonDocument::Compact);
        std::fwrite(bytes.constData(), 1, static_cast<size_t>(bytes.size()), stdout);
        std::fwrite("\n", 1, 1, stdout);
        return 1;
    }
    QJsonObject response = client.result();
    QByteArray bytes = QJsonDocument(response).toJson(QJsonDocument::Compact);
    if (bytes.size() > 2 * 1024 * 1024) {
        bytes = QJsonDocument(QJsonObject{{"success", false}, {"message", "COSMIC response exceeded the two-megabyte limit."}}).toJson(QJsonDocument::Compact);
    }
    std::fwrite(bytes.constData(), 1, static_cast<size_t>(bytes.size()), stdout);
    std::fwrite("\n", 1, 1, stdout);
    return response.value("success").toBool() ? 0 : 1;
}
