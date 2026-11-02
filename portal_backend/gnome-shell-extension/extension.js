import Gio from 'gi://Gio';
import Meta from 'gi://Meta';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';

const BUS_NAME = 'org.linuxmcp.GnomeWindowControl';
const OBJECT_PATH = '/org/linuxmcp/GnomeWindowControl';
const INTERFACE_XML = `
<node>
  <interface name="org.linuxmcp.GnomeWindowControl">
    <method name="GetState">
      <arg name="state_json" type="s" direction="out"/>
    </method>
    <method name="PerformAction">
      <arg name="operation" type="s" direction="in"/>
      <arg name="window_id" type="s" direction="in"/>
      <arg name="workspace_id" type="s" direction="in"/>
      <arg name="result_json" type="s" direction="out"/>
    </method>
  </interface>
</node>`;

export default class LinuxMcpWindowControl extends Extension {
    enable() {
        this._workspaceIds = new WeakMap();
        this._workspaceById = new Map();
        this._nextWorkspaceId = 1;
        this._ownerId = Gio.bus_own_name(
            Gio.BusType.SESSION,
            BUS_NAME,
            Gio.BusNameOwnerFlags.NONE,
            connection => {
                this._dbusObject = Gio.DBusExportedObject.wrapJSObject(INTERFACE_XML, this);
                this._dbusObject.export(connection, OBJECT_PATH);
            },
            () => {},
            () => {
                this._dbusObject?.unexport();
                this._dbusObject = null;
            },
        );
    }

    disable() {
        this._dbusObject?.unexport();
        this._dbusObject = null;
        if (this._ownerId) Gio.bus_unown_name(this._ownerId);
        this._ownerId = 0;
        this._workspaceById.clear();
        this._workspaceIds = new WeakMap();
    }

    _workspaceId(workspace) {
        if (!workspace) return null;
        let id = this._workspaceIds.get(workspace);
        if (!id) {
            id = `workspace:${this._nextWorkspaceId++}`;
            this._workspaceIds.set(workspace, id);
            this._workspaceById.set(id, workspace);
        }
        return id;
    }

    _workspaces() {
        const manager = global.workspace_manager;
        const workspaces = [];
        for (let index = 0; index < manager.get_n_workspaces(); index++) {
            const workspace = manager.get_workspace_by_index(index);
            if (workspace) workspaces.push(workspace);
        }
        const current = new Set(workspaces);
        for (const [id, workspace] of this._workspaceById) {
            if (!current.has(workspace)) this._workspaceById.delete(id);
        }
        return workspaces;
    }

    _windowRow(window) {
        const stableSequence = window.get_stable_sequence();
        const workspace = window.get_workspace();
        const rect = window.get_frame_rect();
        const focused = window.has_focus();
        const maximizeFlags = window.get_maximize_flags();
        return {
            id: `window:${stableSequence}`,
            app_id: window.get_sandboxed_app_id() || window.get_wm_class() || 'Unknown',
            title: window.get_title() || '',
            workspace_id: this._workspaceId(workspace),
            workspace_name: workspace ? `Workspace ${workspace.index() + 1}` : null,
            is_focused: focused,
            geometry: rect ? {x: rect.x, y: rect.y, width: rect.width, height: rect.height} : null,
            state: {
                is_focused: focused,
                is_minimized: window.minimized === true,
                is_maximized: maximizeFlags !== 0,
                is_fullscreen: window.is_fullscreen(),
                is_floating: false,
            },
        };
    }

    GetState() {
        const workspaces = this._workspaces();
        const windows = [];
        for (const actor of global.get_window_actors()) {
            const window = actor.get_meta_window();
            if (!window || window.is_override_redirect()) continue;
            try {
                windows.push(this._windowRow(window));
            } catch (error) {
                logError(error, 'linux-mcp could not read a GNOME window');
            }
        }

        const counts = new Map(workspaces.map(workspace => [this._workspaceId(workspace), 0]));
        for (const window of windows) {
            if (window.workspace_id && counts.has(window.workspace_id))
                counts.set(window.workspace_id, counts.get(window.workspace_id) + 1);
        }
        const activeIndex = global.workspace_manager.get_active_workspace_index();
        const workspaceRows = workspaces.map((workspace, index) => {
            const id = this._workspaceId(workspace);
            const active = index === activeIndex;
            return {
                id,
                name: `Workspace ${index + 1}`,
                is_active: active,
                is_focused: active,
                windows_count: counts.get(id) || 0,
            };
        });
        const activeWorkspace = workspaceRows.find(workspace => workspace.is_active) || null;

        const outputs = Main.layoutManager.monitors.map((monitor, index) => {
            return {
                id: `monitor:${index}`,
                name: `Monitor ${index + 1}`,
                enabled: true,
                is_focused: false,
                logical_geometry: {
                    x: monitor.x,
                    y: monitor.y,
                    width: monitor.width,
                    height: monitor.height,
                },
            };
        });

        const focused = windows.find(window => window.is_focused) || null;
        return JSON.stringify({
            success: true,
            compositor: 'gnome',
            windows,
            focused_window: focused,
            total_windows: windows.length,
            workspaces: workspaceRows,
            active_workspace: activeWorkspace,
            total_workspaces: workspaceRows.length,
            outputs,
            total_outputs: outputs.length,
        });
    }

    _findWindow(identifier) {
        if (typeof identifier !== 'string' || !/^window:[0-9]{1,16}$/.test(identifier)) return null;
        const sequence = Number(identifier.slice('window:'.length));
        for (const actor of global.get_window_actors()) {
            const window = actor.get_meta_window();
            if (window && !window.is_override_redirect() && window.get_stable_sequence() === sequence)
                return window;
        }
        return null;
    }

    _findWorkspace(identifier) {
        if (typeof identifier !== 'string') return null;
        const workspace = this._workspaceById.get(identifier);
        if (!workspace) return null;
        return this._workspaces().includes(workspace) ? workspace : null;
    }

    _result(success, message) {
        return JSON.stringify({success, message});
    }

    PerformAction(operation, windowId, workspaceId) {
        try {
            if (operation === 'switch-workspace') {
                const workspace = this._findWorkspace(workspaceId);
                if (!workspace) return this._result(false, 'The exact observed GNOME workspace is no longer present.');
                workspace.activate(global.get_current_time());
                return this._result(true, 'GNOME accepted the workspace activation request.');
            }

            const window = this._findWindow(windowId);
            if (!window) return this._result(false, 'The exact observed GNOME window identifier is no longer present.');
            if (operation === 'focus') {
                window.activate(global.get_current_time());
            } else if (operation === 'close') {
                if (!window.can_close()) return this._result(false, 'GNOME reports this window cannot be closed.');
                window.delete(global.get_current_time());
            } else if (operation === 'minimize') {
                if (!window.can_minimize()) return this._result(false, 'GNOME reports this window cannot be minimized.');
                window.minimize();
            } else if (operation === 'maximize') {
                if (!window.can_maximize()) return this._result(false, 'GNOME reports this window cannot be maximized.');
                window.maximize(Meta.MaximizeFlags.BOTH);
            } else if (operation === 'move-window') {
                const workspace = this._findWorkspace(workspaceId);
                if (!workspace) return this._result(false, 'The exact observed GNOME workspace is no longer present.');
                window.change_workspace(workspace);
            } else {
                return this._result(false, 'Unknown GNOME window-management operation.');
            }
            return this._result(true, `GNOME accepted the ${operation} request.`);
        } catch (error) {
            logError(error, `linux-mcp GNOME action failed: ${operation}`);
            return this._result(false, 'GNOME rejected the request. Observe the desktop again before retrying.');
        }
    }
}
