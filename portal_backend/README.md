# Linux MCP RemoteDesktop portal backend

This optional user-level companion exposes only the XDG `RemoteDesktop`
interface. It is used on Wayland compositors whose standard portal backend does
not provide remote keyboard and pointer input. The Linux MCP still requests
input through the public XDG portal API.

Each new `Start` request opens a visible Zenity permission prompt. The prompt
shows the caller's verified D-Bus process ID and executable path, plus its
portal application ID and requested device types. Only an explicit **Allow**
starts the session. Denial, timeout, an unavailable prompt, an unverifiable
caller, or closing the session while the prompt is open leaves input disabled.
The grant lasts only for that portal session. The process runs no shell and
accepts no command arguments from the MCP client.

The backend implements the bounded RemoteDesktop keyboard and pointer methods
used by the MCP. It does not expose Screenshot, ScreenCast, EIS, or compositor
control interfaces. It requires a compositor that exposes both
`zwp_virtual_keyboard_manager_v1` and `zwlr_virtual_pointer_manager_v1`.
Hyprland is the tested target; other listed `UseIn` desktop identifiers still
need live compatibility verification.

## Build and install

Build dependencies are CMake, a C/C++ compiler, Qt 6 Core and DBus, Wayland
client headers and scanner, xkbcommon, and `zenity` for the consent UI. The
same build also creates the optional `linux-mcp-cosmic-wm` and
`linux-mcp-gnome-wm` helpers under the prefix's `bin` directory. It installs
the GNOME Shell extension under the prefix's `share/gnome-shell/extensions`
directory. COSMIC sessions use the native helper directly; GNOME sessions
also require the extension to be enabled in the user's current Shell session.
Keep the prefix's `bin` directory on the MCP server's `PATH`. On this host,
configure and install under the user's local prefix:

```sh
cmake -S portal_backend -B /tmp/linux-mcp-portal-build \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$HOME/.local"
cmake --build /tmp/linux-mcp-portal-build
ctest --test-dir /tmp/linux-mcp-portal-build --output-on-failure
cmake --install /tmp/linux-mcp-portal-build
```

With `CMAKE_INSTALL_PREFIX="$HOME/.local"`, enable the installed GNOME
extension with:

```sh
gnome-extensions enable linux-mcp-window-control@linux-mcp-general-purpose
```

Restart the GNOME Shell session if it does not load immediately. The MCP
reports GNOME window control as unavailable until the extension's local D-Bus
service responds.

To route only RemoteDesktop on Hyprland, use
`~/.config/xdg-desktop-portal/hyprland-portals.conf`:

```ini
[preferred]
default=hyprland;gtk
org.freedesktop.impl.portal.RemoteDesktop=linux_mcp
```

The screenshot and screencast interfaces remain routed to the existing
Hyprland backend. After installing or changing the route, reload user units
and restart `xdg-desktop-portal`.

## Attribution

The Wayland virtual-input, key-resolution, input-ownership, portal-session, and
security-policy code is adapted from
[`gfhdhytghd/hypr-kdeconnect-fix`](https://github.com/gfhdhytghd/hypr-kdeconnect-fix),
commit `809c1ea83ca71f94df929ccea04043f0c47c0c32`, under the MIT license in
`LICENSE.upstream`. The Linux MCP changes remove the KDE Connect and Deskflow
allowlist, remove EIS and its bundled dependency, remove direct input
self-test commands, and require the visible per-session consent prompt
described above.

The COSMIC helper's protocol XML files are from the upstream
[`pop-os/cosmic-protocols`](https://github.com/pop-os/cosmic-protocols)
project; each file includes its upstream copyright and permission notice.
