cmake_minimum_required(VERSION 3.20)
project(linux_mcp_portal_backend VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

include(CTest)
include(GNUInstallDirs)
find_package(PkgConfig REQUIRED)
find_package(Qt6 6.5 REQUIRED COMPONENTS Core DBus)
pkg_check_modules(WAYLAND_CLIENT REQUIRED IMPORTED_TARGET wayland-client>=1.20)
pkg_check_modules(XKBCOMMON REQUIRED IMPORTED_TARGET xkbcommon>=1.5)
find_program(WAYLAND_SCANNER_EXECUTABLE wayland-scanner REQUIRED)
find_program(ZENITY_EXECUTABLE zenity)

set(PROTOCOL_SOURCES)
foreach(PROTOCOL_NAME IN ITEMS virtual-keyboard-unstable-v1 wlr-virtual-pointer-unstable-v1)
  set(PROTOCOL_XML "${CMAKE_CURRENT_SOURCE_DIR}/protocols/${PROTOCOL_NAME}.xml")
  set(PROTOCOL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/protocols/${PROTOCOL_NAME}-client-protocol.h")
  set(PROTOCOL_CODE "${CMAKE_CURRENT_BINARY_DIR}/protocols/${PROTOCOL_NAME}-protocol.c")
  add_custom_command(
    OUTPUT "${PROTOCOL_HEADER}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/protocols"
    COMMAND "${WAYLAND_SCANNER_EXECUTABLE}" client-header "${PROTOCOL_XML}" "${PROTOCOL_HEADER}"
    DEPENDS "${PROTOCOL_XML}"
    VERBATIM
  )
  add_custom_command(
    OUTPUT "${PROTOCOL_CODE}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/protocols"
    COMMAND "${WAYLAND_SCANNER_EXECUTABLE}" private-code "${PROTOCOL_XML}" "${PROTOCOL_CODE}"
    DEPENDS "${PROTOCOL_XML}" "${PROTOCOL_HEADER}"
    VERBATIM
  )
  list(APPEND PROTOCOL_SOURCES "${PROTOCOL_HEADER}" "${PROTOCOL_CODE}")
endforeach()

set(PORTAL_BACKEND_SOURCES
  ${PROTOCOL_SOURCES}
  src/input_state.cpp
  src/key_resolver.cpp
  src/main.cpp
  src/portal_backend.cpp
  src/wayland_input.cpp
)

add_executable(linux-mcp-portal ${PORTAL_BACKEND_SOURCES})
target_include_directories(linux-mcp-portal PRIVATE src "${CMAKE_CURRENT_BINARY_DIR}/protocols")
target_link_libraries(linux-mcp-portal PRIVATE Qt6::Core Qt6::DBus PkgConfig::WAYLAND_CLIENT PkgConfig::XKBCOMMON)
target_compile_options(linux-mcp-portal PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=3)
target_link_options(linux-mcp-portal PRIVATE -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
if(ZENITY_EXECUTABLE)
  target_compile_definitions(linux-mcp-portal PRIVATE HKCF_ZENITY_EXECUTABLE="${ZENITY_EXECUTABLE}")
else()
  message(WARNING "zenity was not found; RemoteDesktop Start will deny requests because no consent UI is available")
endif()

configure_file(data/linux-mcp-portal.portal.in linux-mcp-portal.portal @ONLY)
configure_file(data/org.freedesktop.impl.portal.desktop.linux_mcp.service.in
  org.freedesktop.impl.portal.desktop.linux_mcp.service @ONLY)
configure_file(data/linux-mcp-portal.service.in linux-mcp-portal.service @ONLY)

install(TARGETS linux-mcp-portal RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}")

# Optional COSMIC Wayland toplevel control adapter. This stays a separate
# executable because the Python server discovers it only in COSMIC sessions.
set(COSMIC_PROTOCOL_SOURCES)
foreach(PROTOCOL_NAME IN ITEMS
    cosmic-toplevel-info-unstable-v1
    cosmic-toplevel-management-unstable-v1
    cosmic-workspace-unstable-v1
    ext-foreign-toplevel-list-v1
    ext-workspace-v1)
  set(PROTOCOL_XML "${CMAKE_CURRENT_SOURCE_DIR}/protocols/cosmic/${PROTOCOL_NAME}.xml")
  set(PROTOCOL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/protocols/${PROTOCOL_NAME}-client-protocol.h")
  set(PROTOCOL_CODE "${CMAKE_CURRENT_BINARY_DIR}/protocols/${PROTOCOL_NAME}-protocol.c")
  add_custom_command(
    OUTPUT "${PROTOCOL_HEADER}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/protocols"
    COMMAND "${WAYLAND_SCANNER_EXECUTABLE}" client-header "${PROTOCOL_XML}" "${PROTOCOL_HEADER}"
    DEPENDS "${PROTOCOL_XML}"
    VERBATIM
  )
  add_custom_command(
    OUTPUT "${PROTOCOL_CODE}"
    COMMAND "${WAYLAND_SCANNER_EXECUTABLE}" private-code "${PROTOCOL_XML}" "${PROTOCOL_CODE}"
    DEPENDS "${PROTOCOL_XML}" "${PROTOCOL_HEADER}"
    VERBATIM
  )
  list(APPEND COSMIC_PROTOCOL_SOURCES "${PROTOCOL_HEADER}" "${PROTOCOL_CODE}")
endforeach()

add_executable(linux-mcp-cosmic-wm
  ${COSMIC_PROTOCOL_SOURCES}
  src/cosmic_window_manager.cpp
)
target_include_directories(linux-mcp-cosmic-wm PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/protocols")
target_link_libraries(linux-mcp-cosmic-wm PRIVATE Qt6::Core PkgConfig::WAYLAND_CLIENT)
target_compile_options(linux-mcp-cosmic-wm PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=3)
target_link_options(linux-mcp-cosmic-wm PRIVATE -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
install(TARGETS linux-mcp-cosmic-wm RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

add_executable(linux-mcp-gnome-wm src/gnome_window_manager.cpp)
target_link_libraries(linux-mcp-gnome-wm PRIVATE Qt6::Core Qt6::DBus)
target_compile_options(linux-mcp-gnome-wm PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=3)
target_link_options(linux-mcp-gnome-wm PRIVATE -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
install(TARGETS linux-mcp-gnome-wm RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(DIRECTORY gnome-shell-extension/
  DESTINATION "${CMAKE_INSTALL_DATADIR}/gnome-shell/extensions/linux-mcp-window-control@linux-mcp-general-purpose")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/linux-mcp-portal.portal"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/xdg-desktop-portal/portals")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/org.freedesktop.impl.portal.desktop.linux_mcp.service"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/dbus-1/services")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/linux-mcp-portal.service"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/systemd/user")

if(BUILD_TESTING)
  find_program(DBUS_RUN_SESSION_EXECUTABLE dbus-run-session REQUIRED)
  add_executable(portal-test-prompt-allow tests/fake_prompt.cpp)
  target_link_libraries(portal-test-prompt-allow PRIVATE Qt6::Core)
  target_compile_definitions(portal-test-prompt-allow PRIVATE TEST_PROMPT_EXIT_CODE=0 TEST_PROMPT_DELAY_MS=10)

  add_executable(portal-test-prompt-deny tests/fake_prompt.cpp)
  target_link_libraries(portal-test-prompt-deny PRIVATE Qt6::Core)
  target_compile_definitions(portal-test-prompt-deny PRIVATE TEST_PROMPT_EXIT_CODE=1 TEST_PROMPT_DELAY_MS=10)

  add_executable(portal-session-test
    tests/portal_session_test.cpp
    src/input_state.cpp
    src/key_resolver.cpp
    src/portal_backend.cpp
  )
  target_include_directories(portal-session-test PRIVATE src)
  target_link_libraries(portal-session-test PRIVATE Qt6::Core Qt6::DBus PkgConfig::XKBCOMMON)
  target_compile_options(portal-session-test PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_definitions(portal-session-test PRIVATE
    TEST_ACCEPT_PROMPT="$<TARGET_FILE:portal-test-prompt-allow>"
    TEST_DENY_PROMPT="$<TARGET_FILE:portal-test-prompt-deny>"
  )
  add_dependencies(portal-session-test portal-test-prompt-allow portal-test-prompt-deny)
  add_test(NAME portal-session-test
    COMMAND "${CMAKE_COMMAND}" -E env --unset=WAYLAND_DISPLAY --unset=WAYLAND_SOCKET --unset=DISPLAY
      "${DBUS_RUN_SESSION_EXECUTABLE}" -- $<TARGET_FILE:portal-session-test>)
  set_tests_properties(portal-session-test PROPERTIES TIMEOUT 30)
endif()
