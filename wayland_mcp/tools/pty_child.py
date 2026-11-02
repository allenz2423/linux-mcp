"""Attach an inherited PTY slave as the controlling terminal, then exec."""

from __future__ import annotations

import fcntl
import os
import sys
import termios


def main() -> None:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        os._exit(126)
    try:
        slave_fd = int(sys.argv[1])
        command = sys.argv[3:]
        fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        for target_fd in (0, 1, 2):
            if slave_fd != target_fd:
                os.dup2(slave_fd, target_fd)
        if slave_fd > 2:
            os.close(slave_fd)
        os.execvpe(command[0], command, os.environ)
    except BaseException as exc:
        try:
            os.write(2, f"linux-mcp terminal launcher failed: {type(exc).__name__}\r\n".encode())
        except OSError:
            pass
        os._exit(127)


if __name__ == "__main__":
    main()
