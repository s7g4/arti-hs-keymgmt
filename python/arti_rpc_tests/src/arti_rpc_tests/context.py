"""
Context shared across arti_rpc tests.
"""

from __future__ import annotations

import arti_rpc
import math
import signal
import subprocess
import sys
import time
import tomli_w

from arti_rpc_tests import FatalException

from pathlib import Path
from typing import Optional


class TestContext:
    """
    Context shared by a number of tests clients.

    Includes a running arti instance, and the ability to get an RPC connection.
    """

    arti_binary: Path
    conf_file: Path
    socket_path: Path
    arti_process: Optional[ArtiProcess]

    def __init__(self, arti_binary: Path, path: Path):
        """
        Create a new TestContext using the arti binary at `arti_binary`,
        storing all of its files at `path`.

        Does not launch arti.
        """
        path = path.absolute()
        conf_file = path.joinpath("arti.toml")
        cache_dir = path.joinpath("cache")
        state_dir = path.joinpath("state")
        socket_path = path.joinpath("arti_rpc.socket")
        unix_connpt_path = path.joinpath("arti_unix_connpt.toml")
        tcp_connpt_path = path.joinpath("arti_tcp_connpt.toml")
        cookie_path = path.joinpath("rpc_cookie.secret")
        socks_port = 15986  # "chosen by fair dice roll. guaranteed to be random."
        rpc_port = 18929

        with open(unix_connpt_path, "w") as f:
            f.write(
                f"""
[connect]
socket = "unix:{socket_path}"
auth = "none"
"""
            )

        with open(tcp_connpt_path, "w") as f:
            f.write(
                f"""
[connect]
socket = "inet:127.0.0.1:{rpc_port}"
auth = {{ cookie = {{ path = "{cookie_path}" }} }}
"""
            )

        is_windows = sys.platform in ["win32", "cygwin"]

        configuration = {
            "rpc": {
                "enable": True,
                "listen": {
                    "user-default": {
                        "enable": False,
                    },
                    "system-default": {
                        "enable": False,
                    },
                    "unix-point": {
                        "enable": not is_windows,
                        "file": str(unix_connpt_path),
                    },
                    "tcp-point": {
                        "file": str(tcp_connpt_path),
                    },
                },
            },
            "storage": {
                "cache_dir": str(cache_dir),
                "state_dir": str(state_dir),
            },
            "proxy": {
                "socks_listen": socks_port,
            },
        }
        with open(conf_file, "wb") as f:
            tomli_w.dump(configuration, f)

        self.arti_binary = arti_binary
        self.conf_file = conf_file
        self.socket_path = socket_path
        if is_windows:
            self.unix_connpt_path = None
        else:
            self.unix_connpt_path = unix_connpt_path
        self.tcp_connpt_path = tcp_connpt_path
        self.cookie_path = cookie_path
        self.rpc_port = rpc_port
        self.arti_process = None

    def launch_arti(self):
        """
        Start a new Arti process, and store it in self.arti_process.
        """
        args = [self.arti_binary, "proxy", "-c", self.conf_file]

        # TODO: Capture the logs from arti somehow.  (As it stands,
        # they just go to stdout, which is iffy.
        self.arti_process = ArtiProcess(subprocess.Popen(args))
        self._wait_for_rpc()

    def open_rpc_connection(self) -> arti_rpc.ArtiRpcConn:
        """
        Open an RPC connection to Arti.
        """
        bld = arti_rpc.ArtiRpcConnBuilder()
        bld.prepend_literal_path(str(self.tcp_connpt_path))
        return bld.connect()

    def arti_process_is_running(self) -> bool:
        """
        Return true if we have launched an arti process,
        and it is still running.
        """
        if self.arti_process is None:
            return False
        return self.arti_process.is_running()

    def _wait_for_rpc(self, timeout: float = 3.0) -> None:
        """
        Wait up to `timeout` seconds until an Arti RPC connection succeeds.

        Raise an exception if it fails.
        """
        interval = 0.1
        waited = 0.0
        for _ in range(math.ceil(timeout / interval)):
            try:
                _ = self.open_rpc_connection()
                print(f"Waited {waited} seconds for Arti RPC to be reachable.")
                return
            except arti_rpc.ArtiRpcError:
                time.sleep(interval)
                waited += interval

        raise FatalException("Arti not reachable after {timeout} seconds.")


class ArtiProcess:
    """
    Wrapper for an Arti process.

    Shuts down the process when dropped.
    """

    process: Optional[subprocess.Popen]

    def __init__(self, process: subprocess.Popen):
        """Wrap a subprocess.Popen as an ArtiProcess."""
        self.process = process

    def is_running(self) -> bool:
        """
        Return true if the process is running.
        """
        return self.process is not None and self.process.poll() is None

    def close(self, gently: bool) -> None:
        """Shut down this process.

        If `gently` is true, start with a SIGINT, and wait a while
        seconds for the process to exit.

        if `gently` is false, or SIGINT fails, terminate the process.
        """
        if self.process is not None:
            if gently and sys.platform != "win32":
                self.process.send_signal(signal.SIGINT)
                try:
                    self.process.wait(10)
                except subprocess.TimeoutExpired:
                    print("Process ignored SIGINT. Terminating")
                    self.process.terminate()
            else:
                self.process.terminate()

            self.process.wait(10)
            self.process = None

    def __del__(self):
        self.close(False)
