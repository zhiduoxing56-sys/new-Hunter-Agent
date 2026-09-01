"""Real, disposable AutoPenBench Docker environment management."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class EnvironmentError(RuntimeError):
    """A real container or workstation operation failed."""


def _safe_decode(raw: bytes) -> tuple[str, bool]:
    """Decode subprocess output without ever crashing on arbitrary bytes.

    Returns (text, lossy) where lossy is True when the raw bytes were not
    valid UTF-8 and replacement characters were introduced. The raw bytes are
    never silently dropped: callers must persist the raw artifact alongside.
    """
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), True


@dataclass(frozen=True)
class SessionConfig:
    benchmark_root: Path
    level: str
    category: str
    target: str
    run_dir: Path

    @property
    def compose_files(self) -> tuple[Path, Path]:
        return (
            self.benchmark_root / "benchmark/machines/docker-compose.yml",
            self.benchmark_root
            / f"benchmark/machines/{self.level}/{self.category}/docker-compose.yml",
        )


def config_from_env() -> SessionConfig:
    required = (
        "AUTOPENBENCH_ROOT",
        "AUTOPENBENCH_LEVEL",
        "AUTOPENBENCH_CATEGORY",
        "AUTOPENBENCH_TARGET",
        "AUTOPENBENCH_RUN_DIR",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise EnvironmentError(f"missing AutoPenBench session environment: {', '.join(missing)}")
    return SessionConfig(
        benchmark_root=Path(os.environ["AUTOPENBENCH_ROOT"]).resolve(),
        level=os.environ["AUTOPENBENCH_LEVEL"],
        category=os.environ["AUTOPENBENCH_CATEGORY"],
        target=os.environ["AUTOPENBENCH_TARGET"],
        run_dir=Path(os.environ["AUTOPENBENCH_RUN_DIR"]).resolve(),
    )


class AutoPenBenchSession:
    """Operate one upstream Kali workstation and one vulnerable target.

    Commands always execute in the upstream Kali container (or through its SSH
    client into a target).  The adapter never reads target files from the host.
    """

    def __init__(self, config: SessionConfig) -> None:
        self.config = config
        self.connected: dict[str, dict[str, str | int]] = {}
        self.events_path = config.run_dir / "adapter-tool-events.jsonl"
        self.state_path = config.run_dir / "adapter-session.json"
        self.build_root = config.run_dir / "upstream-machines"
        if self.state_path.exists():
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            connected = value.get("connected", {})
            if isinstance(connected, dict):
                self.connected = connected

    @property
    def _compose(self) -> list[str]:
        command = ["docker", "compose"] if shutil.which("docker") else ["docker-compose"]
        for path in self._compose_files:
            command.extend(("-f", str(path)))
        return command

    @property
    def _compose_files(self) -> tuple[Path, Path]:
        return (
            self.build_root / "docker-compose.yml",
            self.build_root / self.config.level / self.config.category / "docker-compose.yml",
        )

    def _run(
        self, command: list[str], *, timeout: int = 600, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        started = time.time()
        try:
            result = subprocess.run(
                command,
                cwd=self.config.benchmark_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._event("host", command, "", error=f"{type(exc).__name__}: {exc}")
            raise EnvironmentError(f"container command failed to run: {exc}") from exc
        # Raw bytes are captured without text=True so invalid UTF-8 output from
        # a target never raises UnicodeDecodeError inside the MCP tool boundary.
        # The model-facing text is a deterministic safe decode; the raw bytes
        # are persisted for audit and hashed so nothing is silently lost.
        raw = result.stdout
        text, lossy = _safe_decode(raw)
        extra: dict[str, Any] = {
            "exit_code": result.returncode,
            "elapsed_s": time.time() - started,
        }
        if lossy:
            extra["decode_error"] = True
            extra["raw_sha256"] = hashlib.sha256(raw).hexdigest()
            extra["raw_bytes"] = len(raw)
            raw_path = self.config.run_dir / "raw-tool-outputs"
            raw_path.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(started))
            artifact = raw_path / f"raw-{stamp}-{extra['raw_sha256'][:8]}.bin"
            with artifact.open("wb") as stream:
                stream.write(raw)
            extra["raw_artifact"] = str(artifact)
        self._event("host", command, text, **extra)
        if check and result.returncode != 0:
            raise EnvironmentError(
                f"container command exited {result.returncode}: {text[-1000:]}"
            )
        return subprocess.CompletedProcess(
            result.args, result.returncode, text, None
        )

    def _event(self, kind: str, command: list[str] | str, output: str, **extra: Any) -> None:
        self.config.run_dir.mkdir(parents=True, exist_ok=True)
        record = {"at": time.time(), "kind": kind, "command": command, "output": output, **extra}
        with self.events_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def _save(self) -> None:
        self.state_path.write_text(
            json.dumps({"connected": self.connected}, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _prepare_upstream_build_context(self) -> None:
        """Copy and minimally repair stale upstream build metadata per run.

        The upstream pin for Kali's 2025.1 keyring was removed from Kali's
        rolling pool. This disposable copy keeps both upstream and Hunter core
        code untouched.
        """
        source = self.config.benchmark_root / "benchmark/machines"
        if self.build_root.exists():
            shutil.rmtree(self.build_root)
        shutil.copytree(source, self.build_root)
        dockerfile = self.build_root / "kali/Dockerfile"
        # The upstream workstation image already contains the expected Kali
        # tools. Its Dockerfile's subsequent rolling upgrade crosses the t64
        # OpenSSL transition and fails while replacing legacy.so. Preserve the
        # upstream workstation unchanged and omit only that broken upgrade.
        #
        # ``latest`` can predate the Kali rolling archive signing key. Fetch
        # the archive-maintained keyring before refreshing package metadata;
        # otherwise apt accepts its stale image-layer lists after a signature
        # failure, which later produces a misleading package 404.
        dockerfile.write_text(
            """FROM lucagioacchini/kali-linux-headless:latest

USER root

ENV DEBIAN_FRONTEND=noninteractive

RUN rm -rf /var/lib/apt/lists/* \\
    && curl --fail --silent --show-error --location \\
        https://archive.kali.org/archive-keyring.gpg \\
        --output /usr/share/keyrings/kali-archive-keyring.gpg \\
    && apt-get update \\
    && apt-get install -y --no-install-recommends sshpass \\
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /root/scripts
RUN setcap -r /usr/lib/nmap/nmap || true

COPY adapted_exploits/openssl_heartbleed.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb
COPY adapted_exploits/geoserver_unauth_rce_cve_2024_36401.rb /usr/share/metasploit-framework/modules/exploits/multi/http/geoserver_unauth_rce_cve_2024_36401.rb
COPY adapted_exploits/log4shell_scanner.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/http/log4shell_scanner.rb
""",
            encoding="utf-8",
        )
        self._event(
            "lifecycle",
            "prepare_build_context",
            "copied upstream machines; refreshed Kali archive keyring, installed sshpass, skipped broken rolling upgrade",
        )

    def start(self) -> None:
        self._prepare_upstream_build_context()
        for path in self._compose_files:
            if not path.is_file():
                raise EnvironmentError(f"missing upstream compose file: {path}")
        # The upstream files use fixed container names and a fixed subnet.  Tear
        # down only this task category before creating a fresh Kali + target.
        self._run([*self._compose, "down", "--remove-orphans"], timeout=180)
        self._run(
            [*self._compose, "up", "-d", "--build", "kali_master", self.config.target], timeout=900
        )
        self._run(
            ["docker", "exec", "kali_master", "bash", "-lc", "service ssh status"], timeout=45
        )
        self._event("lifecycle", "start", f"kali_master and {self.config.target} started")

    def cleanup(self) -> None:
        try:
            # /root/scripts is a bind mount into the disposable build context.
            # With rootless Docker, files written by Kali can be represented on
            # the host as ``nobody`` and cannot subsequently be unlinked by the
            # invoking user.  Remove only the generated script contents while
            # the container still owns that mount, before compose tears it down.
            try:
                self._run(
                    ["docker", "exec", "kali_master", "bash", "-lc", "rm -rf /root/scripts/*"],
                    timeout=45,
                )
                self._event("lifecycle", "clear_scripts", "removed generated Kali script files")
            except EnvironmentError as exc:
                # A failed build never creates kali_master; compose cleanup
                # below remains necessary in that case.
                self._event("lifecycle", "clear_scripts", "", error=str(exc))
            self._run([*self._compose, "down", "--remove-orphans", "--volumes"], timeout=180)
            self._event("lifecycle", "cleanup", "containers removed")
        except EnvironmentError as exc:
            self._event("lifecycle", "cleanup", "", error=str(exc))
            raise
        finally:
            if self.build_root.exists():
                shutil.rmtree(self.build_root)

    def _kali(self, command: str, *, timeout: int = 90, check: bool = True) -> str:
        result = self._run(
            ["docker", "exec", "kali_master", "bash", "-lc", command],
            timeout=timeout,
            check=check,
        )
        output = result.stdout
        if result.returncode != 0:
            output = f"{output}\n[command exited with status {result.returncode}]"
        self._event("kali_command", command, output, exit_code=result.returncode)
        return output

    def execute_bash(self, machine_ipaddr: str, cmd: str) -> str:
        if machine_ipaddr == "192.168.0.5":
            # A nonzero shell status is normal reconnaissance evidence (for
            # example, grep reports no match). Return it to the agent rather
            # than converting it into a failed MCP invocation.
            return self._kali(cmd, check=False)
        connection = self.connected.get(machine_ipaddr)
        if connection is None:
            return "Before sending a remote command you need to set-up an SSH connection."
        remote = (
            f"sshpass -p {self._quote(str(connection['password']))} ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 -p {int(connection['port'])} "
            f"{self._quote(str(connection['username']))}@{self._quote(machine_ipaddr)} -- bash -lc "
            f"{self._quote(cmd)}"
        )
        return self._kali(remote, check=False)

    @staticmethod
    def _quote(value: str) -> str:
        return "'" + value.replace("'", "'\\\"'\\\"'") + "'"

    def ssh_connect(
        self, ssh_ipaddr: str, ssh_port: int, ssh_username: str, ssh_password: str
    ) -> str:
        command = (
            f"sshpass -p {self._quote(ssh_password)} ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 -p {ssh_port} {self._quote(ssh_username)}@{self._quote(ssh_ipaddr)} true"
        )
        try:
            output = self._kali(command)
        except EnvironmentError as exc:
            return f"SSH connection failed: {exc}"
        self.connected[ssh_ipaddr] = {
            "port": ssh_port,
            "username": ssh_username,
            "password": ssh_password,
        }
        self._save()
        return output or f"SSH connection established to {ssh_ipaddr}:{ssh_port}"

    def write_file(self, content: str, file_name: str) -> str:
        if "/" in file_name or not file_name or file_name in {".", ".."}:
            return "Error: file_name must be a basename."
        payload = base64.b64encode(content.encode()).decode()
        return self._kali(
            f"echo {self._quote(payload)} | base64 -d > /root/scripts/{self._quote(file_name)}"
        )
