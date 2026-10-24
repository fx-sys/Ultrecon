"""Detect-and-auto-install logic for external recon tools.

The manifest (``core/tools_manifest.yaml``) is the single source of truth. No
third-party source is vendored into this repository: binaries are installed by
their upstream package manager or cloned into the gitignored ``tools/src`` and
built locally.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.logging_utils import get_logger
from core.paths import DEFAULT_MANIFEST, PROJECT_ROOT, TOOLS_BIN, TOOLS_SRC, resolve_path
from core.util import safe_filename, truncate

log = get_logger(__name__)

ACCESS_VALUES = {"oss", "free_tier", "manual_only"}
INSTALL_METHODS = {"go", "pipx", "npm", "gem", "git", "apt_fallback", "manual_note"}
KINDS = {"tool", "http_api", "wordlist", "os_utility"}


class ManifestError(ValueError):
    pass


@dataclass
class ManifestTool:
    key: str
    name: str
    phase: int
    binary: str | None
    check_cmd: str | None
    version_cmd: str | None
    install_method: str
    repo_url: str
    access: str
    kind: str = "tool"
    description: str = ""
    notes: str = ""
    go_module: str | None = None
    pipx_package: str | None = None
    npm_package: str | None = None
    gem_package: str | None = None
    apt_package: str | None = None
    git_url: str | None = None
    build: str | None = None
    build_command: str | None = None
    binary_path: str | None = None
    release_asset: str | None = None
    auto_install: bool = True
    active: bool = False
    default_enabled: bool = True
    api_key_env: str | None = None
    path: str | None = None

    @classmethod
    def from_dict(cls, key: str, value: dict[str, Any]) -> ManifestTool:
        if not isinstance(value, dict):
            raise ManifestError(f"tool {key!r} must be a mapping")
        missing = [field for field in ("name", "phase", "install_method", "access") if field not in value]
        if missing:
            raise ManifestError(f"tool {key!r} missing {', '.join(missing)}")
        return cls(
            key=key,
            name=str(value.get("name")),
            phase=int(value.get("phase", 0)),
            binary=value.get("binary"),
            check_cmd=value.get("check_cmd"),
            version_cmd=value.get("version_cmd"),
            install_method=str(value.get("install_method")),
            repo_url=str(value.get("repo_url") or ""),
            access=str(value.get("access")),
            kind=str(value.get("kind", "tool")),
            description=str(value.get("description", "")),
            notes=str(value.get("notes", "")),
            go_module=value.get("go_module"),
            pipx_package=value.get("pipx_package"),
            npm_package=value.get("npm_package"),
            gem_package=value.get("gem_package"),
            apt_package=value.get("apt_package"),
            git_url=value.get("git_url"),
            build=value.get("build"),
            build_command=value.get("build_command"),
            binary_path=value.get("binary_path"),
            release_asset=value.get("release_asset"),
            auto_install=bool(value.get("auto_install", True)),
            active=bool(value.get("active", False)),
            default_enabled=bool(value.get("default_enabled", True)),
            api_key_env=value.get("api_key_env"),
            path=value.get("path"),
        )

    @property
    def requires_binary(self) -> bool:
        return self.kind in {"tool", "os_utility"} and bool(self.binary)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v not in (None, "", [], False)}


class ToolsManifest:
    def __init__(self, tools: dict[str, ManifestTool], path: Path | None = None) -> None:
        self.tools = tools
        self.path = path

    @classmethod
    def load(cls, path: str | Path | None = None) -> ToolsManifest:
        manifest_path = Path(path).expanduser() if path else DEFAULT_MANIFEST
        try:
            raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
        except FileNotFoundError as exc:
            raise ManifestError(f"manifest not found: {manifest_path}") from exc
        except (OSError, yaml.YAMLError) as exc:
            raise ManifestError(f"cannot read manifest {manifest_path}: {exc}") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("tools"), dict):
            raise ManifestError("manifest must contain a top-level 'tools' mapping")
        tools: dict[str, ManifestTool] = {}
        for key, value in raw["tools"].items():
            tools[str(key)] = ManifestTool.from_dict(str(key), value)
        manifest = cls(tools, manifest_path)
        manifest.validate()
        return manifest

    def validate(self) -> None:
        errors: list[str] = []
        for key, tool in self.tools.items():
            if tool.access not in ACCESS_VALUES:
                errors.append(f"{key}: access must be one of {sorted(ACCESS_VALUES)}")
            if tool.install_method not in INSTALL_METHODS:
                errors.append(f"{key}: install_method must be one of {sorted(INSTALL_METHODS)}")
            if tool.kind not in KINDS:
                errors.append(f"{key}: kind must be one of {sorted(KINDS)}")
            if tool.install_method == "go" and not tool.go_module:
                errors.append(f"{key}: go install requires go_module")
            if tool.install_method == "pipx" and not tool.pipx_package:
                errors.append(f"{key}: pipx install requires pipx_package")
            if tool.install_method == "npm" and not tool.npm_package:
                errors.append(f"{key}: npm install requires npm_package")
            if tool.install_method == "gem" and not tool.gem_package:
                errors.append(f"{key}: gem install requires gem_package")
            if tool.install_method == "apt_fallback" and not tool.apt_package:
                errors.append(f"{key}: apt_fallback requires apt_package")
            if tool.requires_binary and not tool.check_cmd:
                errors.append(f"{key}: tool with a binary requires check_cmd")
            if tool.kind == "wordlist" and not tool.path:
                errors.append(f"{key}: wordlist requires path")
            if not 1 <= tool.phase <= 17:
                errors.append(f"{key}: phase must be 1..17")
        duplicate_binaries: dict[str, list[str]] = {}
        for key, tool in self.tools.items():
            if tool.binary:
                duplicate_binaries.setdefault(tool.binary, []).append(key)
        for binary, keys in duplicate_binaries.items():
            if len(keys) > 1:
                errors.append(f"duplicate binary {binary!r} declared by {keys}")
        if errors:
            raise ManifestError("invalid tools manifest:\n  " + "\n  ".join(errors))

    def get(self, key: str) -> ManifestTool | None:
        return self.tools.get(key)

    def by_binary(self, binary: str) -> ManifestTool | None:
        for tool in self.tools.values():
            if tool.binary == binary:
                return tool
        return None

    def resolve(self, names: list[str] | tuple[str, ...]) -> list[ManifestTool]:
        """Resolve a mix of manifest keys and binary names."""
        resolved: list[ManifestTool] = []
        seen: set[str] = set()
        for name in names:
            tool = self.get(name) or self.by_binary(name)
            if tool is None:
                log.debug("No manifest entry for %s", name)
                continue
            if tool.key not in seen:
                seen.add(tool.key)
                resolved.append(tool)
        return resolved

    def for_phases(self, phases: list[int]) -> list[ManifestTool]:
        return sorted(
            (t for t in self.tools.values() if t.phase in phases),
            key=lambda t: (t.phase, t.name.lower()),
        )


@dataclass
class ToolStatus:
    key: str
    name: str
    binary: str | None
    method: str
    status: str
    version: str = ""
    path: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "binary": self.binary,
            "method": self.method,
            "status": self.status,
            "version": self.version,
            "path": self.path,
            "detail": self.detail,
        }


@dataclass
class Installer:
    manifest: ToolsManifest
    tools_bin: Path = TOOLS_BIN
    tools_src: Path = TOOLS_SRC
    never_install: set[str] = field(default_factory=set)
    auto_install: bool = True
    timeout: float = 900

    # -- discovery -------------------------------------------------------
    def which(self, binary: str | None) -> str | None:
        if not binary:
            return None
        local = self.tools_bin / binary
        if local.is_file() and os.access(local, os.X_OK):
            return str(local)
        extra_paths = [str(Path.home() / ".local" / "bin"), str(Path.home() / "go" / "bin")]
        extra_paths.append(os.environ.get("PATH", ""))
        found = shutil.which(binary, path=os.pathsep.join(extra_paths))
        if not found:
            venv_bin = Path(sys.executable).parent / binary
            if venv_bin.is_file() and os.access(venv_bin, os.X_OK):
                return str(venv_bin)
        return found

    def _wordlist_path(self, tool: ManifestTool) -> Path | None:
        if not tool.path:
            return None
        return resolve_path(tool.path, base=PROJECT_ROOT)

    def _version(self, tool: ManifestTool, path: str | None) -> str:
        command = tool.version_cmd or tool.check_cmd
        if not command or not path:
            return ""
        try:
            argv = shlex.split(command)
        except ValueError:
            return ""
        if argv and argv[0] == tool.binary:
            argv[0] = path
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                env={**os.environ, "NO_COLOR": "1", "PAGER": "cat"},
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        text = (proc.stdout or "") + " " + (proc.stderr or "")
        for line in text.splitlines():
            line = line.strip()
            if line:
                return truncate(re.sub(r"\s+", " ", line), 100)
        return ""

    def detect(self, tool: ManifestTool, *, check_version: bool = True) -> ToolStatus:
        if tool.kind == "http_api":
            return ToolStatus(
                tool.key, tool.name, None, "builtin", "builtin", detail="HTTP API / built-in source"
            )
        if tool.kind == "wordlist":
            path = self._wordlist_path(tool)
            if path and path.exists():
                detail = "submodule present" if path.is_dir() else "file present"
                return ToolStatus(
                    tool.key, tool.name, None, tool.install_method, "present", path=str(path),
                    detail=detail
                )
            return ToolStatus(
                tool.key,
                tool.name,
                None,
                tool.install_method,
                "missing",
                detail="run: git submodule update --init --recursive",
            )
        if tool.install_method == "manual_note" or tool.access == "manual_only":
            return ToolStatus(
                tool.key,
                tool.name,
                tool.binary,
                tool.install_method,
                "manual",
                detail=tool.notes or "manual installation only",
            )
        path = self.which(tool.binary)
        if path:
            return ToolStatus(
                tool.key,
                tool.name,
                tool.binary,
                tool.install_method,
                "installed",
                version=self._version(tool, path) if check_version else "",
                path=path,
            )
        return ToolStatus(
            tool.key,
            tool.name,
            tool.binary,
            tool.install_method,
            "missing",
            detail=tool.notes or "",
        )

    def detect_binaries(
        self,
        names: list[str] | tuple[str, ...],
        *,
        check_version: bool = True,
    ) -> list[ToolStatus]:
        return [
            self.detect(tool, check_version=check_version)
            for tool in self.manifest.resolve(list(names))
        ]

    # -- install ---------------------------------------------------------
    def ensure(
        self,
        names: list[str] | tuple[str, ...],
        *,
        install: bool | None = None,
        report_all: bool = False,
    ) -> list[ToolStatus]:
        tools = self.manifest.resolve(list(names))
        if report_all:
            tools = sorted(self.manifest.tools.values(), key=lambda t: (t.phase, t.name.lower()))
        do_install = self.auto_install if install is None else install
        statuses: list[ToolStatus] = []
        for tool in tools:
            status = self.detect(tool)
            if status.status in {"installed", "present", "builtin", "manual"}:
                statuses.append(status)
                continue
            if not tool.requires_binary and tool.kind != "wordlist":
                statuses.append(status)
                continue
            if tool.kind == "wordlist":
                status.detail = "wordlist missing; install git submodules (.gitmodules)"
                statuses.append(status)
                continue
            if not do_install:
                status.status = "missing (auto-install disabled)"
                statuses.append(status)
                continue
            if tool.key in self.never_install or not tool.auto_install:
                status.status = "skipped"
                status.detail = (
                    tool.notes or "auto-install disabled for this tool; install it manually"
                )
                statuses.append(status)
                continue
            installed = self.install_tool(tool)
            status = self.detect(tool) if installed else status
            if installed and status.status == "installed":
                log.info("Installed %s", tool.name)
            elif not installed:
                status.status = "failed"
                status.detail = status.detail or "installation failed; continuing without it"
                log.warning("Could not install %s; phase will continue without it", tool.name)
            statuses.append(status)
        return statuses

    def _run(
        self,
        command: list[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        log.debug("installer exec: %s", " ".join(command))
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout or self.timeout,
            check=False,
        )

    def install_tool(self, tool: ManifestTool) -> bool:
        method = tool.install_method
        try:
            if method == "go":
                return self._install_go(tool)
            if method == "pipx":
                return self._install_pipx(tool)
            if method == "npm":
                return self._install_npm(tool)
            if method == "gem":
                return self._install_gem(tool)
            if method == "apt_fallback":
                return self._install_apt(tool)
            if method == "git":
                return self._install_git(tool)
            log.info("%s needs manual installation: %s", tool.name, tool.notes or tool.repo_url)
            return False
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("Installer error for %s: %s", tool.name, exc)
            return False

    def _install_go(self, tool: ManifestTool) -> bool:
        self.tools_bin.mkdir(parents=True, exist_ok=True)
        if not shutil.which("go"):
            log.warning(
                "Go toolchain not found; cannot install %s. See https://go.dev/dl/", tool.name
            )
            return False
        env = os.environ.copy()
        env["GOBIN"] = str(self.tools_bin)
        env.setdefault("GOFLAGS", "-mod=mod")
        module = tool.go_module or ""
        proc = self._run(["go", "install", f"{module}@latest"], env=env)
        if proc.returncode != 0:
            log.warning(
                "go install %s failed: %s",
                module,
                truncate((proc.stderr or proc.stdout).strip(), 300),
            )
            return False
        return bool(self.which(tool.binary))

    def _install_pipx(self, tool: ManifestTool) -> bool:
        if not shutil.which("pipx"):
            log.warning("pipx not found; cannot install %s", tool.name)
            return False
        spec = tool.pipx_package or tool.repo_url
        proc = self._run(["pipx", "install", str(spec)])
        if proc.returncode != 0:
            log.warning(
                "pipx install %s failed: %s",
                spec,
                truncate((proc.stderr or proc.stdout).strip(), 300),
            )
            return False
        return bool(self.which(tool.binary))

    def _install_npm(self, tool: ManifestTool) -> bool:
        if not shutil.which("npm"):
            log.warning("npm not found; cannot install %s", tool.name)
            return False
        spec = tool.npm_package or tool.repo_url
        proc = self._run(["npm", "install", "-g", str(spec)])
        if proc.returncode != 0:
            log.warning(
                "npm install -g %s failed: %s",
                spec,
                truncate((proc.stderr or proc.stdout).strip(), 300),
            )
            return False
        return bool(self.which(tool.binary))

    def _install_gem(self, tool: ManifestTool) -> bool:
        if not shutil.which("gem"):
            log.warning("gem not found; cannot install %s", tool.name)
            return False
        spec = tool.gem_package or tool.repo_url
        proc = self._run(["gem", "install", "--user-install", str(spec)])
        if proc.returncode != 0:
            log.warning("gem install %s failed: %s", spec, truncate(proc.stderr, 300))
            return False
        return bool(self.which(tool.binary))

    def _install_apt(self, tool: ManifestTool) -> bool:
        package = tool.apt_package or tool.binary
        if sys.platform == "darwin" and shutil.which("brew"):
            proc = self._run(["brew", "install", str(package)])
        elif shutil.which("apt-get"):
            proc = self._run(["apt-get", "install", "-y", str(package)])
        else:
            log.info(
                "No supported package manager for %s; install manually: %s",
                tool.name,
                tool.repo_url or tool.notes,
            )
            return False
        if proc.returncode != 0:
            hint = f"sudo apt-get install -y {package}" if shutil.which("apt-get") else f"brew install {package}"
            log.warning(
                "Package install for %s failed (try: %s): %s",
                tool.name,
                hint,
                truncate((proc.stderr or proc.stdout).strip(), 300),
            )
            return False
        return bool(self.which(tool.binary))

    # -- git builds ------------------------------------------------------
    def _clone(self, tool: ManifestTool) -> Path | None:
        self.tools_src.mkdir(parents=True, exist_ok=True)
        target = self.tools_src / safe_filename(tool.key)
        if target.exists():
            return target
        url = tool.git_url or tool.repo_url
        if not url:
            return None
        proc = self._run(["git", "clone", "--depth", "1", url, str(target)])
        if proc.returncode != 0:
            log.warning("git clone for %s failed: %s", tool.name, truncate(proc.stderr, 300))
            return None
        return target

    def _install_git(self, tool: ManifestTool) -> bool:
        repo = self._clone(tool)
        if repo is None:
            return False
        build = (tool.build or "none").lower()
        if build == "make":
            proc = self._run(["make", "-j2"], cwd=repo)
            if proc.returncode != 0:
                log.warning("make for %s failed: %s", tool.name, truncate(proc.stderr, 300))
                return False
        elif build == "cargo":
            if not shutil.which("cargo"):
                log.warning("cargo not found; cannot build %s", tool.name)
                return False
            proc = self._run(["cargo", "build", "--release"], cwd=repo)
            if proc.returncode != 0:
                log.warning("cargo build for %s failed: %s", tool.name, truncate(proc.stderr, 300))
                return False
            candidate = repo / "target" / "release" / (tool.binary or "")
            if candidate.is_file():
                self._link(candidate, tool.binary or tool.key)
                return True
        elif build == "pip":
            proc = self._run([sys.executable, "-m", "pip", "install", "-e", "."], cwd=repo)
            if proc.returncode != 0:
                log.warning("pip build for %s failed: %s", tool.name, truncate(proc.stderr, 300))
                return False
        elif build == "prebuilt":
            if not self._install_release(tool, repo):
                return False
        elif build == "custom":
            if not tool.build_command:
                return False
            proc = self._run(shlex.split(tool.build_command), cwd=repo)
            if proc.returncode != 0:
                log.warning("build command for %s failed: %s", tool.name, truncate(proc.stderr, 300))
                return False
        elif build == "install_script":
            if not tool.auto_install:
                log.info("Skipping installer script for %s; install manually", tool.name)
                return False
            proc = self._run(["bash", "install.sh"], cwd=repo)
            if proc.returncode != 0:
                return False
        # perl/none: no build step.
        return self._link_from_repo(tool, repo)

    def _install_release(self, tool: ManifestTool, repo: Path) -> bool:
        repo_url = (tool.git_url or tool.repo_url).rstrip("/")
        match = re.search(r"github\.com/([^/]+/[^/]+?)(?:\.git)?$", repo_url)
        if not match:
            return False
        api = f"https://api.github.com/repos/{match.group(1)}/releases/latest"
        try:
            req = urllib.request.Request(api, headers={"User-Agent": "Ultrecon-installer"})
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = json.load(response)
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            log.warning("Could not query release for %s: %s", tool.name, exc)
            return False
        assets = payload.get("assets") or []
        pattern = re.compile(tool.release_asset or r"(linux|Linux).*(amd64|x86_64)", re.I)
        asset = next((a for a in assets if pattern.search(str(a.get("name", "")))), None)
        if not asset:
            log.warning("No matching release asset for %s", tool.name)
            return False
        with tempfile.TemporaryDirectory(prefix="ultrecon-release-") as tmp:
            archive = Path(tmp) / str(asset["name"])
            try:
                req = urllib.request.Request(
                    str(asset["browser_download_url"]),
                    headers={"User-Agent": "Ultrecon-installer"},
                )
                with urllib.request.urlopen(req, timeout=120) as response, archive.open("wb") as out:
                    shutil.copyfileobj(response, out)
                extracted = Path(tmp) / "extracted"
                extracted.mkdir()
                if archive.suffix == ".zip" or archive.name.endswith(".zip"):
                    with zipfile.ZipFile(archive) as zf:
                        zf.extractall(extracted)
                elif archive.name.endswith((".tar.gz", ".tgz")):
                    with tarfile.open(archive) as tf:
                        tf.extractall(extracted, filter="data")
                else:
                    shutil.copy(archive, extracted / (tool.binary or tool.key))
                found = next(
                    (
                        p
                        for p in extracted.rglob(tool.binary or tool.key)
                        if p.is_file() and not p.is_symlink()
                    ),
                    None,
                )
                if not found:
                    return False
                found.chmod(0o755)
                return self._copy_to_tools_bin(found, tool.binary or tool.key)
            except (urllib.error.URLError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
                log.warning("Release download for %s failed: %s", tool.name, exc)
                return False

    def _link_from_repo(self, tool: ManifestTool, repo: Path) -> bool:
        if tool.binary_path:
            candidate = repo / tool.binary_path
            if candidate.is_file():
                return self._link(candidate, tool.binary or tool.key)
        if tool.binary:
            candidate = repo / tool.binary
            if candidate.is_file():
                return self._link(candidate, tool.binary)
            for path in repo.rglob(tool.binary):
                if path.is_file() and path.stat().st_size > 0:
                    return self._link(path, tool.binary)
        log.warning("Could not find built binary for %s in %s", tool.name, repo)
        return False

    def _link(self, source: Path, name: str) -> bool:
        self.tools_bin.mkdir(parents=True, exist_ok=True)
        target = self.tools_bin / name
        try:
            source.chmod(source.stat().st_mode | 0o111)
            if target.exists() or target.is_symlink():
                target.unlink()
            target.symlink_to(source.resolve())
            return True
        except OSError as exc:
            log.warning("Could not link %s: %s", source, exc)
            return False

    def _copy_to_tools_bin(self, source: Path, name: str) -> bool:
        """Copy a release binary out of its temporary extraction directory."""
        self.tools_bin.mkdir(parents=True, exist_ok=True)
        target = self.tools_bin / name
        staged: Path | None = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=f".{safe_filename(name)}-", dir=self.tools_bin)
            os.close(fd)
            staged = Path(temp_name)
            shutil.copy2(source, staged)
            staged.chmod(source.stat().st_mode | 0o111)
            os.replace(staged, target)
            return True
        except OSError as exc:
            log.warning("Could not copy release binary %s: %s", source, exc)
            return False
        finally:
            if staged is not None:
                try:
                    staged.unlink(missing_ok=True)
                except OSError:
                    pass

    # -- update ----------------------------------------------------------
    def update(self, names: list[str] | tuple[str, ...] | None = None) -> list[ToolStatus]:
        tools = (
            sorted(self.manifest.tools.values(), key=lambda t: (t.phase, t.name.lower()))
            if names is None
            else self.manifest.resolve(list(names))
        )
        results: list[ToolStatus] = []
        for tool in tools:
            status = self.detect(tool)
            if status.status not in {"installed", "present"}:
                results.append(status)
                continue
            try:
                success = False
                detail = ""
                if tool.install_method == "go":
                    success = self._install_go(tool)
                elif tool.install_method == "pipx":
                    package = tool.pipx_package or tool.repo_url
                    proc = self._run(["pipx", "upgrade", str(package)])
                    success = proc.returncode == 0
                    detail = truncate((proc.stderr or proc.stdout).strip(), 200)
                elif tool.install_method == "npm":
                    package = tool.npm_package or tool.repo_url
                    proc = self._run(["npm", "install", "-g", f"{package}@latest"])
                    success = proc.returncode == 0
                    detail = truncate((proc.stderr or proc.stdout).strip(), 200)
                elif tool.install_method == "gem":
                    package = tool.gem_package or tool.repo_url
                    proc = self._run(["gem", "update", "--user-install", str(package)])
                    success = proc.returncode == 0
                    detail = truncate((proc.stderr or proc.stdout).strip(), 200)
                elif tool.install_method == "apt_fallback":
                    success, detail = self._update_system_package(tool)
                elif tool.install_method == "git":
                    repo = self.tools_src / safe_filename(tool.key)
                    if repo.is_dir():
                        pulled = self._run(["git", "pull", "--ff-only"], cwd=repo)
                        if pulled.returncode == 0:
                            success = self._install_git(tool)
                        else:
                            detail = truncate((pulled.stderr or pulled.stdout).strip(), 200)
                    else:
                        detail = "installed outside tools/src; update it with its source package manager"
                else:
                    detail = f"manual update required (method: {tool.install_method})"

                updated = self.detect(tool)
                if success and updated.status == "installed":
                    updated.status = "updated"
                else:
                    updated.status = "update-failed"
                    updated.detail = detail or "update command failed or binary was not refreshed"
                results.append(updated)
            except (OSError, subprocess.TimeoutExpired) as exc:
                status.status = "update-failed"
                status.detail = truncate(str(exc), 200)
                results.append(status)
        return results

    def _update_system_package(self, tool: ManifestTool) -> tuple[bool, str]:
        package = tool.apt_package or tool.binary
        if not package:
            return False, "system package name is not configured"
        if sys.platform == "darwin" and shutil.which("brew"):
            proc = self._run(["brew", "upgrade", str(package)])
        elif shutil.which("apt-get"):
            refreshed = self._run(["apt-get", "update"])
            if refreshed.returncode != 0:
                return False, truncate((refreshed.stderr or refreshed.stdout).strip(), 200)
            proc = self._run(["apt-get", "install", "--only-upgrade", "-y", str(package)])
        else:
            return False, "no supported package manager; update this tool manually"
        detail = truncate((proc.stderr or proc.stdout).strip(), 200)
        return proc.returncode == 0, detail

    # -- output ----------------------------------------------------------
    @staticmethod
    def format_table(statuses: list[ToolStatus]) -> str:
        headers = ("Tool", "Binary", "Method", "Status", "Version")
        rows = [
            (
                truncate(s.name, 28),
                s.binary or "-",
                s.method,
                s.status,
                truncate(s.version, 34),
            )
            for s in statuses
        ]
        widths = [len(h) for h in headers]
        for row in rows:
            widths = [max(w, len(str(cell))) for w, cell in zip(widths, row, strict=True)]
        lines = [
            "  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)),
            "  ".join("-" * w for w in widths),
        ]
        for row in rows:
            lines.append(
                "  ".join(str(c).ljust(w) for c, w in zip(row, widths, strict=True))
            )
        return "\n".join(lines)


def installer_from_config(config: dict[str, Any], *, install: bool | None = None) -> Installer:
    install_cfg = config.get("install") or {}
    manifest = ToolsManifest.load()
    never = set(install_cfg.get("never_install") or [])
    auto = bool(install_cfg.get("auto", True)) if install is None else bool(install)
    return Installer(
        manifest=manifest,
        never_install=never,
        auto_install=auto,
        timeout=float(install_cfg.get("timeout", 900)),
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Inspect or install Ultrecon tool dependencies")
    parser.add_argument("--check", action="store_true", help="detect tools and print a table")
    parser.add_argument("--install", action="store_true", help="install missing tools")
    parser.add_argument("--update", action="store_true", help="update installed tools")
    parser.add_argument("--phase", action="append", type=int, help="limit to a phase")
    parser.add_argument("--tool", action="append", help="limit to a manifest key or binary")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    from core.logging_utils import setup_logging

    setup_logging(args.verbose)
    manifest = ToolsManifest.load()
    installer = Installer(manifest)
    names = args.tool or []
    if args.phase:
        names = [t.key for t in manifest.for_phases(args.phase)]
    if args.update:
        statuses = installer.update(names or None)
    elif args.install:
        statuses = installer.ensure(names, install=True) if names else installer.ensure([], install=True, report_all=True)
    else:
        statuses = installer.ensure(names, install=False) if names else installer.ensure([], install=False, report_all=True)
    print(installer.format_table(statuses))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
