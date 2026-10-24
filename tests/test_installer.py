from __future__ import annotations

import io
import os
import subprocess
import zipfile

from core.installer import Installer, ManifestTool, ToolsManifest


def _tool() -> ManifestTool:
    return ManifestTool(
        key="fixture-tool",
        name="Fixture Tool",
        phase=1,
        binary="fixture-tool",
        check_cmd="fixture-tool --version",
        version_cmd="fixture-tool --version",
        install_method="go",
        repo_url="https://example.invalid/fixture",
        access="oss",
        go_module="example.invalid/fixture@latest",
    )


def test_detection_uses_mocked_path_and_skips_version_when_requested(monkeypatch, tmp_path) -> None:
    manifest = ToolsManifest({"fixture-tool": _tool()})
    installer = Installer(manifest, tools_bin=tmp_path / "bin", tools_src=tmp_path / "src")
    monkeypatch.setattr(installer, "which", lambda _binary: "/fake/fixture-tool")

    def unexpected_process(*args, **kwargs):
        raise AssertionError("dry detection must not execute a subprocess")

    monkeypatch.setattr(subprocess, "run", unexpected_process)
    status = installer.detect(_tool(), check_version=False)
    assert status.status == "installed"
    assert status.version == ""
    assert status.path == "/fake/fixture-tool"


def test_ensure_can_report_missing_without_installing(monkeypatch, tmp_path) -> None:
    manifest = ToolsManifest({"fixture-tool": _tool()})
    installer = Installer(
        manifest,
        tools_bin=tmp_path / "bin",
        tools_src=tmp_path / "src",
        auto_install=True,
    )
    monkeypatch.setattr(installer, "which", lambda _binary: None)

    def unexpected_process(*args, **kwargs):
        raise AssertionError("install=False must not execute subprocesses")

    monkeypatch.setattr(subprocess, "run", unexpected_process)
    status, = installer.ensure(["fixture-tool"], install=False)
    assert status.status == "missing (auto-install disabled)"
    assert not (tmp_path / "bin").exists()
    assert not (tmp_path / "src").exists()


def test_release_binary_is_copied_out_of_temporary_extraction(monkeypatch, tmp_path) -> None:
    from core import installer as installer_module

    archive_data = io.BytesIO()
    with zipfile.ZipFile(archive_data, "w") as archive:
        archive.writestr("release/findomain", b"fixture executable")

    class FakeResponse:
        def __init__(self, data: bytes) -> None:
            self.data = io.BytesIO(data)

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            self.data.close()

        def read(self, *args):
            return self.data.read(*args)

    payloads = [
        b'{"assets":[{"name":"findomain-linux-amd64.zip",'
        b'"browser_download_url":"https://fixture.invalid/release.zip"}]}',
        archive_data.getvalue(),
    ]
    monkeypatch.setattr(
        installer_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(payloads.pop(0)),
    )
    tool = ManifestTool(
        key="findomain",
        name="Findomain",
        phase=2,
        binary="findomain",
        check_cmd="findomain --version",
        version_cmd=None,
        install_method="git",
        repo_url="https://github.com/Findomain/Findomain",
        access="oss",
        release_asset=r"findomain-linux.*amd64",
    )
    installer = Installer(
        ToolsManifest({"findomain": tool}),
        tools_bin=tmp_path / "bin",
        tools_src=tmp_path / "src",
    )

    assert installer._install_release(tool, tmp_path / "src")
    installed = tmp_path / "bin" / "findomain"
    assert installed.is_file()
    assert not installed.is_symlink()
    assert installed.read_bytes() == b"fixture executable"
    assert os.access(installed, os.X_OK)
