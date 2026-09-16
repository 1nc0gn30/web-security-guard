"""Unit tests for web_security_guard.compat module."""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from web_security_guard.compat import (
    atomic_write_text,
    configure_utf8_streams,
    get_platform_info,
    is_termux_environment,
    open_browser,
    resolve_path,
    safe_print,
    to_posix_path,
)


def test_is_termux_environment() -> None:
    # 1. When TERMUX_VERSION is in environment
    with patch.dict(os.environ, {"TERMUX_VERSION": "0.118.0"}, clear=False):
        assert is_termux_environment() is True

    # 2. When PREFIX contains com.termux
    with patch.dict(os.environ, {"PREFIX": "/data/data/com.termux/files/usr"}, clear=True):
        assert is_termux_environment() is True

    # 3. When /data/data/com.termux exists
    with patch.dict(os.environ, {}, clear=True), patch("os.path.exists", return_value=True):
        assert is_termux_environment() is True

    # 4. Standard environment (neither)
    with patch.dict(os.environ, {}, clear=True), patch("os.path.exists", return_value=False):
        assert is_termux_environment() is False


def test_configure_utf8_streams() -> None:
    with patch.dict(os.environ, {}, clear=False):
        configure_utf8_streams()
        assert os.environ.get("PYTHONIOENCODING") == "utf-8"

    # Test reconfigure handling
    mock_stdout = MagicMock()
    mock_stdout.encoding = "ascii"
    mock_stdout.reconfigure = MagicMock()
    with patch.object(sys, "stdout", mock_stdout):
        configure_utf8_streams()
        mock_stdout.reconfigure.assert_called_with(encoding="utf-8", errors="replace")


def test_safe_print_normal_and_unicode() -> None:
    buf = io.StringIO()
    safe_print("Test", "Safe", "Print", "🔒", sep="-", end="!\n", file=buf, flush=True)
    assert buf.getvalue() == "Test-Safe-Print-🔒!\n"


def test_safe_print_default_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    safe_print("Standard", "Stdout", "Output")
    captured = capsys.readouterr()
    assert "Standard Stdout Output\n" == captured.out


def test_safe_print_unicode_encode_error() -> None:
    class FailingStream:
        def __init__(self) -> None:
            self.written: list[str] = []
            self.encoding = "ascii"

        def write(self, s: str) -> None:
            # Real terminal behavior: fails if non-ascii character is present
            s.encode("ascii")
            self.written.append(s)

        def flush(self) -> None:
            pass

    failing_stream = FailingStream()
    safe_print("Emoji 🛡️ and unicode \u2714", file=failing_stream, flush=True)  # type: ignore[arg-type]
    assert len(failing_stream.written) == 1
    assert "?" in failing_stream.written[0] or "Emoji" in failing_stream.written[0]


def test_atomic_write_text(tmp_path: Path) -> None:
    target_file = tmp_path / "nested" / "dir" / "secret_config.txt"
    content = "SECURITY_KEY=super_secure_value\nUTF8_EMOJI=🛡️"

    # 1. Write to non-existing path (creates parents)
    res_path = atomic_write_text(target_file, content)
    assert res_path == target_file
    assert target_file.exists()
    assert target_file.read_text(encoding="utf-8") == content

    # 2. Overwrite existing file atomically
    new_content = "UPDATED_KEY=rotated_secure_value\n"
    res_path2 = atomic_write_text(target_file, new_content)
    assert res_path2 == target_file
    assert target_file.read_text(encoding="utf-8") == new_content


def test_atomic_write_text_error_cleanup(tmp_path: Path) -> None:
    target_file = tmp_path / "fail_write.txt"
    with patch("os.fsync", side_effect=OSError("Disk failure simulated")):
        with pytest.raises(OSError, match="Disk failure simulated"):
            atomic_write_text(target_file, "some data")
    # Destination must not exist
    assert not target_file.exists()


def test_resolve_path() -> None:
    p = resolve_path("./src")
    assert p.is_absolute()
    assert p.name == "src" or p.exists()


def test_resolve_path_with_env_var() -> None:
    with patch.dict(os.environ, {"MY_TEST_SECURITY_DIR": "/tmp/security_test"}, clear=False):
        resolved = resolve_path("$MY_TEST_SECURITY_DIR/subfolder")
        assert resolved == Path("/tmp/security_test/subfolder").resolve()


def test_to_posix_path() -> None:
    win_path = "C:\\Users\\admin\\projects\\web-security-guard\\config.json"
    posix = to_posix_path(win_path)
    assert posix == "C:/Users/admin/projects/web-security-guard/config.json"
    assert "\\" not in posix

    unix_path = "/var/log/security.log"
    assert to_posix_path(unix_path) == "/var/log/security.log"


def test_open_browser_termux() -> None:
    with patch("web_security_guard.compat.is_termux_environment", return_value=True), \
         patch("shutil.which", return_value="/data/data/com.termux/files/usr/bin/termux-open-url"), \
         patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        success = open_browser("https://example.com/security")
        assert success is True
        mock_run.assert_called_once()


def test_open_browser_webbrowser_standard() -> None:
    with patch("web_security_guard.compat.is_termux_environment", return_value=False), \
         patch("webbrowser.open", return_value=True) as mock_wb:
        success = open_browser("https://example.com/login")
        assert success is True
        mock_wb.assert_called_with("https://example.com/login", new=0, autoraise=True)


def test_open_browser_darwin_fallback() -> None:
    with patch("web_security_guard.compat.is_termux_environment", return_value=False), \
         patch("webbrowser.open", side_effect=Exception("Browser error")), \
         patch("platform.system", return_value="Darwin"), \
         patch("shutil.which", return_value="/usr/bin/open"), \
         patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        success = open_browser("https://example.com/dashboard")
        assert success is True
        mock_run.assert_called_with(["/usr/bin/open", "https://example.com/dashboard"], timeout=5)


def test_open_browser_linux_fallback() -> None:
    with patch("web_security_guard.compat.is_termux_environment", return_value=False), \
         patch("webbrowser.open", side_effect=Exception("Browser not configured")), \
         patch("platform.system", return_value="Linux"), \
         patch("shutil.which", return_value="/usr/bin/xdg-open"), \
         patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
        success = open_browser("https://example.com/docs")
        assert success is True
        mock_run.assert_called_with(["/usr/bin/xdg-open", "https://example.com/docs"], timeout=5)


def test_open_browser_complete_failure() -> None:
    with patch("web_security_guard.compat.is_termux_environment", return_value=False), \
         patch("webbrowser.open", side_effect=Exception("Browser not configured")), \
         patch("platform.system", return_value="UnknownOS"), \
         patch("shutil.which", return_value=None):
        success = open_browser("https://example.com/fail")
        assert success is False


def test_get_platform_info() -> None:
    info = get_platform_info()
    assert isinstance(info, dict)
    assert "system" in info
    assert "platform" in info
    assert "is_linux" in info
    assert "is_macos" in info
    assert "is_windows" in info
    assert "is_termux" in info
    assert "python_version" in info
    assert "default_encoding" in info
    assert "stdout_encoding" in info
