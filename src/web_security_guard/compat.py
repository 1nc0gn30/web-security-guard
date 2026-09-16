"""Cross-platform compatibility utilities for web-security-guard.

Supports Linux, Termux Android, macOS, and Windows environments.
Provides safe stream encoding, atomic writes, cross-platform path handling,
browser invocation, and platform capability discovery.
"""

from __future__ import annotations

import io
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional, TextIO, Union


def is_termux_environment() -> bool:
    """Detect whether the current process is running inside Termux on Android."""
    if "TERMUX_VERSION" in os.environ:
        return True
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        return True
    if os.path.exists("/data/data/com.termux"):
        return True
    return False


def configure_utf8_streams() -> None:
    """Configure standard I/O streams (stdin, stdout, stderr) to UTF-8 encoding.

    Safely handles detached streams, custom wrappers, and read-only stream states.
    """
    os.environ["PYTHONIOENCODING"] = "utf-8"

    for stream_name in ("stdin", "stdout", "stderr"):
        stream: Optional[Any] = getattr(sys, stream_name, None)
        if stream is None:
            continue

        # Skip if already UTF-8
        enc = getattr(stream, "encoding", None) or ""
        if enc.lower() in ("utf-8", "utf8"):
            continue

        # Try Python 3.7+ reconfigure
        if hasattr(stream, "reconfigure") and callable(stream.reconfigure):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
                continue
            except (io.UnsupportedOperation, AttributeError, ValueError, OSError):
                pass

        # Fallback for streams with buffer attribute
        if hasattr(stream, "buffer") and stream.buffer is not None:
            try:
                line_buffering = getattr(stream, "line_buffering", True)
                new_wrapper = io.TextIOWrapper(
                    stream.buffer,
                    encoding="utf-8",
                    errors="replace",
                    line_buffering=line_buffering,
                )
                setattr(sys, stream_name, new_wrapper)
            except (io.UnsupportedOperation, AttributeError, ValueError, OSError):
                pass


def safe_print(
    *args: Any,
    sep: str = " ",
    end: str = "\n",
    file: Optional[TextIO] = None,
    flush: bool = False,
) -> None:
    """Print to standard output or a designated stream with fallback encoding.

    Guarantees no UnicodeEncodeError will crash execution on legacy terminal consoles.
    """
    target_file = file if file is not None else sys.stdout
    text = sep.join(str(arg) for arg in args) + end

    try:
        if target_file is not None:
            target_file.write(text)
            if flush and hasattr(target_file, "flush"):
                target_file.flush()
    except (UnicodeEncodeError, UnicodeError):
        encoding = getattr(target_file, "encoding", "utf-8") or "utf-8"
        encoded_bytes = text.encode(encoding, errors="replace")
        decoded_text = encoded_bytes.decode(encoding, errors="replace")
        if target_file is not None:
            target_file.write(decoded_text)
            if flush and hasattr(target_file, "flush"):
                target_file.flush()


def atomic_write_text(
    file_path: Union[str, Path],
    content: str,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> Path:
    """Write text to a file atomically via a temporary file and atomic replacement.

    Ensures that partially written files never corrupt destination state.

    Args:
        file_path: Path to the destination file.
        content: Text content to write.
        encoding: Text encoding (default: utf-8).
        errors: Error handling scheme for encoding.

    Returns:
        Path to the written destination file.
    """
    dest_path = resolve_path(file_path)
    dest_dir = dest_path.parent
    dest_dir.mkdir(parents=True, exist_ok=True)

    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        dir=dest_dir,
        delete=False,
        encoding=encoding,
        errors=errors,
        prefix=f".{dest_path.name}.tmp_",
    )
    temp_path = Path(temp_file.name)

    try:
        with temp_file:
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.replace(temp_path, dest_path)
        return dest_path
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def resolve_path(path: Union[str, Path]) -> Path:
    """Resolve user tilde and environment variables to an absolute Path.

    Args:
        path: String or Path object to resolve.

    Returns:
        Absolute resolved Path object.
    """
    raw_str = str(path)
    expanded = os.path.expandvars(os.path.expanduser(raw_str))
    return Path(expanded).resolve()


def to_posix_path(path: Union[str, Path]) -> str:
    """Convert any file system path to standard POSIX forward-slash format.

    Args:
        path: String or Path object.

    Returns:
        String with forward slashes.
    """
    raw_str = str(path)
    # Handle drive letters and backslashes
    return raw_str.replace("\\", "/")


def open_browser(url: str, new: int = 0, autoraise: bool = True) -> bool:
    """Open a URL in the platform default browser with Termux fallback.

    Args:
        url: The web URL to open.
        new: 0 (same window), 1 (new window), 2 (new tab).
        autoraise: Whether to raise the window if supported.

    Returns:
        True if browser invocation succeeded, False otherwise.
    """
    # 1. Termux Android environment
    if is_termux_environment():
        for cmd in ("termux-open-url", "termux-open"):
            exe_path = shutil.which(cmd)
            if exe_path:
                try:
                    res = subprocess.run(
                        [exe_path, url],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                    )
                    if res.returncode == 0:
                        return True
                except (subprocess.SubprocessError, OSError):
                    pass

    # 2. Standard library webbrowser
    try:
        return bool(webbrowser.open(url, new=new, autoraise=autoraise))
    except Exception:
        pass

    # 3. OS fallback launchers
    system_name = platform.system().lower()
    if system_name == "darwin":
        exe = shutil.which("open")
        if exe:
            try:
                return subprocess.run([exe, url], timeout=5).returncode == 0
            except (subprocess.SubprocessError, OSError):
                pass
    elif system_name == "linux":
        exe = shutil.which("xdg-open")
        if exe:
            try:
                return subprocess.run([exe, url], timeout=5).returncode == 0
            except (subprocess.SubprocessError, OSError):
                pass

    return False


def get_platform_info() -> Dict[str, Any]:
    """Retrieve comprehensive operating system and runtime environment metadata.

    Returns:
        Dictionary containing OS flags, platform name, encoding, and Termux state.
    """
    sys_name = platform.system().lower()
    is_linux = sys_name == "linux" or sys.platform.startswith("linux")
    is_macos = sys_name == "darwin" or sys.platform == "darwin"
    is_windows = sys_name == "windows" or sys.platform.startswith("win")
    is_termux = is_termux_environment()

    stdout_enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    stderr_enc = getattr(sys.stderr, "encoding", None) or "utf-8"

    return {
        "system": sys_name,
        "platform": sys.platform,
        "is_linux": is_linux,
        "is_macos": is_macos,
        "is_windows": is_windows,
        "is_termux": is_termux,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "default_encoding": sys.getdefaultencoding(),
        "filesystem_encoding": sys.getfilesystemencoding(),
        "stdout_encoding": stdout_enc,
        "stderr_encoding": stderr_enc,
    }
