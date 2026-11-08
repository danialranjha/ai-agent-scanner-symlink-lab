# Selected upstream excerpts, see source-map.json and vendor/LICENSE.
from pathlib import Path
import os
import fnmatch

# Exact value from pinned engine/sanitizer.py line 35.
MAX_FILE_BYTES = 2 * 1024 * 1024

_SYSTEM_DIRS = [
    Path(os.environ.get("WINDIR", r"C:\Windows")),
    Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)"),
    Path(r"C:\ProgramData"),
    Path("/etc"), Path("/usr"), Path("/bin"), Path("/sbin"),
    Path("/System"), Path("/Library"), Path("/private"), Path("/var"),
]

_SENSITIVE_PATTERNS = [
    ".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*",
    "credentials*", "cookies*", "Login Data", "*.sqlite", "*.db",
    "NTDS.dit", "SAM", "SECURITY", "*.kdbx", "*.pfx", "*.p12", "*.wallet",
]

_BINARY_SNIFF_BYTES = 8192

def _is_under(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False

def _is_sensitive(rel: str) -> bool:
    name = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return any(fnmatch.fnmatch(name, pat.lower()) for pat in _SENSITIVE_PATTERNS)

def _read_file_bytes(path: Path) -> bytes:
    """防护⑤/⑥：只读打开 + BOM 感知的二进制嗅探（UTF-16 不误判）+ 单文件上限。"""
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"文件超过单文件上限（{MAX_FILE_BYTES // 1024}KB）：{path}")
    with open(path, "rb") as fh:  # noqa: SIM115 - 显式只读
        data = head = fh.read(_BINARY_SNIFF_BYTES)
        if len(head) == _BINARY_SNIFF_BYTES:
            data = head + fh.read()
    # UTF-16/UTF-32 BOM 优先：其 NUL 字节是编码字节而非二进制标志
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or data[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return data
    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
        raise ValueError(f"二进制文件，跳过：{path.name}")
    return data

def _guard_file(fpath: Path) -> None:
    """file mode 防护（P0-3）：系统目录拒绝 + 敏感文件拒绝，与 dir mode 同口径。"""
    resolved = fpath.resolve()
    for d in _SYSTEM_DIRS:
        try:
            if _is_under(resolved, d.expanduser().resolve()):
                raise ValueError(f"拒绝读取系统目录内文件：{resolved}")
        except OSError:
            continue
    if _is_sensitive(fpath.name):
        raise ValueError(f"敏感文件只报存在、不读取内容：{fpath.name}")
