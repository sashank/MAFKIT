"""Static APK analysis: archive inspection, manifest parsing, certificate analysis, and capability scanning."""

from __future__ import annotations

import base64
import re
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .model import Finding
from .util import (
    DOMAIN_RE,
    IP_RE,
    URL_RE,
    WS_RE,
    entropy,
    hashes,
    printable_strings,
    run,
    uniq,
    which,
)

if TYPE_CHECKING:
    from .model import Report

SUSPICIOUS_PERMS: dict[str, tuple[str, str, str]] = {
    "android.permission.READ_SMS": (
        "critical",
        "SMS access",
        "Can read SMS/OTP messages.",
    ),
    "android.permission.RECEIVE_SMS": (
        "critical",
        "SMS interception",
        "Can receive incoming SMS.",
    ),
    "android.permission.SEND_SMS": (
        "critical",
        "SMS sending",
        "Can send SMS from the device.",
    ),
    "android.permission.CALL_PHONE": (
        "high",
        "Phone calls",
        "Can initiate calls.",
    ),
    "android.permission.RECORD_AUDIO": (
        "high",
        "Microphone",
        "Can record audio.",
    ),
    "android.permission.CAMERA": (
        "high",
        "Camera",
        "Can use the camera.",
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": (
        "high",
        "Boot persistence",
        "Can restart logic after device reboot.",
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (
        "high",
        "Broad storage access",
        "Can access broad external storage.",
    ),
    "android.permission.REQUEST_DELETE_PACKAGES": (
        "medium",
        "Package deletion",
        "Can request application uninstall/removal.",
    ),
    "android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION": (
        "critical",
        "Screen capture",
        "Supports foreground screen-capture services.",
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "critical",
        "Overlay",
        "Can draw overlays over other applications.",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "high",
        "Package installation",
        "Can request APK installation.",
    ),
}

CAP_PATTERNS: dict[str, list[str]] = {
    "accessibility": [
        "AccessibilityService",
        "onAccessibilityEvent",
        "performGlobalAction",
        "GestureDescription",
        "findAccessibilityNodeInfosByText",
        "findAccessibilityNodeInfosByViewId",
        "canPerformGestures",
        "canRetrieveWindowContent",
    ],
    "sms": [
        "SmsManager",
        "SmsMessage",
        "Telephony$Sms",
        "SEND_SMS",
        "READ_SMS",
        "RECEIVE_SMS",
    ],
    "device_admin": [
        "DeviceAdminReceiver",
        "ADD_DEVICE_ADMIN",
        "BIND_DEVICE_ADMIN",
    ],
    "screen_capture": [
        "MediaProjection",
        "MediaProjectionManager",
        "takeScreenshot",
        "ScreenshotResult",
        "ImageReader",
    ],
    "websocket": [
        "WebSocket",
        "onMessage",
        "ws://",
        "wss://",
    ],
    "shell": [
        "Runtime.exec",
        "ProcessBuilder",
        "___CMD_END___",
        "telnet",
        "ssh",
    ],
    "keylogging": [
        "keylog",
        "keystroke",
        "Keylogger",
    ],
    "camera_mic_privacy_bypass": [
        "camera_mic_icons_enabled",
    ],
    "file_transfer": [
        "upload",
        "download",
        "filedata",
        "savepath",
        "File Finder",
    ],
    "overlay_injection": [
        "injection",
        "ject",
        "overlay",
        "appId",
        "rckey",
    ],
    "persistence": [
        "BOOT_COMPLETED",
        "QUICKBOOT_POWERON",
        "startForegroundService",
    ],
}

MAX_ZIP_ENTRIES = 20_000
MAX_ENTRY_SCAN = 8 * 1024 * 1024
MAX_TOTAL_SCAN = 256 * 1024 * 1024
MAX_ENTRY_FULL = 256 * 1024 * 1024


def _read_prefix(z: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    """Read up to `limit` bytes from a ZIP archive entry."""
    if info.file_size < 0:
        return b''
    want = min(info.file_size, limit)
    with z.open(info, 'r') as fh:
        return fh.read(want)


def safe_zip_read(
    z: zipfile.ZipFile,
    name: str,
    max_bytes: int = MAX_ENTRY_FULL,
) -> bytes:
    """Read full entry data safely while enforcing maximum size limits."""
    info = z.getinfo(name)
    if info.file_size > max_bytes:
        raise ValueError(
            f'ZIP entry {name!r} exceeds forensic read limit ({info.file_size} > {max_bytes} bytes)'
        )
    data = z.read(info)
    if len(data) != info.file_size:
        raise ValueError(f'ZIP entry {name!r} length mismatch')
    return data


class APKAnalyzer:
    """Core static APK analyzer handling container safety, manifest extraction, and indicators."""

    def __init__(self, apk: Path, outdir: Path) -> None:
        self.apk = apk
        self.outdir = outdir
        self.outdir.mkdir(parents=True, exist_ok=True)

    def build_context(self) -> dict[str, Any]:
        """Construct analysis context by safely inspecting ZIP structure and scanning entry strings."""
        try:
            z = zipfile.ZipFile(self.apk)
        except zipfile.BadZipFile as exc:
            raise ValueError(f'Input is not a valid ZIP/APK container: {exc}') from exc

        infos = z.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            z.close()
            raise ValueError(f'APK contains {len(infos)} ZIP entries; safety limit is {MAX_ZIP_ENTRIES}')

        all_strings: list[str] = []
        entries: list[dict[str, Any]] = []
        scan_blobs: list[tuple[str, bytes]] = []
        total_scanned = 0
        warnings: list[str] = []

        for info in infos:
            ratio = (
                (info.file_size / max(1, info.compress_size))
                if info.compress_size
                else float('inf')
                if info.file_size
                else 1.0
            )
            scan_budget = max(0, MAX_TOTAL_SCAN - total_scanned)
            take = min(MAX_ENTRY_SCAN, scan_budget)
            data = b''
            if take:
                try:
                    data = _read_prefix(z, info, take)
                except Exception as exc:
                    warnings.append(f'Could not read {info.filename}: {exc}')
            total_scanned += len(data)

            entries.append({
                "name": info.filename,
                "size": info.file_size,
                "compressed": info.compress_size,
                "compression_ratio": round(ratio, 2) if ratio != float('inf') else 'inf',
                "entropy": round(entropy(data[:2_000_000]), 3),
                "scanned_bytes": len(data),
            })

            if ratio > 1000 and info.file_size > 10 * 1024 * 1024:
                warnings.append(f'Extreme compression ratio for {info.filename}; content scanning was bounded.')

            if data and (
                info.filename.endswith((".dex", ".xml", ".json", ".html", ".js", ".txt", ".so"))
                or info.file_size < 2_000_000
            ):
                all_strings.extend(printable_strings(data))

            if data:
                scan_blobs.append((info.filename, data))

        if total_scanned >= MAX_TOTAL_SCAN:
            warnings.append(f'Total ZIP content scan was capped at {MAX_TOTAL_SCAN} bytes.')

        return {
            "zip": z,
            "entries": entries,
            "all_strings": uniq(all_strings),
            "scan_blobs": scan_blobs,
            "scan_warnings": warnings,
            "outdir": self.outdir,
            "apk": self.apk,
            "safe_zip_read": safe_zip_read,
        }

    def analyze_base(self, report: Report, ctx: dict[str, Any]) -> None:
        """Run base APK metadata, manifest, permission, capability, and IOC extraction."""
        st = self.apk.stat()
        report.hashes = hashes(self.apk)
        report.file_info = {
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "zip_entries": len(ctx["entries"]),
            "high_entropy_entries": [e for e in ctx["entries"] if e["entropy"] >= 7.5][:100],
            "scan_limits": {
                "max_entries": MAX_ZIP_ENTRIES,
                "max_entry_scan_bytes": MAX_ENTRY_SCAN,
                "max_total_scan_bytes": MAX_TOTAL_SCAN,
            },
            "scan_warnings": ctx.get('scan_warnings', []),
        }
        report.limitations.extend(ctx.get('scan_warnings', []))
        report.tools = {
            k: bool(which(k))
            for k in ["jadx", "apktool", "aapt", "apksigner", "keytool"]
        }

        try:
            from androguard.core.apk import APK

            a = APK(str(self.apk))
            report.package = {
                "package_name": a.get_package(),
                "app_name": a.get_app_name(),
                "version_name": a.get_androidversion_name(),
                "version_code": a.get_androidversion_code(),
                "min_sdk": a.get_min_sdk_version(),
                "target_sdk": a.get_target_sdk_version(),
            }
            report.permissions = sorted(a.get_permissions())
            report.components = {
                "activities": sorted(a.get_activities()),
                "services": sorted(a.get_services()),
                "receivers": sorted(a.get_receivers()),
                "providers": sorted(a.get_providers()),
            }
            certs: list[dict[str, Any]] = []
            for c in a.get_certificates():
                try:
                    certs.append({
                        "subject": c.subject.human_friendly,
                        "issuer": c.issuer.human_friendly,
                        "sha256": c.sha256.hex(),
                        "serial": hex(c.serial_number),
                    })
                except Exception:
                    pass
            report.signing = {"certificates": certs}
        except Exception as e:
            report.limitations.append(
                f"Manifest/certificate parsing failed: {type(e).__name__}: {e}"
            )

        strings = ctx["all_strings"]
        joined = "\n".join(strings)
        caps: dict[str, Any] = {}
        for name, pats in CAP_PATTERNS.items():
            hits = [p for p in pats if p.lower() in joined.lower()]
            if hits:
                caps[name] = {
                    "detected": True,
                    "evidence": hits,
                    "basis": "bounded static string/API scan",
                }
        report.capabilities = caps

        for p in report.permissions:
            if p in SUSPICIOUS_PERMS:
                sev, title, interp = SUSPICIOUS_PERMS[p]
                report.findings.append(
                    Finding(sev, "permission", title, [p], interp, 'high')
                )

        cap_meta: dict[str, tuple[str, str, str]] = {
            "accessibility": (
                "critical",
                "Accessibility control",
                "Accessibility APIs are present and can inspect UI or automate gestures "
                "if the service is enabled and the relevant code path executes.",
            ),
            "sms": (
                "critical",
                "SMS manipulation",
                "SMS APIs are present and may support message/OTP access or sending if "
                "permissions/role state permit and the code path executes.",
            ),
            "device_admin": (
                "high",
                "Device administrator",
                "Device-admin APIs are present and can increase persistence/control if activated.",
            ),
            "screen_capture": (
                "critical",
                "Screen capture",
                "MediaProjection/screenshot APIs are present and can support screen observation "
                "when authorized/usable.",
            ),
            "websocket": (
                "high",
                "Persistent remote channel",
                "WebSocket code is present and can support bidirectional communications; "
                "this does not alone prove C2 use.",
            ),
            "shell": (
                "critical",
                "Command execution primitives",
                "Shell/process primitives are present and may allow command execution if invoked.",
            ),
            "keylogging": (
                "critical",
                "Keylogging indicators",
                "Strings/code indicators are consistent with keystroke-capture functionality; "
                "execution requires corroboration.",
            ),
            "camera_mic_privacy_bypass": (
                "critical",
                "Privacy indicator tampering",
                "Code references Android camera/microphone privacy-indicator configuration; "
                "effectiveness depends on OS privileges/version.",
            ),
            "file_transfer": (
                "high",
                "File transfer",
                "Upload/download primitives are present and can support file collection or delivery.",
            ),
            "overlay_injection": (
                "critical",
                "Overlay/injection",
                "Injection/overlay indicators are present and can support deceptive UI or credential collection.",
            ),
            "persistence": (
                "high",
                "Persistence",
                "Boot/start-service indicators are present and can maintain availability if enabled by Android state.",
            ),
        }
        for k, v in caps.items():
            sev, title, interp = cap_meta[k]
            report.findings.append(
                Finding(sev, "capability", title, v["evidence"], interp, "medium")
            )

        urls: list[str] = []
        domains: list[str] = []
        ips: list[str] = []
        evidence: list[dict[str, Any]] = []

        for source, data in ctx.get('scan_blobs', []):
            for kind, rx, enc in [
                ('url', URL_RE, 'utf-8'),
                ('websocket', WS_RE, 'utf-8'),
                ('domain', DOMAIN_RE, 'ascii'),
                ('ipv4', IP_RE, 'ascii'),
            ]:
                for m in rx.findall(data):
                    val = m.decode(enc, 'ignore')
                    if kind in ('url', 'websocket'):
                        urls.append(val)
                    elif kind == 'domain':
                        domains.append(val)
                    else:
                        ips.append(val)
                    if len(evidence) < 5000:
                        evidence.append({
                            'type': kind,
                            'value': val,
                            'source': source,
                            'basis': 'bounded raw-entry scan',
                        })

        report.iocs = {
            "urls": uniq(urls)[:500],
            "domains": uniq(domains)[:500],
            "ipv4": uniq(ips)[:500],
        }
        report.ioc_evidence = evidence

        dec: list[dict[str, Any]] = []
        b64re = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
        for s in strings:
            if len(s) > 2048 or len(s) % 4 or not b64re.match(s):
                continue
            try:
                b = base64.b64decode(s, validate=True)
                t = b.decode("utf-8")
                printable_ratio = sum(
                    ch.isprintable() or ch in '\r\n\t' for ch in t
                ) / max(1, len(t))
                if printable_ratio > 0.9:
                    dec.append({
                        "encoding": "base64",
                        "source": s[:120],
                        "decoded": t[:1000],
                        "confidence": "candidate",
                    })
            except Exception:
                pass
        report.decoded_strings = dec[:500]

    def optional_decompile(self, report: Report) -> None:
        """Attempt external decompilation using JADX and apktool if installed."""
        if which("jadx"):
            target = self.outdir / "jadx"
            code, out = run(
                ["jadx", "-d", str(target), "--show-bad-code", str(self.apk)],
                timeout=180,
            )
            (self.outdir / "jadx.log").write_text(out, errors="replace")
            report.tools["jadx_exit_code"] = code

        if which("apktool"):
            target = self.outdir / "apktool"
            code, out = run(
                ["apktool", "d", "-f", "-o", str(target), str(self.apk)],
                timeout=180,
            )
            (self.outdir / "apktool.log").write_text(out, errors="replace")
            report.tools["apktool_exit_code"] = code
