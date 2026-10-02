# Base APK Behavior Report

## Scope

This report summarizes the static analysis of:

`android-investigation/cinder/jadx-output/sources/base.apk`

The APK was not installed or executed. Conclusions describe capabilities and code indicators, not confirmed runtime activity or operator identity.

## Executive Assessment

The APK is **high risk** and strongly consistent with a remote-access and monitoring trojan. The combination of accessibility control, screen capture, SMS access, device-admin activation, boot persistence, concealed code, background services, and WebSocket indicators is substantially broader than expected for a normal courier application.

Static evidence does not, by itself, prove that every capability is reachable or that the APK was used maliciously. The packed/native loading layer also limits visibility into the complete implementation.

## Sample Identity

- Package: `cinder.yonder.nature`
- Application label: `Courier Service`
- Version: `50.164.125 llxsgaulbwruzk`
- Target SDK: 36
- Minimum SDK: 14
- DEX files: 4
- Restored methods: 10,750
- Candidate repeating-XOR strings: 4,046
- SHA-256: `dd373a6c97d919fb41d41dd4a82a13c7de261178571ce0e6560bbbb47da14182`
- SHA-1: `19218c1d221ad15d7cab2561c7c6a469fe0ced0f`
- MD5: `d54a6aa258ef1265ad6faac3afe41da2`

## Declared Permissions

The manifest requests:

- `INTERNET`
- `ACCESS_NETWORK_STATE`
- `WAKE_LOCK`
- `RECEIVE_BOOT_COMPLETED`
- `FOREGROUND_SERVICE`
- `FOREGROUND_SERVICE_DATA_SYNC`
- `FOREGROUND_SERVICE_MEDIA_PROJECTION`
- `MANAGE_EXTERNAL_STORAGE`
- `READ_EXTERNAL_STORAGE`
- `WRITE_EXTERNAL_STORAGE`
- `READ_SMS`
- `CALL_PHONE`
- `CAMERA`
- `RECORD_AUDIO`
- `REQUEST_DELETE_PACKAGES`
- `POST_NOTIFICATIONS`
- `SET_ALARM`

This is a broad privilege set covering communications, media capture, storage, persistence, and network activity.

## Observed Behaviors

### Accessibility control

The APK declares an accessibility service with `BIND_ACCESSIBILITY_SERVICE`. Its configuration enables:

- All accessibility event types
- Interactive-window retrieval
- Window-content retrieval
- View-ID reporting
- Gesture execution
- Inclusion of views that are normally unimportant

This can allow the application to inspect other applications, automate taps and gestures, interact with dialogs, and potentially collect credentials or one-time codes.

Evidence includes:

- `AccessibilityService`
- `onAccessibilityEvent`
- `performGlobalAction`
- `GestureDescription`
- `findAccessibilityNodeInfosByText`
- `findAccessibilityNodeInfosByViewId`
- `canRetrieveWindowContent`
- `canPerformGestures`

Configuration: `android-investigation/cinder/jadx-output/resources/res/xml/xbvkxyar.xml`

### Screen capture

The manifest includes a media-projection foreground service and the analysis recovered:

- `MediaProjection`
- `MediaProjectionManager`
- `ImageReader`
- `takeScreenshot`
- `ScreenshotResult`
- `iScreenCap`
- `livescreen`

This could support remote screen viewing or screenshot collection after the user grants Android screen-capture authorization.

### SMS and phone activity

The APK requests `READ_SMS` and `CALL_PHONE`. Recovered strings and API references include:

- `SmsManager`
- `SmsMessage`
- `Telephony$Sms`
- `SMS`
- `SMSCALLS`
- `SMSCALLS/`
- `android.app.role.SMS`
- `smsto`
- `RESPOND_VIA_MESSAGE phone=`

This indicates possible SMS reading, SMS handling, and phone-call functionality, subject to Android permission and role state.

### Device administration and deceptive activation

The APK contains a device-admin activation flow using:

- `android.app.action.ADD_DEVICE_ADMIN`
- `android.app.extra.DEVICE_ADMIN`
- `android.app.extra.ADD_EXPLANATION`
- `DeviceAdminReceiver`

Recovered UI text includes:

> Click on Activate button to secure your application.

This may be an attempt to persuade a user to grant device-admin privileges, which can increase persistence and control.

### Persistence and background operation

The APK registers a boot receiver for:

- `BOOT_COMPLETED`
- `QUICKBOOT_POWERON`
- HTC quick boot
- Reboot
- Shutdown

It also reacts to power and battery state changes. The manifest declares multiple enabled services, including data-sync and media-projection foreground services. These components could restart or maintain operation after boot, power events, or application exit.

### Lock-screen and concealed UI

Several activities are configured with combinations of:

- `showWhenLocked`
- `showOnLockScreen`
- `turnScreenOn`
- `excludeFromRecents`
- `noHistory`
- `singleTask`
- `singleInstance`

Notable labels and class names include `Lock`, `Alerts`, `Update`, and `View`. Recovered indicators include `PatternUnlock`, `lock`, `screen`, and `onPause: Detected screen off!`.

These settings can support deceptive prompts, lock-screen presentation, hidden activities, or control of the visible device state.

### Network and remote-control indicators

Recovered WebSocket indicators include:

- `WebSocket`
- `onMessage`
- `WebSocket opened`
- `WebSocket failure`
- `Closing WebSocket`
- `Max WebSocket retries reached, not reconnecting`

The static IOC scan found:

`ws://127.0.0.1:8080/`

No definite external command-and-control domain was recovered. This may be because endpoints are constructed at runtime, encrypted, downloaded later, or hidden in the packed payload.

The other recovered URLs are mostly Android/library documentation, advertising services, public IP-check services, or browser destinations. They should not automatically be treated as C2 indicators.

### File collection and transfer

The APK requests broad storage access through `MANAGE_EXTERNAL_STORAGE` and legacy external-storage permissions. Recovered indicators include:

- `Upload`
- `HandleUpload`
- `download`
- `Fast Download`
- `file_transfer`

This could support file collection or delivery, but the exact paths and protocol were not resolved by static analysis.

### Shell and command execution

The analyzer recovered command-execution primitives and related strings:

- `ProcessBuilder`
- `telnet`
- `ssh`
- Shell and command-related indicators

This suggests possible command execution, although the exact commands and reachable code path remain unconfirmed.

## Packing and Concealed Code

The application uses an obfuscated native loading layer:

- `JgEMldKkCrZWtSoKM.ProxyApplication`
- `JgEMldKkCrZWtSoKM.ProxyComponentFactory`
- `JniBridge`
- `assets/OoooooOooo`
- `assets/d_shell_data_001`
- `assets/vwwwwwvwww/*/libfcc02c764ff6313d.so`

`ProxyApplication` performs native initialization during `attachBaseContext()` and loads application state through `JniBridge`. The `OoooooOooo` asset begins with a DEX-like header and contains mostly non-printable data, consistent with concealed or packed bytecode.

The packed layer is important because the visible JADX output may not contain all application logic, configuration, endpoints, or command handlers.

## Risk Summary

| Capability | Static evidence | Risk |
|---|---|---|
| Accessibility control | Full event/content access and gestures | Critical |
| Screen capture | MediaProjection service and screenshot APIs | Critical |
| SMS access | `READ_SMS`, SMS APIs, SMS-role strings | Critical |
| Overlay/deceptive UI | Lock-screen activities and overlay indicators | Critical |
| Command execution | `ProcessBuilder`, SSH/Telnet indicators | Critical |
| Device administration | Device-admin receiver and activation flow | High |
| Persistence | Boot receiver and restart-related receivers | High |
| Remote communication | WebSocket message/retry indicators | High |
| File transfer | Upload/download indicators and storage access | High |
| Code concealment | Packed DEX asset and native loader | High |

## Limitations

- The APK was analyzed statically only.
- It was not installed, launched, or connected to a device.
- No ADB acquisition or device timeline was available.
- No external C2 server was conclusively identified.
- `androguard` was not installed, so MAFKit reported a manifest/certificate parsing limitation.
- Some indicators may belong to unused code or bundled libraries.
- The packed/native layer prevents complete source-level recovery.

## Recommended Handling

1. Do not install the APK on a personal or production Android device.
2. Preserve the original file and record the SHA-256 hash above.
3. If the APK was installed, isolate the device from networks and preserve logs before removing it.
4. Review enabled accessibility services, device-admin applications, VPNs, installed certificates, notification access, and SMS permissions.
5. Perform dynamic analysis only in an isolated emulator or sacrificial device with controlled networking.
6. Capture DNS, HTTP, WebSocket, filesystem, process, accessibility, SMS, and screen-capture activity during testing.
7. Treat any recovered endpoint, command, credential, SMS, or screen data as sensitive evidence.

## Source Artifacts

- [MAFKit report](mafkit-output/report.md)
- [JSON report](mafkit-output/report.json)
- [Behavior graph](mafkit-output/behavior_graph.json)
- [Behavior graph DOT file](mafkit-output/behavior_graph.dot)
- [Decompiled Android manifest](android-investigation/cinder/jadx-output/resources/AndroidManifest.xml)
- [Accessibility configuration](android-investigation/cinder/jadx-output/resources/res/xml/xbvkxyar.xml)
- [Network security configuration](android-investigation/cinder/jadx-output/resources/res/xml/network_security.xml)
