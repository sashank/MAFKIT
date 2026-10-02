# Mobile APK Forensic Analysis Report — MAFKit v2

> Static analysis only. Presence of capability does not prove execution on a specific handset.

## Executive Summary

Detected **5 critical** and **6 high-severity** forensic indicators.

DPT deep recovery restored **10,750 method bodies** across 4 DEX files.
Recovered **4,079 plausible repeating-XOR strings** from restored bytecode.

## Sample Identity

- **MD5**: `d54a6aa258ef1265ad6faac3afe41da2`
- **SHA1**: `19218c1d221ad15d7cab2561c7c6a469fe0ced0f`
- **SHA256**: `dd373a6c97d919fb41d41dd4a82a13c7de261178571ce0e6560bbbb47da14182`

## Findings

### [CRITICAL] Accessibility control
**Confidence:** medium

Accessibility APIs can inspect UI and automate gestures when the service is enabled.

Evidence:
- `AccessibilityService`
- `onAccessibilityEvent`
- `performGlobalAction`
- `GestureDescription`
- `findAccessibilityNodeInfosByText`
- `findAccessibilityNodeInfosByViewId`
- `canPerformGestures`
- `canRetrieveWindowContent`

### [CRITICAL] SMS manipulation
**Confidence:** medium

SMS APIs are present and may support OTP/message interception or sending.

Evidence:
- `SmsManager`
- `SmsMessage`
- `Telephony$Sms`
- `READ_SMS`

### [CRITICAL] Screen capture
**Confidence:** medium

MediaProjection/screenshot APIs support remote screen observation.

Evidence:
- `MediaProjection`
- `MediaProjectionManager`
- `takeScreenshot`
- `ScreenshotResult`
- `ImageReader`

### [CRITICAL] Remote/system command execution
**Confidence:** medium

Shell/process primitives may allow command execution.

Evidence:
- `ProcessBuilder`
- `telnet`
- `ssh`

### [CRITICAL] Overlay/injection
**Confidence:** medium

Injection/overlay configuration can support credential theft or banking overlays.

Evidence:
- `ject`
- `overlay`
- `rckey`

### [HIGH] Device administrator
**Confidence:** medium

Device-admin APIs can increase persistence/control.

Evidence:
- `DeviceAdminReceiver`

### [HIGH] Persistent remote channel
**Confidence:** medium

WebSocket code can support bidirectional command-and-control.

Evidence:
- `WebSocket`
- `onMessage`

### [HIGH] File transfer
**Confidence:** medium

Upload/download primitives can support file theft or delivery.

Evidence:
- `download`

### [HIGH] Persistence
**Confidence:** medium

Boot/start-service logic can maintain malware availability.

Evidence:
- `BOOT_COMPLETED`
- `QUICKBOOT_POWERON`
- `startForegroundService`

### [HIGH] Code packing/protection detected
**Confidence:** high

Packing can conceal executable logic and configuration from ordinary decompilation.

Evidence:
- `assets/OoooooOooo`
- `assets/d_shell_data_001`
- `ProxyApplication/libdpt.so`

### [HIGH] Hidden operational strings recovered
**Confidence:** high

Statically recovered strings expose behavior or command vocabulary that was concealed in packed bytecode.

Evidence:
- `android.app.action.ADD_DEVICE_ADMIN`
- `android.app.extra.DEVICE_ADMIN`
- `smsto`
- `AdBlock`
- `Blocked redirect to ad host: `
- `Closing WebSocket`
- `screen`
- `iScreenCap`
- `WebSocket closing: `
- `Max WebSocket retries reached, not reconnecting`
- `iScreenCap`
- `WebSocket failure: `
- `Max WebSocket retries reached, not reconnecting`
- `iScreenCap`
- `WebSocket opened`
- `Fast Download`
- `Fast Download`
- `Fast Download`
- `Closing WebSocket`
- `onPause: User navigated away, but screen is still on.`
- `onPause: Detected screen off!`
- `SMS`
- `SMSCALLS`
- `SMSCALLS/`
- `SMS`
- `Camera`
- `Screen`
- `android.app.role.SMS`
- `screensaver_enabled`
- `screensaver_components`
- `AUTH_FAILED_OR_NO_SHELL_PROMPT`
- `PatternUnlock`
- `PatternUnlock`
- `Upload`
- `HandleUpload`
- `lock`
- `upload`
- `screen`
- `dadmin`
- `livescreen`

## ATT&CK-style Behavior Mapping

> Semantic mapping for analyst triage; validate exact official Mobile ATT&CK technique IDs against the current MITRE catalog.

- **Collection / Credential Access** — Input/UI capture and automated interaction (`accessibility`)
- **Collection** — SMS/message collection or manipulation (`sms`)
- **Persistence / Defense Evasion** — Elevated device administration (`device_admin`)
- **Collection** — Screen capture (`screen_capture`)
- **Command and Control** — Bidirectional application-layer channel (`websocket`)
- **Execution** — Command or shell execution (`shell`)
- **Collection / Exfiltration** — File collection and transfer (`file_transfer`)
- **Credential Access** — Phishing/overlay injection (`overlay_injection`)
- **Persistence** — Boot/background-service persistence (`persistence`)

## Deep Deobfuscation

- Repeating-XOR candidates recovered: **4079**
- `android.settings.WIFI_SETTINGS` — `Lcinder/yonder/nature/HomeSmsung;->onCreate(Landroid/os/Bundle;)V`
- `android.intent.action.SET_WALLPAPER` — `Lcinder/yonder/nature/HomeWallp;->a(Landroid/content/Context;)V`
- `android.app.action.ADD_DEVICE_ADMIN` — `Lcinder/yonder/nature/RequestAdm;->onCreate(Landroid/os/Bundle;)V`
- `android.app.extra.DEVICE_ADMIN` — `Lcinder/yonder/nature/RequestAdm;->onCreate(Landroid/os/Bundle;)V`
- `android.app.extra.ADD_EXPLANATION` — `Lcinder/yonder/nature/RequestAdm;->onCreate(Landroid/os/Bundle;)V`
- `Click on Activate button to secure your application.` — `Lcinder/yonder/nature/RequestAdm;->onCreate(Landroid/os/Bundle;)V`
- `ResponseService` — `Lcinder/yonder/nature/Response;-><clinit>()V`
- `smsto` — `Lcinder/yonder/nature/Response;->a(Landroid/content/Intent;)V`
- `android.intent.extra.TEXT` — `Lcinder/yonder/nature/Response;->a(Landroid/content/Intent;)V`
- `RESPOND_VIA_MESSAGE phone=` — `Lcinder/yonder/nature/Response;->a(Landroid/content/Intent;)V`
- ` text=` — `Lcinder/yonder/nature/Response;->a(Landroid/content/Intent;)V`
- `msg` — `Lcinder/yonder/nature/Toastit;->onCreate(Landroid/os/Bundle;)V`
- `t.conf` — `Lcinder/yonder/nature/Toastit;->onCreate(Landroid/os/Bundle;)V`
- `com.samsung.accessibility.installed_service` — `Lcinder/yonder/nature/admcmjgi$d;->OK()V`
- `android.settings.ACCESSIBILITY_SETTINGS` — `Lcinder/yonder/nature/admcmjgi$d;->OK()V`
- `android.intent.extra.COMPONENT_NAME` — `Lcinder/yonder/nature/admcmjgi$d;->OK()V`
- `3` — `Lcinder/yonder/nature/admcmjgi$d;->OK()V`
- `:settings:fragment_args_key` — `Lcinder/yonder/nature/admcmjgi$d;->OK()V`
- `:settings:show_fragment_args` — `Lcinder/yonder/nature/admcmjgi$d;->OK()V`
- `FROM_ALARM` — `Lcinder/yonder/nature/alarme;->b(Landroid/content/Intent;Landroid/content/Context;)V`
- `doubleclick.net` — `Lcinder/yonder/nature/alsygodo$e;->a(Ljava/lang/String;)Z`
- `adservice.google.com` — `Lcinder/yonder/nature/alsygodo$e;->a(Ljava/lang/String;)Z`
- `googlesyndication.com` — `Lcinder/yonder/nature/alsygodo$e;->a(Ljava/lang/String;)Z`
- `ads.` — `Lcinder/yonder/nature/alsygodo$e;->a(Ljava/lang/String;)Z`
- `.*\b(ad|ads|banner|click|track)\b.*\..*` — `Lcinder/yonder/nature/alsygodo$e;->a(Ljava/lang/String;)Z`
- `AdBlock` — `Lcinder/yonder/nature/alsygodo$e;->shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z`
- `Blocked redirect to ad host: ` — `Lcinder/yonder/nature/alsygodo$e;->shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z`
- `http` — `Lcinder/yonder/nature/alsygodo$e;->shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z`
- `https://` — `Lcinder/yonder/nature/alsygodo$e;->shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z`
- `://` — `Lcinder/yonder/nature/alsygodo$e;->shouldOverrideUrlLoading(Landroid/webkit/WebView;Landroid/webkit/WebResourceRequest;)Z`
- `Web Browser` — `Lcinder/yonder/nature/alsygodo;->k(ZLjava/lang/String;)V`
- `Web site not reachable` — `Lcinder/yonder/nature/alsygodo;->k(ZLjava/lang/String;)V`
- `ads.txt` — `Lcinder/yonder/nature/alsygodo;->m(Landroid/content/Context;)V`
- `[AST-PAS]` — `Lcinder/yonder/nature/alsygodo;->m(Landroid/content/Context;)V`
- `3` — `Lcinder/yonder/nature/alsygodo;->m(Landroid/content/Context;)V`
- `ID` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `Deviceid` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `null` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `idf` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `pid` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `itype` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `Slr_client` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `subc` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `msg` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `cip` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `red_k` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `conk` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `Missing ID` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `Error during message sending` — `Lcinder/yonder/nature/alsygodo;->n(Landroid/content/Context;Ljava/lang/String;)V`
- `Browser` — `Lcinder/yonder/nature/alsygodo;->j()V`
- `Client Exit.` — `Lcinder/yonder/nature/alsygodo;->j()V`
- `Closing WebSocket` — `Lcinder/yonder/nature/alsygodo;->j()V`
- `key` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `type` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `icon` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `trk` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `App` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `label` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `com.android.chrome` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `com.android.vending` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `UTF-8` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `text/html` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `https://` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `http://` — `Lcinder/yonder/nature/alsygodo;->onCreate(Landroid/os/Bundle;)V`
- `com.android.systemui` — `Lcinder/yonder/nature/cjtykwcnotvyjqzmeor$g;->run()V`
- `App.ACT.SETUP` — `Lcinder/yonder/nature/cjtykwcnotvyjqzmeor$i$a;->run()V`
- `android.intent.category.DEFAULT` — `Lcinder/yonder/nature/cjtykwcnotvyjqzmeor$i$a;->run()V`
- `App.ACT.CLONE` — `Lcinder/yonder/nature/cjtykwcnotvyjqzmeor$i$b;->run()V`
- `extra_message` — `Lcinder/yonder/nature/cjtykwcnotvyjqzmeor$i$b;->run()V`
- `android.intent.category.DEFAULT` — `Lcinder/yonder/nature/cjtykwcnotvyjqzmeor$i$b;->run()V`
- `Wscr` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `720` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `Hscr` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `1280` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `red_k` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `type` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `scread` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `img` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `frmt` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `I` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `ori` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `skly` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `wmob` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `hmob` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `scread complete` — `Lcinder/yonder/nature/e0$e$a;->run()V`
- `insertSenderMessage(` — `Lcinder/yonder/nature/frcitsfolssodkki$a;->b(Ljava/lang/String;)V`
- `type` — `Lcinder/yonder/nature/frcitsfolssodkki$a;->sendit(Ljava/lang/String;)V`
- `chat` — `Lcinder/yonder/nature/frcitsfolssodkki$a;->sendit(Ljava/lang/String;)V`
- `data` — `Lcinder/yonder/nature/frcitsfolssodkki$a;->sendit(Ljava/lang/String;)V`
- `red_k` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `type` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `screen` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `img` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `frmt` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `skly` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `s` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `ori` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `wmob` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `hmob` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->f(Landroid/content/Context;)V`
- `iScreenCap` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onClosing(Lokhttp3/WebSocket;ILjava/lang/String;)V`
- `WebSocket closing: ` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onClosing(Lokhttp3/WebSocket;ILjava/lang/String;)V`
- `Max WebSocket retries reached, not reconnecting` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onClosing(Lokhttp3/WebSocket;ILjava/lang/String;)V`
- `iScreenCap` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onFailure(Lokhttp3/WebSocket;Ljava/lang/Throwable;Lokhttp3/Response;)V`
- `WebSocket failure: ` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onFailure(Lokhttp3/WebSocket;Ljava/lang/Throwable;Lokhttp3/Response;)V`
- `Max WebSocket retries reached, not reconnecting` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onFailure(Lokhttp3/WebSocket;Ljava/lang/Throwable;Lokhttp3/Response;)V`
- `type` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onMessage(Lokhttp3/WebSocket;Ljava/lang/String;)V`
- `empty` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onMessage(Lokhttp3/WebSocket;Ljava/lang/String;)V`
- `stop` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onMessage(Lokhttp3/WebSocket;Ljava/lang/String;)V`
- `Unauthorized access` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onMessage(Lokhttp3/WebSocket;Ljava/lang/String;)V`
- `iScreenCap` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onOpen(Lokhttp3/WebSocket;Lokhttp3/Response;)V`
- `WebSocket opened` — `Lcinder/yonder/nature/gtzwsszrkrla$a;->onOpen(Lokhttp3/WebSocket;Lokhttp3/Response;)V`
- `Fast Download` — `Lcinder/yonder/nature/h0;->b(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V`
- `Error: Create image` — `Lcinder/yonder/nature/h0;->b(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V`
- `File not found` — `Lcinder/yonder/nature/h0;->b(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V`
- `Error:` — `Lcinder/yonder/nature/h0;->b(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V`
- `VideoSize` — `Lcinder/yonder/nature/h0;->c(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V`
- `Width: ` — `Lcinder/yonder/nature/h0;->c(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V`
- `, Height: ` — `Lcinder/yonder/nature/h0;->c(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V`
- `-y -i "%s" -vf scale=` — `Lcinder/yonder/nature/h0;->c(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V`
- ` -c:v libx264 -preset veryfast -crf 28 -c:a copy -movflags +faststart "%s"` — `Lcinder/yonder/nature/h0;->c(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V`

## Behavior Graph

- Nodes: **252**
- Edges: **220**
- Machine-readable graph: `behavior_graph.json`
- Graphviz source: `behavior_graph.dot`

## Indicators of Compromise

### URLs / WebSockets
- `http://schemas.android.com/apk/res/android`
- `https://android.googlesource.com/toolchain/llvm-project`
- `http://schemas.android.com/apk/res-auto`
- `https://issuetracker.google.com/issues/new?component=413107&template=1096568`
- `https://developer.android.com/training/articles/direct-boot`
- `https://youtrack.jetbrains.com/issue/KT-46465`
- `https://publicsuffix.org/list/public_suffix_list.dat`
- `https://mozilla.org/MPL/2.0/`
- `http://www.apache.org/licenses/LICENSE-2.0`
- `http://schemas.android.com/aapt`
- `http://fsf.org/`
- `http://www.gnu.org/licenses/`
- `http://www.gnu.org/philosophy/why-not-lgpl.html`
- `http://www.apache.org/licenses/`
- `https://github.com/arthenica/ffmpeg-kit/wiki/Source`
- `http://checkip.amazonaws.com`
- `https://api.ipify.org`
- `https://icanhazip.com`
- `https://ifconfig.me/ip`
- `https://www.google.com/`
- `https://www.bing.com/`
- `https://www.youtube.com/`
- `https://www.facebook.com/`
- `https://www.twitter.com/`
- `https://play.google.com/`
- `ws://127.0.0.1:8080/`

### Domains
- `schemas.android.com`
- `android.intent.category.INFO`
- `androidx.work`
- `88androidx.work`
- `55androidx.work`
- `NNandroidx.work`
- `LLandroidx.work`
- `KKandroidx.work`
- `android.net`
- `GGandroidx.work`
- `77androidx.work`
- `22androidx.work`
- `c.Cc`
- `b.IO`
- `d.in`
- `a.Cc`
- `c.cc`
- `android.googlesource.com`
- `android.app`
- `Dispatchers.IO`
- `6androidx.work`
- `Wandroidx.work`
- `Gandroidx.work`
- `openssh.com`
- `current.work`
- `kotlinx.coroutines.io`
- `javax.net`
- `4org.apache.commons.net`
- `org.apache.commons.net`
- `apache.commons.net`
- `org.openjsse.net`
- `7androidx.work`
- `2androidx.work`
- `com.android.org`
- `com.google.android.gms.org`
- `java.net`
- `issuetracker.google.com`
- `developer.android.com`
- `Pandroidx.work`
- `java.io`
- `jcraft.com`
- `libcore.io`
- `whois.internic.net`
- `youtrack.jetbrains.com`
- `publicsuffix.org`
- `mozilla.org`
- `www.apache.org`
- `66androidx.appcompat.app`
- `androidx.fragment.app`
- `fsf.org`
- `www.gnu.org`
- `x265.com`
- `github.com`
- `arthenica.com`
- `ShapeAppearanceOverlay.Material3.Corner.Top`
- `TextAppearance.Compat.Notification.Info`
- `doubleclick.net`
- `adservice.google.com`
- `googlesyndication.com`
- `google.com`
- `youtube.com`
- `checkip.amazonaws.com`
- `api.ipify.org`
- `icanhazip.com`
- `ifconfig.me`
- `www.google.com`
- `www.bing.com`
- `www.youtube.com`
- `www.facebook.com`
- `www.twitter.com`
- `skin.info`
- `droid.app`
- `com.sec.android.app`
- `play.google.com`

### IPv4
- `127.0.0.1`
- `0.0.0.0`
- `0.0.39.113`
- `121.0.0.0`
- `113.0.0.0`
- `120.0.0.0`

## Packer / Protection

```json
{
  "detected": true,
  "family": "DPT Shell",
  "evidence": [
    "assets/OoooooOooo",
    "assets/d_shell_data_001",
    "ProxyApplication/libdpt.so"
  ],
  "recovered_dex": [
    {
      "name": "classes.dex",
      "size": 1571844,
      "offset": 9116,
      "path": "/mnt/data/mafkit_v2_test/recovered/dpt/original/classes.dex"
    },
    {
      "name": "classes2.dex",
      "size": 1604744,
      "offset": 9116,
      "path": "/mnt/data/mafkit_v2_test/recovered/dpt/original/classes2.dex"
    },
    {
      "name": "classes3.dex",
      "size": 1462540,
      "offset": 9116,
      "path": "/mnt/data/mafkit_v2_test/recovered/dpt/original/classes3.dex"
    },
    {
      "name": "classes4.dex",
      "size": 1546716,
      "offset": 9116,
      "path": "/mnt/data/mafkit_v2_test/recovered/dpt/original/classes4.dex"
    },
    {
      "name": "classes5.dex",
      "size": 25212,
      "offset": 9116,
      "path": "/mnt/data/mafkit_v2_test/recovered/dpt/original/classes5.dex"
    }
  ],
  "method_restoration": {
    "restored": true,
    "store_version": 2,
    "dex_sections": 4,
    "total_methods_restored": 10750,
    "dexes": [
      {
        "dex": "classes.dex",
        "records": 2584,
        "patched": 2584,
        "unpatched": 0,
        "path": "/mnt/data/mafkit_v2_test/recovered/dpt/restored/classes.dex"
      },
      {
        "dex": "classes2.dex",
        "records": 2587,
        "patched": 2587,
        "unpatched": 0,
        "path": "/mnt/data/mafkit_v2_test/recovered/dpt/restored/classes2.dex"
      },
      {
        "dex": "classes3.dex",
        "records": 2856,
        "patched": 2856,
        "unpatched": 0,
        "path": "/mnt/data/mafkit_v2_test/recovered/dpt/restored/classes3.dex"
      },
      {
        "dex": "classes4.dex",
        "records": 2723,
        "patched": 2723,
        "unpatched": 0,
        "path": "/mnt/data/mafkit_v2_test/recovered/dpt/restored/classes4.dex"
      }
    ]
  }
}
```

## Limitations

- Manifest/certificate parsing failed: No module named 'androguard'

## Recommended Corroboration

Correlate APK capabilities with handset evidence: install/uninstall timestamps, Accessibility/Device Admin state, usage/events, package remnants, preferences/configuration, DNS/network logs, SMS/call/notification artifacts, and financial transaction timestamps.