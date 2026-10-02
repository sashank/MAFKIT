# ADB Evidence Acquisition Guide — MAFKit v3

This workflow collects **non-destructive Android system evidence** for correlation with an APK forensic analysis. It does not root the device and does not intentionally modify application data. Use it only on a device you own or are authorized to examine.

## 1. Preserve the situation first

1. Do **not** uninstall the suspicious app before acquisition if the device can be safely isolated.
2. Record the current date/time, device model, phone number/owner reference, and who handled the device.
3. Photograph or note any visible suspicious app name, Accessibility prompt, Device Admin prompt, or fraud message.
4. If ongoing remote control is suspected, isolate network connectivity in a manner appropriate to your incident-response process. Be aware that changing network state itself changes device state, so document it.
5. Avoid opening the suspicious app or deliberately triggering it.

## 2. Install ADB on the forensic workstation

Download Google's **Android SDK Platform-Tools** for Windows, macOS, or Linux. Verify:

```bash
adb version
```

## 3. Enable USB debugging on the Android device

On most Android devices:

1. Open **Settings → About phone**.
2. Tap **Build number** seven times until Developer options are enabled.
3. Go to **Settings → System / Additional settings → Developer options**.
4. Enable **USB debugging**.
5. Connect the phone using a USB data cable.
6. When the phone shows **Allow USB debugging?**, verify the workstation fingerprint and approve it.

OEM menu names differ. Enabling Developer options changes device state; note the time you enabled it in your evidence log.

## 4. Confirm exactly one authorized device

```bash
adb devices -l
```

Expected form:

```text
SERIAL    device product:... model:... transport_id:...
```

If it says `unauthorized`, unlock the phone and approve the prompt. If multiple devices appear, disconnect the ones not being acquired.

## 5. Identify the suspicious package, if not already known

List third-party packages:

```bash
adb shell pm list packages -3 -f -U -i
```

Search by a known package fragment:

### Windows PowerShell
```powershell
adb shell pm list packages -3 -f -U -i | Select-String "courier|cinder|yonder"
```

### Linux/macOS
```bash
adb shell pm list packages -3 -f -U -i | grep -Ei 'courier|cinder|yonder'
```

For the sample investigated in this case, the package was:

```text
cinder.yonder.nature
```

Do not assume that package name applies to other APKs.

## 6. Run MAFKit's acquisition collector

Install MAFKit v3 first:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e .
```

Then acquire evidence for a known package:

```bash
mafkit collect-adb -o case-001-adb --package cinder.yonder.nature
```

Or collect general device evidence if the package is unknown:

```bash
mafkit collect-adb -o case-001-adb
```

The collector requests a normal Android `bugreport.zip` by default. To skip that large collection:

```bash
mafkit collect-adb -o case-001-adb --package PACKAGE.NAME --no-bugreport
```

Convenience scripts are also included:

```bash
./scripts/collect_adb.sh case-001-adb PACKAGE.NAME
```

```powershell
.\scripts\collect_adb.ps1 -Out case-001-adb -Package PACKAGE.NAME
```

## 7. Evidence collected

The standard collector records, where Android permits it:

- `adb devices -l`
- device build/model properties (`getprop`)
- all and third-party package inventories
- package installer, UID and APK path information
- target `dumpsys package`
- Accessibility service state
- Device Policy / Device Administrator state
- Android roles, including default SMS role
- secure/global/system settings snapshots
- activity/process/service state
- usage statistics snapshot
- notification service state
- network/connectivity/netstats snapshots
- Wi-Fi state
- scheduled jobs and alarms
- battery/device-idle state
- current retained logcat buffer
- `bugreport.zip`
- best-effort pull of the target installed APK when the OS permits it
- SHA-256 inventory of acquisition files during later MAFKit analysis

## 8. Important Android limitations

Normal ADB shell access is intentionally restricted on modern Android:

- It generally **cannot read another app's private `/data/data/<package>` directory** without root, a debuggable build, backup support, or a specialist forensic acquisition method.
- SMS/call/notification contents may not be directly readable through shell commands.
- `logcat` is a rolling buffer and may no longer contain older events.
- `dumpsys usagestats` retention/detail differs across Android versions and OEM builds.
- An uninstalled application may leave fewer direct package artifacts.
- A bugreport can contain sensitive personal/device information. Store it as evidence and restrict access.

Absence of an artifact in ADB output is therefore **not proof that an action did not occur**.

## 9. Correlate ADB evidence with the APK

Create a timeline CSV using `examples/timeline-template.csv`, then run:

```bash
mafkit analyze suspicious.apk \
  -o case-001-analysis \
  --deep \
  --adb-dir case-001-adb \
  --timeline incident-timeline.csv
```

On Windows PowerShell:

```powershell
mafkit analyze suspicious.apk `
  -o case-001-analysis `
  --deep `
  --adb-dir case-001-adb `
  --timeline incident-timeline.csv
```

The report will compare the APK's package/capabilities with evidence such as package presence, first-install and update times, Accessibility state, Device Admin state, system references, usage/activity history, notification references, and the supplied fraud timeline.

## 10. Useful manual commands for focused validation

Replace `PACKAGE.NAME` with the suspect package.

```bash
adb shell dumpsys package PACKAGE.NAME
adb shell settings get secure enabled_accessibility_services
adb shell settings get secure accessibility_enabled
adb shell dumpsys accessibility
adb shell dumpsys device_policy
adb shell cmd role get-role-holders android.app.role.SMS
adb shell dumpsys usagestats
adb shell dumpsys activity | grep PACKAGE.NAME
adb shell dumpsys notification | grep PACKAGE.NAME
adb shell dumpsys netstats | grep PACKAGE.NAME
adb shell pm path PACKAGE.NAME
```

On Windows, replace `grep PACKAGE.NAME` with `Select-String "PACKAGE.NAME"` after piping the command output in PowerShell.

## 11. Chain-of-custody recommendation

For an evidentiary case, retain:

- the original APK unchanged;
- its SHA-256 hash;
- the entire ADB acquisition directory;
- `collection_manifest.json`;
- `bugreport.zip` if collected;
- investigator name/date/time/device identifier notes;
- the original bank/UPI transaction timestamps and complaint references;
- MAFKit-generated `report.json`, `evidence.jsonl`, and HTML/Markdown reports.

Do analysis on copies where practical. MAFKit's acquisition parsing inventories each file with SHA-256 so later changes are visible.

## Forensic handling notes (v3.1)

When the output may be used in an investigation:

1. Photograph/document the handset state before changing settings, including displayed date/time and lock state where permitted.
2. Record device make/model, Android version, visible serial/IMEI only if your procedure authorizes it, collector identity, case/reference number, cable/workstation used, and acquisition start/end time.
3. Enabling Developer Options or USB debugging changes device state. Record exactly when and why it was enabled. Do not claim the collection was state-neutral.
4. Use a dedicated analysis workstation where practical. Avoid installing unrelated applications on the handset.
5. Confirm exactly one authorized device using `adb devices -l` before acquisition. MAFKit v3.1 then pins subsequent commands to that serial using `adb -s`.
6. Do not edit the raw acquisition directory after collection. Make a working copy for analysis.
7. Verify `collection_manifest.sha256` against `collection_manifest.json` and preserve both.
8. Treat ADB as a logical/read-oriented acquisition. Lack of an artifact in ADB output does not prove it never existed.

Optional case metadata:

```bash
mafkit collect-adb \
  -o CASE-001-ADB \
  --package cinder.yonder.nature \
  --case-id CASE-001 \
  --examiner "Examiner Name"
```

The same metadata can be supplied during analysis:

```bash
mafkit analyze suspicious.apk \
  -o CASE-001-ANALYSIS \
  --deep \
  --adb-dir CASE-001-ADB \
  --timeline incident-timeline.csv \
  --case-id CASE-001 \
  --examiner "Examiner Name"
```
