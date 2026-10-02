# USB Phone Scanner

MAFKit scans installed Android application packages from a laptop using Android Debug Bridge (ADB). It does not install an app on the phone, root the phone, or execute scanned APKs. APKs are copied to the laptop and inspected as archives. The scan is read-only; app removal is a separate, manually confirmed command.

## Requirements
On this computer the scanner checkout is `~/Downloads/MAFKIT-main`. Run it from its parent directory so Python selects that copy:
- A USB data cable
- An Android phone you own or are authorized to examine
cd ~/Downloads

Optional: install `androguard` to improve offline parsing of APK manifests and signing certificates:

```sh
python -m pip install androguard
```

MAFKit can still collect package permission state from Android when this optional library is not installed.

## Prepare Android

1. Open **Settings > About phone** and tap **Build number** seven times. Some manufacturers place Build number under **Software information**.
2. Return to Settings and open **Developer options**.
3. Enable **USB debugging**. Do not enable bootloader unlocking or USB installation for this scan.
4. Connect the phone to the laptop with a data-capable USB cable and unlock the phone.
5. At the phone's **Allow USB debugging?** prompt, verify the computer and accept its RSA fingerprint. Do not select always-allow on a computer you do not control.
6. On the laptop, verify the connection:

```sh
adb devices -l
```
The phone must be listed with state `device`. If it says `unauthorized`, unlock the phone and accept the prompt. If it is not listed, try another cable/USB port and install the manufacturer's USB driver on Windows if needed.

## Run a Scan

On this computer the scanner checkout is `~/Downloads/MAFKIT-main`. Run it from its parent directory so Python selects that copy:

```sh
cd ~/Downloads
python -m 'MAFKIT-main' scan-phone --out phone-scan-output
```

Do not run `python -m MAFKIT` from `~` for this checkout. That selects a separate `~/MAFKIT` folder, which does not contain the phone scanner.

The scan includes system and third-party apps by default. Use `--third-party-only` to skip system packages, `--serial SERIAL` to choose one phone when multiple devices are connected, or `--max-apps 5` for a small initial test.

```sh
cd ~/Downloads
python -m 'MAFKIT-main' scan-phone --third-party-only --out phone-scan-output
```

To select one phone when multiple devices are attached, or run a short test:

```sh
cd ~/Downloads
python -m 'MAFKIT-main' scan-phone --serial SERIAL --out phone-scan-output
python -m 'MAFKIT-main' scan-phone --max-apps 5 --out phone-scan-output
```

The scanner enumerates installed packages, reads package permission/install metadata and active accessibility/device-admin state, pulls the APK splits that Android exposes to the ADB shell user, and inspects those files offline. Larger devices may take several minutes. It fails rather than silently choosing a device if more than one authorized device is connected.

## Read the Results

The output directory contains:

- `phone_scan.md`: readable overview and per-app detail, with permission states, risk factors, coverage warnings, and APK fingerprints.
- `phone_scan.json`: full machine-readable scan result.
- `pulled_apks/`: APK files copied from the phone for offline inspection.
- `.scan_work/`: temporary static-analysis working files.

Each app receives a heuristic score from 0 to 100; **higher means fewer risk indicators were observed**, not that the app is certified safe. Scores account for granted sensitive permissions, static API/string indicators, packed-code indicators, and observed active accessibility or device-admin state. Requested-but-not-granted permissions are listed but do not receive the granted-permission score penalty. Review the factor list and scan coverage, not only the number.

A partial or metadata-only result means MAFKit could not inspect all relevant APK files. It must not be interpreted as a clean result. Scoring is not a malware verdict, does not use a cloud reputation database, and does not monitor live app behavior.

## Removing an App

Review the report and confirm the package is unwanted before taking action. To remove one third-party package from Android user 0:

```sh
cd ~/Downloads
python -m 'MAFKIT-main' remove-app com.example.package
```

MAFKit displays a prompt requiring the exact package name, refuses packages not listed as third-party apps, and asks Android Package Manager to uninstall it for user 0. Android removes the app's private data for that user. Shared-storage files are not deleted automatically. Removal can disrupt the phone or app, so do not remove a package solely because of its score. This command does not delete arbitrary files or system apps.

## Privacy and Cleanup

The scan does not read private app databases, messages, photos, or protected `/data/data` files. Ordinary USB debugging does not grant that access; rooting a phone is outside this scanner's scope. Pulled APKs and reports can reveal installed-app inventory and should be treated as sensitive. Store the output securely and remove the output directory from the laptop when it is no longer needed.

After scanning, disconnect the cable, turn off USB debugging, and use **Developer options > Revoke USB debugging authorizations** if the laptop should no longer be trusted. You can also turn Developer options off.
