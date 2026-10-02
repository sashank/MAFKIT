# Regression Validation — Original Investigation APK

The forensic-reviewed v3.1 build was re-run against the original APK used during development.

- SHA-256: `dd373a6c97d919fb41d41dd4a82a13c7de261178571ce0e6560bbbb47da14182`
- Package override used in this environment: `cinder.yonder.nature` (Androguard was not installed in the validation container)
- Restored DPT method bodies: **10,750**
- Candidate repeating-XOR plaintext strings: **4,046**
- Behavior graph: **252 nodes / 220 edges**
- Regression assertions: **passed**

The lower XOR count versus the earlier prototype is intentional: v3.1 uses stricter plaintext-quality scoring to reduce false positives.
