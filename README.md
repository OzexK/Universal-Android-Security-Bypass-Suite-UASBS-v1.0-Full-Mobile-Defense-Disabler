# 🛡️ Universal Android Security Bypass Suite v1.0

**Author:** Khaled Al-Refaee (Ozex)  
**Version:** 1.0  
**Release Date:** 2025  
**License:** Authorized Penetration Testing & Research Use Only  
**Platform:** Android (Java + Native)

---

## 🚀 Overview

**Universal Android Security Bypass Suite v1.0** is a powerful, modular **Frida-based instrumentation toolkit** designed for advanced penetration testers, mobile red team operators, and professional security researchers.

It provides full-spectrum evasion of Android application security controls by dynamically detecting and disabling protection mechanisms **at runtime**, supporting both **Java** and **native** layers.

> **Disclaimer:** This tool is intended **ONLY** for authorized red teaming, vulnerability assessments, and security research under legal contracts and engagements. Do not use for malicious purposes.

---

## 🔍 Features

| Module                  | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| ✅ Root Detection        | Bypass RootBeer, API checks, file checks, SELinux, Magisk detection         |
| ✅ Emulator Detection    | Evade QEMU, Bluestacks, LDPlayer, Nox and common emulator indicators        |
| ✅ Frida Detection       | Remove traces via process/thread check, port scans, and stack traces        |
| ✅ Debugger Detection    | Patch `isDebuggerConnected`, `TracerPid`, and native anti-debug logic       |
| ✅ SSL Pinning           | Hook & disable TrustManager, OkHTTP, WebView, TrustKit, etc.                |
| ✅ Play Integrity / SafetyNet | Spoof API responses and bypass attestation via inline patching         |
| ✅ Tamper Detection      | Disable signature, checksum, and class verification checks                  |
| ✅ VPN / Proxy Check     | Patch VPN checks, DNS leaks, and proxy detector methods                     |
| ✅ Screen Lock / Biometrics | Patch biometric checks and lock screen requirement logic                |
| ✅ Real Device Check     | Spoof build properties to bypass `isRealDevice()` logic                     |
| ✅ Firebase & Retrofit   | Intercept and log network data from Firebase and Retrofit clients           |
| ✅ Native Hook Support   | Hook libc/system/native methods for stealth or patching                    |
| ✅ Crash-Safe Execution  | All modules include optional try-catch wrappers for safer execution         |
| ✅ OPSEC Safe Mode       | Hides Frida presence, disables crash reporting, prevents recon failures     |
| ✅ Dynamic Class/Method Discovery | Scan and enumerate runtime classes and methods                     |

---

## ⚙️ Configuration

Edit the `CONFIG` object at the top of the script to enable/disable features:

```js
const CONFIG = {
    verbose: true,         // Show all logs in console
    crashSafe: true,       // Wrap all hooks in try/catch
    autoBypass: true,      // Automatically apply bypass hooks
    stealthMode: true,     // Anti-Frida and Anti-Emulator stealth
    discoveryMode: false,  // Enable dynamic class/method enumeration
    detailedOutput: true   // Show descriptions for each hook
};
```

---

## 📦 Usage

> 🧠 You must have Frida installed on your PC and Frida server running on the Android device.

```bash
# Connect to USB device and spawn target app
frida -U -n com.target.app -l Universal-Android-Security-Bypass-Suite-UASBS-v1.0-Full-Mobile-Defense-Disabler.js

# OR attach to already running process
frida -U -p <PID> -l Universal-Android-Security-Bypass-Suite-UASBS-v1.0-Full-Mobile-Defense-Disabler.js
```

Optional (enable logs):

```bash
frida -U -n com.target.app -l universal_bypass.js --runtime=v8
```


---

## 🧪 Tested Protections Bypassed

- RootBeer Library
- SafetyNet API & Integrity API
- Frida Detection (common + custom)
- Emulator detection (LDPlayer, Bluestacks, Nox, Genymotion)
- Tamper protection
- SSL Pinning (TrustManager, WebViewClient, TrustKit)
- VPN Detection
- Screen Lock Checks
- Biometric Prompt Enforcement

---

## 🧠 Internals

- Built using Frida's `Java.perform()` and `Interceptor.attach()` APIs
- Native hooking via `Module.findExportByName`, `Memory.scan()`, `Interceptor.replace()`
- All detection checks are dynamically found and patched
- Runs on Android 7 to Android 14 (tested)
- Safe to use in OPSEC-sensitive red team engagements

---

## 🔐 Legal Notice

This tool is intended for:

- Penetration testing engagements under contract
- Red teaming simulations
- Mobile security assessments
- Research and education

**Do NOT use on applications you do not own or have explicit permission to test.**  
All actions are your responsibility. The author assumes no liability.

---

## 📚 References

- [Frida Docs](https://frida.re/docs/)
- [Android Reverse Engineering](https://github.com/JesusFreke/smali)
- [OWASP MASVS](https://owasp.org/www-project-mobile-security/)

---

## 🧊 Credits

- Developed by **Khaled Al-Refaee** a.k.a. `Ozex`
- Part of `Ozex Red Team Arsenal`

---

## ☕ Support :)

- Buy Me a Coffee: [https://coff.ee/ozex](https://coff.ee/ozex)

---
