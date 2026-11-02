# PIV Tester

Small Android app for testing PIV smart cards over NFC (IsoDep) and USB CCID readers.

Features: select PIV applet, read CHUID, read certificates (9A/9C/9D/9E), PIN retries/verify,
sign-and-verify test (RSA 1024/2048, ECC P-256/P-384) and a raw APDU console.

## Build

Requires JDK 17+ and the Android SDK (platform 35). Then run:

    ./gradlew assembleDebug

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`. CI builds it on every push
and uploads it as an artifact. Targets Android 15 (API 35), min Android 6.0 (API 23).
