# PIV Tester

Small Android app for testing PIV smart cards over NFC (IsoDep) and USB CCID readers.

Features: select PIV applet, read CHUID, read certificates (9A/9C/9D/9E), PIN retries/verify,
sign-and-verify test (RSA 1024/2048, ECC P-256/P-384) and a raw APDU console.

## Build

Requires the Debian/Ubuntu packages `android-sdk-platform-23`, `android-sdk-build-tools`,
`apksigner`, `aapt`, `zipalign` and JDK 17. Then run:

    ./build.sh

The output is a debug-signed `pivtest.apk`. A prebuilt APK is attached to the GitHub release.
