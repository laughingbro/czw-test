#!/bin/sh
# Builds a signed debug APK using the apt-provided Android toolchain.
set -e
cd "$(dirname "$0")"
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
JAVAC=$JAVA_HOME/bin/javac
JAVA=$JAVA_HOME/bin/java
SDK=/usr/lib/android-sdk
JAR=$SDK/platforms/android-23/android.jar
BT=$SDK/build-tools/29.0.3

rm -rf build && mkdir -p build/classes
$JAVAC -source 8 -target 8 -encoding UTF-8 -Xlint:-options -bootclasspath "$JAR" -d build/classes src/com/example/pivtest/*.java
$JAVA -jar $BT/lib/dx.jar --dex --output=build/classes.dex build/classes
aapt package -f -M AndroidManifest.xml -I "$JAR" -F build/unsigned.apk
(cd build && aapt add unsigned.apk classes.dex >/dev/null)
zipalign -f 4 build/unsigned.apk build/aligned.apk
[ -f debug.keystore ] || keytool -genkeypair -keystore debug.keystore -storepass android -keypass android \
    -alias debug -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Debug"
apksigner sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android --out pivtest.apk build/aligned.apk
apksigner verify pivtest.apk && echo "Built $(pwd)/pivtest.apk"
