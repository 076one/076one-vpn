#!/usr/bin/env bash
# Builds 076one APK without Gradle: Go core -> jniLibs, aapt2 -> resources, javac+d8 -> dex, zipalign, apksigner.
# Required env (defaults match the sandbox where it was first built):
#   GO        go binary (>= 1.26)            ANDROID_JAR  platforms/android-34/android.jar
#   GO124     Go 1.24 (warp-plus)            GO126        Go 1.26.10 (libchain: Xray-core v26.3.27 + psiphon-tunnel-core)
#   AAPT2     aapt2 binary for this host     ZIPALIGN     zipalign binary for this host
#   D8_JAR    build-tools/lib/d8.jar         APKSIGNER_JAR build-tools/lib/apksigner.jar
#   JAVA_HOME JDK 17
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HERE/../out}"
B="${BUILD_DIR:-/tmp/o76build}"
GO="${GO:-/tmp/t/go/bin/go}"
JAVA_HOME="${JAVA_HOME:-/tmp/t/jdk}"
ANDROID_JAR="${ANDROID_JAR:-/tmp/t/plat/android-34/android.jar}"
AAPT2="${AAPT2:-/tmp/t/bt/build-tools/aapt2}"
ZIPALIGN="${ZIPALIGN:-/tmp/t/bt/build-tools/zipalign}"
D8_JAR="${D8_JAR:-/tmp/t/btj/android-14/lib/d8.jar}"
APKSIGNER_JAR="${APKSIGNER_JAR:-/tmp/t/btj/android-14/lib/apksigner.jar}"
KS="$HERE/android/o76one-release.jks"
: "${KS_PASS:?set KS_PASS to your keystore password}"
APK_NAME="${APK_NAME:-076one-v1.8.4.apk}"
MIN_SDK=21
# v1.6: Aether v2.4.0 (CluvexStudio, AGPL-3.0), official static musl arm64 build, unmodified; arm64-v8a only
AETHER_SO="$HERE/android/jniLibs/arm64-v8a/libaether.so"
AETHER_SHA=a9d5e80e55b55c11566f9a7b078bf68815a3779fe450a4b344b8b96587634baf
J="$JAVA_HOME/bin"

rm -rf "$B"; mkdir -p "$B"/{lib/arm64-v8a,lib/armeabi-v7a,gen,classes,dex} "$OUT"

echo "== Go core"
( cd "$HERE/core"
  export CGO_ENABLED=0 GOFLAGS=-mod=mod
  GOOS=android GOARCH=arm64 "$GO" build -trimpath -ldflags="-s -w -buildid=" -o "$B/lib/arm64-v8a/libo76core.so" ./o76core
  # android/arm needs cgo; a static linux/arm binary runs fine on Android
  GOOS=linux GOARCH=arm GOARM=7 "$GO" build -trimpath -ldflags="-s -w -buildid=" -o "$B/lib/armeabi-v7a/libo76core.so" ./o76core )

echo "== Firefox core libfpn (Predator VPN core v2.0.7, GPL-3.0) both ABIs"
( cd "$HERE/fpn"
  export CGO_ENABLED=0 GOFLAGS=-mod=mod
  FL='-s -w -buildid= -X github.com/sagernet/sing-box/constant.Version=1.12.0'
  GOOS=android GOARCH=arm64 "$GO" build -trimpath -tags with_gvisor -ldflags="$FL" -o "$B/lib/arm64-v8a/libfpn.so" .
  GOOS=linux GOARCH=arm GOARM=7 "$GO" build -trimpath -tags with_gvisor -ldflags="$FL" -o "$B/lib/armeabi-v7a/libfpn.so" . )

echo "== warp-plus core libwplus (bepass-org, MIT + Psiphon GPL-3.0) both ABIs; needs Go 1.24 (psiphon-tls breaks on newer Go)"
( cd "$HERE/wplus"
  export CGO_ENABLED=0 GOFLAGS=-mod=mod GOTOOLCHAIN=local
  G124="${GO124:-/tmp/t/go124/bin/go}"
  GOOS=android GOARCH=arm64 "$G124" build -trimpath -ldflags="-s -w -buildid= -checklinkname=0" -o "$B/lib/arm64-v8a/libwplus.so" ./cmd/warp-plus
  GOOS=linux GOARCH=arm GOARM=7 "$G124" build -trimpath -ldflags="-s -w -buildid=" -o "$B/lib/armeabi-v7a/libwplus.so" ./cmd/warp-plus )

echo "== Config + Psiphon core libchain (Xray-core v26.3.27 MPL-2.0 + psiphon-tunnel-core GPL-3.0) both ABIs; Go 1.26 (what this psiphon commit needs)"
( cd "$HERE/chain"
  export CGO_ENABLED=0 GOFLAGS=-mod=mod GOTOOLCHAIN=local
  G126="${GO126:-/tmp/t/go126/bin/go}"
  "$G126" version | grep -q 'go1.26' || { echo "libchain needs Go 1.26.x (set GO126)"; exit 1; }
  GOOS=android GOARCH=arm64 "$G126" build -trimpath -ldflags="-s -w -buildid= -checklinkname=0" -o "$B/lib/arm64-v8a/libchain.so" .
  GOOS=linux GOARCH=arm GOARM=7 "$G126" build -trimpath -ldflags="-s -w -buildid= -checklinkname=0" -o "$B/lib/armeabi-v7a/libchain.so" . )

echo "== Aether core (arm64-v8a only)"
echo "$AETHER_SHA  $AETHER_SO" | sha256sum -c --quiet
cp "$AETHER_SO" "$B/lib/arm64-v8a/libaether.so"
chmod 755 "$B/lib/arm64-v8a/"*.so "$B/lib/armeabi-v7a/"*.so

echo "== resources"
"$AAPT2" compile --dir "$HERE/android/res" -o "$B/res.zip"
"$AAPT2" link -I "$ANDROID_JAR" --manifest "$HERE/android/AndroidManifest.xml" -A "$HERE/android/assets" \
  --java "$B/gen" -o "$B/base.apk" "$B/res.zip" --min-sdk-version $MIN_SDK --target-sdk-version 33

echo "== java"
"$J/javac" -encoding UTF-8 --release 11 -nowarn -cp "$ANDROID_JAR" -d "$B/classes" \
  $(find "$HERE/android/java" "$B/gen" -name '*.java')
"$J/java" -cp "$D8_JAR" com.android.tools.r8.D8 --release --min-api $MIN_SDK --lib "$ANDROID_JAR" \
  --output "$B/dex" $(find "$B/classes" -name '*.class')

echo "== package"
cp "$B/base.apk" "$B/unsigned.apk"
( cd "$B/dex" && zip -q -X "$B/unsigned.apk" classes.dex )
( cd "$B" && zip -q -X -r "$B/unsigned.apk" lib )
"$ZIPALIGN" -f -p 4 "$B/unsigned.apk" "$B/aligned.apk"

# updates must be signed with the same key (signer cert SHA-256 ec956e98…): never create a new keystore here
[ -f "$KS" ] || { echo "missing $KS (release keystore)"; exit 1; }
export KS_PASS
"$J/java" -jar "$APKSIGNER_JAR" sign --ks "$KS" --ks-pass env:KS_PASS --key-pass env:KS_PASS --ks-key-alias o76one \
  --min-sdk-version $MIN_SDK --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --v4-signing-enabled false --out "$OUT/$APK_NAME" "$B/aligned.apk"
"$J/java" -jar "$APKSIGNER_JAR" verify --verbose --min-sdk-version $MIN_SDK "$OUT/$APK_NAME"
( cd "$OUT" && sha256sum "$APK_NAME" > "$APK_NAME.sha256" )
echo "APK: $OUT/$APK_NAME"
