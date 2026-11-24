#!/usr/bin/env bash
# Recreates /tmp/t toolchain for build.sh (Go, JDK17, android-34 jar, build-tools 34)
set -e
mkdir -p /tmp/t && cd /tmp/t
if [ "$(uname -m)" = aarch64 ]; then GOA=arm64; JA=aarch64; else GOA=amd64; JA=x64; fi
# on aarch64 hosts: sudo dpkg --add-architecture amd64; apt-get install qemu-user libc6:amd64 zipalign; build with AAPT2=/tmp/t/aapt2q ZIPALIGN=/usr/bin/zipalign
[ -x go/bin/go ] || { curl -sL https://go.dev/dl/go1.27.4.linux-$GOA.tar.gz | tar xz; }
[ -x go124/bin/go ] || { mkdir -p go124 && curl -sL https://go.dev/dl/go1.24.13.linux-$GOA.tar.gz | tar xz -C go124 --strip-components=1; }
[ -x go126/bin/go ] || { mkdir -p go126 && curl -sL https://go.dev/dl/go1.26.10.linux-$GOA.tar.gz | tar xz -C go126 --strip-components=1; }
[ -x jdk/bin/java ] || { mkdir -p jdk && curl -sL "https://api.adoptium.net/v3/binary/latest/17/ga/linux/$JA/jdk/hotspot/normal/eclipse" | tar xz -C jdk --strip-components=1; }
if [ ! -f plat/android-34/android.jar ]; then
  curl -sL -o p.zip https://dl.google.com/android/repository/platform-34-ext7_r03.zip && mkdir -p plat && unzip -q p.zip -d plat && mv plat/android-* plat/android-34 2>/dev/null || true; rm -f p.zip; fi
if [ ! -x bt/build-tools/aapt2 ]; then
  curl -sL -o b.zip https://dl.google.com/android/repository/build-tools_r34-linux.zip && mkdir -p bt && unzip -q b.zip -d bt && mv bt/android-14 bt/build-tools; rm -f b.zip
  mkdir -p btj && cp -r bt/build-tools btj/android-14; fi
ls go/bin jdk/bin/java plat/android-34/android.jar bt/build-tools/aapt2 bt/build-tools/zipalign btj/android-14/lib/d8.jar btj/android-14/lib/apksigner.jar
printf '#!/bin/sh\nexec qemu-x86_64 -L / /tmp/t/bt/build-tools/aapt2 "$@"\n' > /tmp/t/aapt2q; chmod +x /tmp/t/aapt2q
