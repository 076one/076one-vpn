#!/usr/bin/env python3
"""v1.8.5: writes release/latest.json for the in-app updater from the built APKs.
usage: latest_json.py <out dir> <versionName> <versionCode> <notes.json {fa,en,zh}> > latest.json
APK names: 076one-v<ver>.apk (universal), 076one-v<ver>-arm64-v8a.apk, 076one-v<ver>-armeabi-v7a.apk.
Files are published at release/<name> on github.com/076one/076one-vpn (branch main)."""
import hashlib, json, os, sys
out, ver, code, notes = sys.argv[1], sys.argv[2], int(sys.argv[3]), json.load(open(sys.argv[4], encoding="utf-8"))
RAW = "https://github.com/076one/076one-vpn/raw/main/"
def entry(abi, name):
    p = os.path.join(out, name)
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return {"abi": abi, "apk": "release/" + name, "url": RAW + "release/" + name, "size": os.path.getsize(p), "sha256": h}
base = f"076one-v{ver}"
apks = [entry("universal", base + ".apk"), entry("arm64-v8a", base + "-arm64-v8a.apk"), entry("armeabi-v7a", base + "-armeabi-v7a.apk")]
u = apks[0]
doc = {"versionCode": code, "versionName": ver, "minSdk": 21,
       "apk": u["apk"], "url": u["url"], "size": u["size"], "sha256": u["sha256"],
       "signerSha256": "ec956e98caa16d80234dcb3f1e9b8b66fa9e14f8a78f71702142ad0024116ee8",
       "apks": apks, "notes": notes}
print(json.dumps(doc, ensure_ascii=False, indent=2))
