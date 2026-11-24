#!/usr/bin/env python3
"""API-level audit for 076one: lists every Android/Java platform class, method and field the compiled app classes
reference whose `since` in api-versions.xml is above MIN (default 21), together with the calling method, so each one
can be guarded with Build.VERSION.SDK_INT or replaced.

usage: apicheck.py <classes dir> <api-versions.xml> [min]
Guarded calls are still listed (javap shows no guards); the report marks a call as guarded when the calling method
also reads Build$VERSION.SDK_INT - review those by hand.
"""
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

cls_dir, api_xml = sys.argv[1], sys.argv[2]
MIN = int(sys.argv[3]) if len(sys.argv) > 3 else 21
JAVAP = os.environ.get("JAVAP", "/tmp/t/jdk/bin/javap")

root = ET.parse(api_xml).getroot()
classes = {}
for c in root.findall("class"):
    since = int(c.get("since", "1"))
    members = {}
    for m in c:
        if m.tag in ("method", "field"):
            members[m.get("name")] = int(m.get("since", str(since)))
    supers = [e.get("name") for e in c if e.tag in ("extends", "implements")]
    classes[c.get("name")] = (since, members, supers)


def lookup(owner, member, seen=None):
    """since of member in owner or its supertypes; None when unknown"""
    seen = seen or set()
    if owner in seen or owner not in classes:
        return None
    seen.add(owner)
    since, members, supers = classes[owner]
    if member in members:
        return members[member]
    for s in supers:
        r = lookup(s, member, seen)
        if r is not None:
            return r
    return None


files = []
for d, _, fs in os.walk(cls_dir):
    files += [os.path.join(d, f) for f in fs if f.endswith(".class")]
out = subprocess.run([JAVAP, "-c", "-p", "-constants"] + files, capture_output=True, text=True).stdout

ref = re.compile(r'// (Method|InterfaceMethod|Field|class) ("?[\w<>$]+"?:\S+|[\w/$]+(?:\."?[\w<>$]+"?:\S+)?)')


def split_ref(kind, body, cur):
    """-> owner, name, desc ; javap omits the owner for members of the current class"""
    if kind == "class":
        return body, "", ""
    if ":" not in body:
        return body, "", ""
    head, desc = body.split(":", 1)
    head = head.replace('"', "")
    if "." in head:
        owner, name = head.rsplit(".", 1)
    else:
        owner, name = cur.replace(".", "/"), head
    return owner, name, desc
# app classes -> superclass (javap header), to resolve calls made on `this` / app subclasses of platform classes
app_super = {}
for l in out.splitlines():
    m = re.match(r"^(?:public |private |protected |static |final |abstract |\s)*class (\S+) extends (\S+)", l)
    if m:
        app_super[m.group(1).replace(".", "/")] = m.group(2).replace(".", "/")


def platform_owner(owner):
    seen = set()
    while owner in app_super and owner not in seen:
        seen.add(owner)
        owner = app_super[owner]
    return owner
issues = {}
cur_cls, cur_m, guarded = "", "", set()
methods_with_sdk = set()
lines = out.splitlines()
# pass 1: methods that read SDK_INT
for l in lines:
    m = re.match(r"^(?:public |private |protected |static |final |abstract |synchronized |native |\s)*class (\S+)", l)
    if l.startswith("Compiled from") or m:
        if m:
            cur_cls = m.group(1)
        continue
    mm = re.match(r"^  (\S.*\(.*\).*);$", l) or re.match(r"^  (static \{\});$", l)
    if mm:
        cur_m = mm.group(1)
        continue
    if "android/os/Build$VERSION.SDK_INT" in l:
        methods_with_sdk.add((cur_cls, cur_m))
cur_cls = cur_m = ""
for l in lines:
    m = re.match(r"^(?:public |private |protected |static |final |abstract |synchronized |\s)*(?:class|interface) (\S+)", l)
    if m:
        cur_cls = m.group(1)
        # supertypes
        ext = re.findall(r"(?:extends|implements) ([\w.$, ]+)", l)
        for grp in ext:
            for t in grp.split(","):
                t = t.strip().replace(".", "/")
                if t in classes and classes[t][0] > MIN:
                    issues.setdefault((t, "<supertype>", classes[t][0]), set()).add(cur_cls)
        continue
    mm = re.match(r"^  (\S.*\(.*\).*);$", l) or re.match(r"^  (static \{\});$", l)
    if mm:
        cur_m = mm.group(1)
        continue
    for kind, body in ref.findall(l):
        owner, name, desc = split_ref(kind, body, cur_cls)
        if owner.startswith("com/o76one/") and kind != "class":
            owner = platform_owner(owner)
        if not (owner.startswith("android/") or owner.startswith("java/") or owner.startswith("javax/")
                or owner.startswith("org/json/") or owner.startswith("dalvik/")):
            continue
        if owner not in classes:
            issues.setdefault((owner, "<class not in api-versions>", 999), set()).add(cur_cls + " " + cur_m)
            continue
        csince = classes[owner][0]
        if csince > MIN:
            issues.setdefault((owner, "<class>", csince), set()).add(cur_cls + " " + cur_m)
        if kind == "class" or not name:
            continue
        key = name + desc if kind != "Field" else name
        s = lookup(owner, key)
        if s is None and kind != "Field":
            continue  # e.g. lambdas' synthetic or inherited-from-Object edge cases
        if s is not None and s > MIN:
            tag = " [method reads SDK_INT]" if (cur_cls, cur_m) in methods_with_sdk else ""
            issues.setdefault((owner, key, s), set()).add(cur_cls + " " + cur_m + tag)

for (owner, key, s), users in sorted(issues.items(), key=lambda x: (x[0][2], x[0][0])):
    print(f"API {s:>3}  {owner}.{key}")
    for u in sorted(users):
        print(f"           <- {u}")
print(f"\n{len(issues)} references above API {MIN}")
