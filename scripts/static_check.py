#!/usr/bin/env python3
"""
Static sanity checks for the TrustShield source tree.

This is NOT a compiler. It cannot resolve types, check method signatures, or
verify generics. What it does catch is the class of mechanical error that is easy
to introduce when writing Java without a build available:

  1. package declaration disagreeing with directory layout
  2. public type name disagreeing with filename
  3. unbalanced braces/parens/brackets (tokenised properly, so text blocks,
     comments, string and char literals do not confuse the count)
  4. imports of com.trustshield.* that point at files which do not exist
  5. malformed pom.xml / application.yml / phishing_model.json
  6. model JSON vector lengths and featureNames order disagreeing with
     UrlFeatureExtractor.FEATURE_NAMES  <-- the contract PhishingModel enforces
     at startup, so a mismatch here is a guaranteed boot failure
  7. FEATURE_NAMES and FEATURE_DESCRIPTIONS lengths disagreeing

Exit code is non-zero if any check fails.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")

errors = []
warnings = []
checked_java = 0


def err(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


# ---------------------------------------------------------------------------
# Java tokeniser: strips comments and literals so bracket counting is reliable
# ---------------------------------------------------------------------------

def strip_java_noise(src: str) -> str:
    """Remove comments, string literals, char literals and text blocks."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        # line comment
        if c == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        # block comment
        if c == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                i += 1
            i += 2
            continue
        # text block """ ... """
        if src.startswith('"""', i):
            i += 3
            while i < n and not src.startswith('"""', i):
                if src[i] == "\\":
                    i += 1
                i += 1
            i += 3
            continue
        # string literal
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        # char literal
        if c == "'":
            i += 1
            while i < n and src[i] != "'":
                if src[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue

        out.append(c)
        i += 1
    return "".join(out)


def check_balance(path: Path, code: str):
    pairs = {"}": "{", ")": "(", "]": "["}
    opens = {"{": "}", "(": ")", "[": "]"}
    stack = []
    line = 1
    for ch in code:
        if ch == "\n":
            line += 1
        elif ch in opens:
            stack.append((ch, line))
        elif ch in pairs:
            if not stack:
                err(f"{path}: unexpected '{ch}' at line {line} (nothing open)")
                return
            top, top_line = stack.pop()
            if top != pairs[ch]:
                err(f"{path}: '{ch}' at line {line} closes '{top}' opened at line {top_line}")
                return
    if stack:
        ch, ln = stack[-1]
        err(f"{path}: unclosed '{ch}' opened at line {ln}")


# ---------------------------------------------------------------------------
# Walk Java sources
# ---------------------------------------------------------------------------

declared_types = {}   # fully-qualified name -> path
imports_needed = []   # (path, fqn)

for java in sorted(ROOT.rglob("*.java")):
    checked_java += 1
    raw = java.read_text(encoding="utf-8")
    code = strip_java_noise(raw)

    check_balance(java, code)

    # package must match directory
    m = re.search(r"^\s*package\s+([\w.]+)\s*;", code, re.M)
    if not m:
        err(f"{java}: no package declaration")
        continue
    pkg = m.group(1)

    parts = java.parts
    for marker in (("src", "main", "java"), ("src", "test", "java")):
        try:
            idx = next(i for i in range(len(parts) - 2)
                       if tuple(parts[i:i + 3]) == marker)
            expected = ".".join(parts[idx + 3:-1])
            break
        except StopIteration:
            expected = None
    if expected is None:
        warn(f"{java}: not under src/main/java or src/test/java")
    elif expected != pkg:
        err(f"{java}: package '{pkg}' but directory implies '{expected}'")

    # top-level type name must match filename
    tm = re.search(r"^\s*(?:public\s+)?(?:final\s+|abstract\s+)?"
                   r"(class|interface|enum|record)\s+(\w+)", code, re.M)
    if tm:
        type_name = tm.group(2)
        if type_name != java.stem:
            err(f"{java}: declares {tm.group(1)} '{type_name}' but file is '{java.stem}.java'")
        declared_types[f"{pkg}.{type_name}"] = java
    else:
        warn(f"{java}: could not find a top-level type declaration")

    # collect trustshield imports for cross-checking
    for im in re.finditer(r"^\s*import\s+(static\s+)?(com\.trustshield\.[\w.]+)\s*;",
                          code, re.M):
        imports_needed.append((java, im.group(2), bool(im.group(1))))

# resolve internal imports
for path, fqn, is_static in imports_needed:
    if fqn in declared_types:
        continue
    # static import or nested type: strip the last segment and retry
    parent = fqn.rsplit(".", 1)[0]
    if parent in declared_types:
        continue
    err(f"{path}: imports '{fqn}' but no such type was found in the source tree")

# ---------------------------------------------------------------------------
# POMs
# ---------------------------------------------------------------------------

poms = sorted(ROOT.rglob("pom.xml"))
module_dirs_declared = []
for pom in poms:
    try:
        tree = ET.parse(pom)
    except ET.ParseError as e:
        err(f"{pom}: not well-formed XML: {e}")
        continue
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    for mod in tree.findall(".//m:modules/m:module", ns):
        module_dirs_declared.append((pom, mod.text.strip()))

# every declared module must exist on disk with its own pom
for pom, mod in module_dirs_declared:
    target = pom.parent / mod / "pom.xml"
    if not target.exists():
        err(f"{pom}: declares module '{mod}' but {target} does not exist "
            f"(Maven fails before compiling anything)")

# ---------------------------------------------------------------------------
# YAML
# ---------------------------------------------------------------------------

for y in sorted(ROOT.rglob("*.yml")) + sorted(ROOT.rglob("*.yaml")):
    try:
        list(yaml.safe_load_all(y.read_text(encoding="utf-8")))
    except yaml.YAMLError as e:
        err(f"{y}: invalid YAML: {e}")

# ---------------------------------------------------------------------------
# Model JSON vs Java feature contract
# ---------------------------------------------------------------------------

extractor = next(ROOT.rglob("UrlFeatureExtractor.java"), None)
java_names = []
java_desc_count = None
if extractor:
    src = extractor.read_text(encoding="utf-8")

    def array_strings(field):
        m = re.search(field + r"\s*=\s*\{(.*?)\};", src, re.S)
        if not m:
            return None
        return re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))

    java_names = array_strings("FEATURE_NAMES") or []
    descs = array_strings("FEATURE_DESCRIPTIONS")
    java_desc_count = len(descs) if descs is not None else None

    if not java_names:
        err("Could not parse FEATURE_NAMES out of UrlFeatureExtractor.java")
    if java_desc_count is None:
        err("Could not parse FEATURE_DESCRIPTIONS out of UrlFeatureExtractor.java")
    elif java_desc_count != len(java_names):
        err(f"FEATURE_NAMES has {len(java_names)} entries but "
            f"FEATURE_DESCRIPTIONS has {java_desc_count} "
            f"(the UI would show the wrong reason next to the right score)")
else:
    err("UrlFeatureExtractor.java not found")

for mj in sorted(ROOT.rglob("phishing_model.json")):
    try:
        model = json.loads(mj.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        err(f"{mj}: invalid JSON: {e}")
        continue

    n = len(java_names) if java_names else None
    for field in ("mean", "scale", "coefficients"):
        vec = model.get(field)
        if not isinstance(vec, list):
            err(f"{mj}: field '{field}' missing or not an array")
        elif n and len(vec) != n:
            err(f"{mj}: '{field}' has {len(vec)} entries, expected {n} "
                f"(PhishingModel hard-fails on this at startup)")

    names = model.get("featureNames")
    if not isinstance(names, list):
        err(f"{mj}: no featureNames array — feature order cannot be verified")
    elif java_names and names != java_names:
        for i, (a, b) in enumerate(zip(names, java_names)):
            if a != b:
                err(f"{mj}: featureNames[{i}] is '{a}' but Java extractor has '{b}'")
                break
        if len(names) != len(java_names):
            err(f"{mj}: featureNames has {len(names)} entries, Java has {len(java_names)}")

    # zero scale would produce NaN scores
    scale = model.get("scale")
    if isinstance(scale, list):
        zeros = [i for i, v in enumerate(scale) if v == 0]
        if zeros:
            names_hit = [java_names[i] if i < len(java_names) else str(i) for i in zeros]
            warn(f"{mj}: scale is 0 for {names_hit} — PhishingModel substitutes 1.0, "
                 f"but check this is intended")

    prov = model.get("provenance")
    if prov and prov != "TRAINED":
        warn(f"{mj}: provenance is '{prov}' — accuracy figures must not be reported")

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

print(f"Java files checked : {checked_java}")
print(f"Types declared     : {len(declared_types)}")
print(f"Internal imports   : {len(imports_needed)}")
print(f"POMs parsed        : {len(poms)}")
print()

if warnings:
    print(f"WARNINGS ({len(warnings)}):")
    for w in warnings:
        print(f"  ~ {w}")
    print()

if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors:
        print(f"  x {e}")
    sys.exit(1)

print("No structural errors found.")
print("NOTE: this is not a compile. Type resolution, method signatures and")
print("generics are unverified. `mvn clean install` is still required.")
