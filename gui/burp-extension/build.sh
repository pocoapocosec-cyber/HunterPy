#!/usr/bin/env bash
# Build the HunterPy Burp Suite extension.
#
# Prereqs:
#   1. JDK 17+ (Montoya API targets 17)
#   2. A copy of montoya-api-<version>.jar from your Burp install.
#      Find it at:
#        Burp Suite ▸ Extensions ▸ APIs ▸ View Montoya API JavaDoc
#      then download the matching JAR from
#        https://portswigger.net/burp/releases  ▸ "Montoya API JAR"
#      Copy it to:  gui/burp-extension/lib/montoya-api.jar
#
# Output:
#   out/                — compiled .class files
#   hunterpy-burp.jar   — drop this into Burp ▸ Extensions ▸ Add
set -euo pipefail
cd "$(dirname "$0")"

OUT=out
JAR=hunterpy-burp.jar
MONTOYA_JAR=lib/montoya-api.jar

if [[ ! -f "$MONTOYA_JAR" ]]; then
    cat >&2 <<EOF
[ERR] Missing $MONTOYA_JAR

    Download the Montoya API JAR from
       https://github.com/PortSwigger/burp-extensions-montoya-api
    or from your Burp install (Help ▸ About ▸ "Download Montoya API JAR")
    and place it at:
       gui/burp-extension/lib/montoya-api.jar

    Then re-run ./build.sh
EOF
    exit 1
fi

SRC=$(find src/main/java -name '*.java')

echo "[+] Compiling against Montoya API..."
rm -rf "$OUT" "$JAR"
mkdir -p "$OUT"
javac -encoding UTF-8 --release 17 -Xlint:-serial -Xlint:-options \
    -cp "$MONTOYA_JAR" -d "$OUT" $SRC

echo "[+] Copying resources..."
cp -r src/main/resources/* "$OUT/" 2>/dev/null || true

if command -v jar >/dev/null 2>&1 ; then
    echo "[+] Building JAR..."
    ( cd "$OUT" && jar cf "../$JAR" . )
    echo "[+] Done: $JAR"
    echo "    Install in Burp: Extensions ▸ Add ▸ Java ▸ select $JAR"
else
    echo "[~] 'jar' tool not on PATH — install a full JDK to package."
    echo "    Compiled classes are in $OUT/"
fi
