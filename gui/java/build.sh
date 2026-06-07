#!/usr/bin/env bash
# Tiny build script — no Maven, no Gradle required.
# Produces:
#   gui/java/out/             - compiled .class files
#   gui/java/HunterPyGUI.jar  - executable JAR (java -jar HunterPyGUI.jar)
set -euo pipefail

cd "$(dirname "$0")"

OUT=out
JAR=HunterPyGUI.jar
SRC=$(find src/main/java -name '*.java')

echo "[+] Compiling Java sources (JDK $(javac -version 2>&1 | cut -d' ' -f2))..."
rm -rf "$OUT" "$JAR"
mkdir -p "$OUT"
# -Xlint:all is on but the noisy `serial` warning is suppressed — none of
# our Swing components are ever serialized.
javac -encoding UTF-8 -d "$OUT" --release 11 \
      -Xlint:all -Xlint:-serial -Xlint:-options $SRC

echo "[+] Running headless smoke test..."
java -cp "$OUT" io.hunterpy.gui.SmokeTest

if command -v jar >/dev/null 2>&1 ; then
    echo "[+] Building executable JAR..."
    cat > "$OUT/MANIFEST.MF" <<EOF
Manifest-Version: 1.0
Main-Class: io.hunterpy.gui.App
Implementation-Title: HunterPy GUI
Implementation-Version: 2.0.0
EOF
    ( cd "$OUT" && jar cfm "../$JAR" MANIFEST.MF $(find . -name '*.class') )
    echo "[+] Done."
    echo "    Run: java -jar gui/java/$JAR  [path/to/report.json]"
else
    echo "[~] 'jar' tool not on PATH — skipping JAR packaging."
    echo "    Install a full JDK (not just JRE) to build the JAR."
    echo "    For now, run with the loose .class files:"
    echo "      java -cp gui/java/$OUT io.hunterpy.gui.App  [report.json]"
fi
