#!/usr/bin/env bash
# Build without Gradle: downloads deps into ./libs and compiles with javac.
# Requires JDK 17+ and curl.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
LIBS="$ROOT/libs"
CLASSES="$ROOT/build/classes"
OUT_JAR_DIR="$ROOT/build/libs"
OUT_JAR="$OUT_JAR_DIR/burp-export-import-1.0.0.jar"

MONTOYA_VER="2023.12.1"
GSON_VER="2.10.1"

MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VER}/montoya-api-${MONTOYA_VER}.jar"
GSON_URL="https://repo1.maven.org/maven2/com/google/code/gson/gson/${GSON_VER}/gson-${GSON_VER}.jar"

mkdir -p "$LIBS" "$CLASSES" "$OUT_JAR_DIR"

download() {
    local url="$1" dest="$2"
    if [[ -f "$dest" ]]; then
        echo "  cached: $(basename "$dest")"
    else
        echo "  fetch:  $url"
        curl -fsSL "$url" -o "$dest"
    fi
}

echo "[1/4] Downloading dependencies..."
download "$MONTOYA_URL" "$LIBS/montoya-api-${MONTOYA_VER}.jar"
download "$GSON_URL"    "$LIBS/gson-${GSON_VER}.jar"

echo "[2/4] Compiling Java sources..."
SRC_FILES="$(find "$ROOT/src/main/java" -name '*.java')"
javac -d "$CLASSES" \
    -cp "$LIBS/montoya-api-${MONTOYA_VER}.jar:$LIBS/gson-${GSON_VER}.jar" \
    --release 17 \
    $SRC_FILES

echo "[3/4] Copying resources and extracting gson into class tree..."
cp -R "$ROOT/src/main/resources/." "$CLASSES/"
(cd "$CLASSES" && jar xf "$LIBS/gson-${GSON_VER}.jar")
rm -rf "$CLASSES/META-INF/versions" \
       "$CLASSES/META-INF/MANIFEST.MF" \
       "$CLASSES"/META-INF/*.SF "$CLASSES"/META-INF/*.DSA "$CLASSES"/META-INF/*.RSA 2>/dev/null || true

echo "[4/4] Packaging jar..."
(cd "$CLASSES" && jar cf "$OUT_JAR" .)

echo
echo "Built: $OUT_JAR"
