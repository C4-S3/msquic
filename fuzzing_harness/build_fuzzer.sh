#!/bin/bash
#
# Build script for msquic frame fuzzer
#
# Usage:
#   ./build_fuzzer.sh [libfuzzer|afl]
#
# Requirements:
#   - clang with sanitizers
#   - AFL++ (for AFL mode)
#

set -e

MODE=${1:-libfuzzer}

echo "[*] Building msquic frame fuzzer in $MODE mode..."

# Compiler flags
COMMON_FLAGS="-O1 -g -fno-omit-frame-pointer"
SANITIZERS="-fsanitize=address,undefined,integer"

# Directories
SRC_DIR="."
BUILD_DIR="build"
mkdir -p "$BUILD_DIR"

case "$MODE" in
    libfuzzer)
        echo "[*] Building with libFuzzer..."
        clang++ $COMMON_FLAGS $SANITIZERS -fsanitize=fuzzer \
            -o "$BUILD_DIR/frame_fuzzer" \
            frame_fuzzer.cpp
        echo "[+] Built: $BUILD_DIR/frame_fuzzer"
        echo ""
        echo "Run with:"
        echo "  ./$BUILD_DIR/frame_fuzzer -max_len=65535 -timeout=10 corpus/"
        ;;

    afl)
        echo "[*] Building with AFL++..."
        if ! command -v afl-clang-fast++ &> /dev/null; then
            echo "[!] ERROR: afl-clang-fast++ not found. Install AFL++ first."
            echo "    sudo apt install afl++ (or build from source)"
            exit 1
        fi

        afl-clang-fast++ $COMMON_FLAGS $SANITIZERS \
            -o "$BUILD_DIR/frame_fuzzer_afl" \
            frame_fuzzer.cpp
        echo "[+] Built: $BUILD_DIR/frame_fuzzer_afl"
        echo ""
        echo "Run with:"
        echo "  afl-fuzz -i corpus/ -o findings/ -- ./$BUILD_DIR/frame_fuzzer_afl"
        ;;

    *)
        echo "[!] ERROR: Unknown mode '$MODE'"
        echo "Usage: $0 [libfuzzer|afl]"
        exit 1
        ;;
esac

echo ""
echo "[*] Don't forget to generate corpus first:"
echo "    python3 generate_corpus.py"
