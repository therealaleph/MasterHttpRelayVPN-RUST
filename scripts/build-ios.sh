#!/usr/bin/env bash
# Build libmhrv_rs.a for iOS device + simulator and merge into a fat XCFramework.
#
# Prerequisites:
#   - Xcode installed (not just CommandLineTools)
#   - rustup targets: aarch64-apple-ios  aarch64-apple-ios-sim  x86_64-apple-ios
#   - lipo / xcodebuild in PATH (both come with Xcode)
#
# Usage:
#   ./scripts/build-ios.sh              # release build
#   ./scripts/build-ios.sh --debug      # debug build

set -euo pipefail

PROFILE="release-ios"
CARGO_FLAGS="--profile release-ios"
if [[ "${1:-}" == "--debug" ]]; then
  PROFILE="debug"
  CARGO_FLAGS=""
fi

CRATE_NAME="mhrv_rs"
LIB_NAME="lib${CRATE_NAME}.a"
OUT_DIR="ios/build"
XCFW_DIR="${OUT_DIR}/${CRATE_NAME}.xcframework"

echo "==> Installing required Rust targets..."
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios 2>/dev/null || true

# Build ONLY the staticlib. `cargo build --lib` also links the cdylib, whose
# link fails on iOS (undefined ___chkstk_darwin from C deps under -nodefaultlibs).
# `cargo rustc --crate-type staticlib` produces just libmhrv_rs.a.
echo "==> Building for aarch64-apple-ios (device)..."
cargo rustc ${CARGO_FLAGS} --target aarch64-apple-ios --lib --crate-type staticlib

echo "==> Building for aarch64-apple-ios-sim (Apple Silicon simulator)..."
cargo rustc ${CARGO_FLAGS} --target aarch64-apple-ios-sim --lib --crate-type staticlib

echo "==> Building for x86_64-apple-ios (Intel simulator)..."
cargo rustc ${CARGO_FLAGS} --target x86_64-apple-ios --lib --crate-type staticlib

DEVICE_LIB="target/aarch64-apple-ios/${PROFILE}/${LIB_NAME}"
SIM_ARM_LIB="target/aarch64-apple-ios-sim/${PROFILE}/${LIB_NAME}"
SIM_X86_LIB="target/x86_64-apple-ios/${PROFILE}/${LIB_NAME}"

echo "==> Merging simulator slices into fat lib..."
mkdir -p "${OUT_DIR}/sim"
lipo -create \
  "${SIM_ARM_LIB}" \
  "${SIM_X86_LIB}" \
  -output "${OUT_DIR}/sim/${LIB_NAME}"

echo "==> Packaging XCFramework..."
rm -rf "${XCFW_DIR}"
xcodebuild -create-xcframework \
  -library "${DEVICE_LIB}" \
  -headers ios/NetworkExtension \
  -library "${OUT_DIR}/sim/${LIB_NAME}" \
  -headers ios/NetworkExtension \
  -output "${XCFW_DIR}"

echo ""
echo "Done: ${XCFW_DIR}"
echo "  Add ${CRATE_NAME}.xcframework to your Xcode project under the"
echo "  NetworkExtension target > Frameworks, Libraries, and Embedded Content."
