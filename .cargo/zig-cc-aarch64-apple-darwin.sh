#!/bin/sh
exec /opt/zig-linux-x86_64-0.14.0/zig cc -target aarch64-macos "$@"
