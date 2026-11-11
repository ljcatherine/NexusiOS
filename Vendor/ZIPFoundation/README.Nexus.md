# ZIPFoundation vendored copy

This source is copied from the `weichsel/ZIPFoundation` 0.9.20 release at commit `22787ffb59de99e5dc1fbfe80b19c97a904ad48d` and is distributed under the included MIT license.

Nexus changes `Data+Compression.swift` in two conditional-compilation checks: on Apple platforms with `Compression` available, it uses ZIPFoundation's built-in CRC32 implementation instead of importing host `zlib`. Linux continues to use zlib. This prevents NixOS host libraries from leaking into the cross-compiled iPhoneOS link. The ZIP reading and Compression-framework code is otherwise upstream 0.9.20.
