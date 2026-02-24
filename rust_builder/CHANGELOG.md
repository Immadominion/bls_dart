## 0.0.2

- Fixed `.pubignore` that excluded platform directories (`ios/`, `android/`, `macos/`, `linux/`, `windows/`) from the published package
- iOS/macOS podspecs and Android/Linux/Windows build configs are now correctly included

## 0.0.1

- Initial release.
- Cargokit native build plugin for bls_dart.
- Compiles the blst BLS12-381 Rust library for Android, iOS, macOS, Linux and Windows via flutter_rust_bridge.
