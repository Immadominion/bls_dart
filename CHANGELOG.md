## 0.1.0

- Initial release.
- BLS12-381 min_pk signature verification via blst.
- `bls12381MinPkVerify` — single signature verification.
- `bls12381MinPkAggregate` — aggregate multiple signatures.
- `bls12381MinPkVerifyAggregate` — verify aggregate against multiple public keys.
- Platform support: Android, iOS, macOS, Linux, Windows.
- DST: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` (Sui Move compatible).
