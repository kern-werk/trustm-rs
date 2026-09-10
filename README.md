# trustm-rs

Rust bindings for the Infineon OPTIGA Trust M secure element, built from Infineon's own C host library.

A fully static binary for an aarch64 device is `cargo build --release --target aarch64-unknown-linux-musl` with `aarch64-linux-musl-gcc` on the path.

```rust
use trustm::{EccCurve, KeyId, KeyUsage, Trustm};

let mut chip = Trustm::open("/dev/i2c-1", 0x30)?;
let public_key = chip.ecc_generate_keypair(EccCurve::NistP256, KeyUsage::SIGN, KeyId::E0F1)?;
let digest = chip.hash_sha256(b"hello")?;
let signature = chip.ecdsa_sign(KeyId::E0F1, &digest)?;
chip.ecdsa_verify(EccCurve::NistP256, &public_key, &digest, &signature)?;
```

The host library is asynchronous with callbacks; `trustm` turns every command into a blocking call with a timeout. One `Trustm` handle per process. Data formats are the chip's: ECC public keys come as a DER `BIT STRING` around the uncompressed point and ECDSA signatures as two bare DER `INTEGER`s. `ecc_public_key_point` and `ecdsa_signature_to_rs` convert those to the plain forms most crates want.

Anything the safe API does not cover (protected updates, streaming hash and HMAC, AES modes other than ECB, session-based keys) is reachable through `trustm::sys`.

The versioning of this crate follows the versioning of the submodule.

## Build configuration

`trustm-sys/csrc/trustm_sys_config.h` enables every chip command. Two things are deliberately off:

- Shielded connection, which encrypts the I2C link with a host-side secret, as it is the only feature that needs mbedTLS.
- Reset and VDD GPIO handling. Reset is done over I2C (soft reset), so no GPIO library is needed. If your board needs a hard reset, wire pins into `trustm-sys/csrc/pal_config.c`.

The bindings in `trustm-sys/src/bindings.rs` are committed so consumers do not need libclang.
