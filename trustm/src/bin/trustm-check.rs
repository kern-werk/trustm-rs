//! trustm-check: exercise a Trust M on a target with read-only operations.
//!
//! ```text
//! trustm-check BUS        BUS is a number (3) or a device (/dev/i2c-3).
//!                         Slave address is 0x30.
//! ```
//!
//! Nothing here writes to the chip: no key generation, no data object or
//! metadata writes, no counter updates. Signing uses the factory key in
//! 0xE0F0, whose public key is taken from the factory certificate in 0xE0E0,
//! so the sign/verify round trip also validates the signature format this
//! crate assumes. Exit status is non-zero if any check fails.

use std::time::Instant;
use trustm::{EccCurve, Error, KeyId, RngType, Trustm};

const HELP: &str = "\
trustm-check: read-only health check of an OPTIGA Trust M

usage: trustm-check BUS
       trustm-check -h | --help

  BUS   I2C bus number (3) or device path (/dev/i2c-3). Slave address 0x30.

Reads identity and state objects, metadata and the factory certificate,
draws random bytes, runs a SHA-256 known answer, and signs with the factory
key 0xE0F0 then verifies against its certificate. Writes nothing to the chip.
Exit status: 0 all checks passed, 1 a check failed, 2 bad usage.";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bus = match args.as_slice() {
        [b] if b == "-h" || b == "--help" => {
            println!("{HELP}");
            return;
        }
        [b] => bus_path(b),
        _ => {
            eprintln!("{HELP}");
            std::process::exit(2);
        }
    };
    let addr = trustm::DEFAULT_ADDR;

    let mut r = Report::default();
    println!("trustm-check: {bus} addr 0x{addr:02x}");

    let t = Instant::now();
    let mut chip = match Trustm::open(&bus, addr) {
        Ok(c) => {
            r.ok("open application", t);
            c
        }
        Err(e) => {
            r.fail("open application", t, &e);
            r.finish();
            return;
        }
    };

    // ---- identity and state data objects ---------------------------------
    r.check("read coprocessor UID (0xE0C2)", || {
        let uid = chip.read_data(0xE0C2, 0)?;
        expect(uid.len() == 27, "UID should be 27 bytes")?;
        Ok(hex(&uid))
    });
    r.check("read lifecycle state (0xE0C0)", || {
        let v = chip.read_data(0xE0C0, 0)?;
        Ok(format!(
            "{} ({})",
            hex(&v),
            match v.first() {
                Some(0x01) => "creation",
                Some(0x03) => "initialization",
                Some(0x07) => "operational",
                Some(0x0F) => "termination",
                _ => "?",
            }
        ))
    });
    r.check("read security status (0xE0C1)", || {
        Ok(hex(&chip.read_data(0xE0C1, 0)?))
    });
    r.check("read security event counter (0xE0C5)", || {
        Ok(hex(&chip.read_data(0xE0C5, 0)?))
    });
    r.check("read max comm buffer size (0xE0C6)", || {
        let v = chip.read_data(0xE0C6, 0)?;
        expect(v.len() == 2, "expected 2 bytes")?;
        Ok(format!("{} bytes", u16::from_be_bytes([v[0], v[1]])))
    });
    r.check("read monotonic counter (0xE120)", || {
        Ok(hex(&chip.read_data(0xE120, 0)?))
    });

    // ---- metadata ---------------------------------------------------------
    for (oid, what) in [
        (0xE0F0u16, "factory key slot 0xE0F0"),
        (0xE0F1, "key slot 0xE0F1"),
        (0xE0E0, "certificate 0xE0E0"),
        (0xF1D1, "data object 0xF1D1"),
    ] {
        r.check(&format!("read metadata of {what}"), || {
            Ok(hex(&chip.read_metadata(oid)?))
        });
    }

    // ---- factory certificate ------------------------------------------------
    let mut factory_pub: Option<Vec<u8>> = None;
    r.check("read factory certificate (0xE0E0)", || {
        let raw = chip.read_data(0xE0E0, 0)?;
        let der = strip_cert_header(&raw)?;
        expect(
            der.starts_with(&[0x30, 0x82]),
            "certificate should be a DER SEQUENCE",
        )?;
        let point =
            find_p256_spki(der).ok_or(Error::BadData("no P-256 public key in certificate"))?;
        factory_pub = Some(point.to_vec());
        Ok(format!("{} bytes, P-256 public key found", der.len()))
    });

    // ---- random and hash --------------------------------------------------
    r.check("random 32 bytes (TRNG)", || {
        let a = chip.random(RngType::Trng, 32)?;
        let b = chip.random(RngType::Trng, 32)?;
        expect(a != b, "two draws should differ")?;
        expect(a.iter().any(|&x| x != 0), "all zero")?;
        Ok(hex(&a[..8]) + "...")
    });
    r.check("SHA-256 known answer", || {
        let d = chip.hash_sha256(b"abc")?;
        const WANT: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        expect(d == WANT, "digest mismatch")?;
        Ok("matches".into())
    });

    // ---- sign with the factory key, verify against its certificate ---------
    let digest = [0x42u8; 32];
    let mut signature: Option<Vec<u8>> = None;
    r.check("ECDSA sign with factory key 0xE0F0", || {
        let s = chip.ecdsa_sign(KeyId::E0F0, &digest)?;
        let rs = trustm::ecdsa_signature_to_rs(&s, 32)?;
        expect(rs.len() == 64, "r||s should be 64 bytes")?;
        let out = format!("{} bytes DER, r||s ok", s.len());
        signature = Some(s);
        Ok(out)
    });
    if let (Some(sig), Some(point)) = (&signature, &factory_pub) {
        // The chip wants the BIT STRING form for host-supplied keys.
        let mut der_key = vec![0x03, 0x42, 0x00];
        der_key.extend_from_slice(point);
        r.check("ECDSA verify on chip against certificate key", || {
            chip.ecdsa_verify(EccCurve::NistP256, &der_key, &digest, sig)?;
            Ok("valid".into())
        });
        r.check("ECDSA verify rejects a tampered digest", || {
            let mut bad = digest;
            bad[0] ^= 1;
            match chip.ecdsa_verify(EccCurve::NistP256, &der_key, &bad, sig) {
                Err(_) => Ok("rejected".into()),
                Ok(()) => Err(Error::BadData("tampered digest verified")),
            }
        });
    } else {
        r.skip("ECDSA verify on chip against certificate key");
        r.skip("ECDSA verify rejects a tampered digest");
    }

    let t = Instant::now();
    match chip.close() {
        Ok(()) => r.ok("close application", t),
        Err(e) => r.fail("close application", t, &e),
    }
    r.finish();
}

// ---------------------------------------------------------------------------

#[derive(Default)]
struct Report {
    failed: u32,
    passed: u32,
}

impl Report {
    fn check(&mut self, name: &str, f: impl FnOnce() -> Result<String, Error>) {
        let t = Instant::now();
        match f() {
            Ok(info) => {
                self.passed += 1;
                println!(
                    "ok    {:<48} {:>6} ms  {}",
                    name,
                    t.elapsed().as_millis(),
                    info
                );
            }
            Err(e) => self.fail(name, t, &e),
        }
    }
    fn ok(&mut self, name: &str, t: Instant) {
        self.passed += 1;
        println!("ok    {:<48} {:>6} ms", name, t.elapsed().as_millis());
    }
    fn fail(&mut self, name: &str, t: Instant, e: &Error) {
        self.failed += 1;
        println!(
            "FAIL  {:<48} {:>6} ms  {}",
            name,
            t.elapsed().as_millis(),
            e
        );
    }
    fn skip(&mut self, name: &str) {
        println!("skip  {name:<48}");
    }
    fn finish(&self) {
        println!("{} passed, {} failed", self.passed, self.failed);
        if self.failed > 0 {
            std::process::exit(1);
        }
    }
}

fn expect(cond: bool, msg: &'static str) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(Error::BadData(msg))
    }
}

/// `3` becomes `/dev/i2c-3`; anything else is taken as a device path.
fn bus_path(arg: &str) -> String {
    if arg.chars().all(|c| c.is_ascii_digit()) {
        format!("/dev/i2c-{arg}")
    } else {
        arg.to_string()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 0xE0E0 may hold the certificate bare, or wrapped in the chip's "TLS
/// identity" header: tag 0xC0, 2-byte length, then a 3-byte-length chain
/// where each certificate is prefixed by its own 3-byte length (9 bytes
/// total before the first DER byte).
fn strip_cert_header(raw: &[u8]) -> Result<&[u8], Error> {
    match raw.first() {
        Some(0x30) => Ok(raw),
        Some(0xC0) if raw.len() > 9 => Ok(&raw[9..]),
        _ => Err(Error::BadData("unknown certificate framing")),
    }
}

/// Locate a P-256 SubjectPublicKeyInfo inside a DER certificate and return
/// the uncompressed point. Looks for the prime256v1 OID followed by the
/// BIT STRING wrapper, which is how every X.509 encoder lays it out.
fn find_p256_spki(der: &[u8]) -> Option<&[u8]> {
    const OID: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let i = der.windows(OID.len()).position(|w| w == OID)?;
    let rest = &der[i + OID.len()..];
    if rest.len() < 4 + 65 || rest[..4] != [0x03, 0x42, 0x00, 0x04] {
        return None;
    }
    Some(&rest[3..3 + 65])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_search() {
        let mut der = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB];
        der.extend_from_slice(&[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
        der.extend_from_slice(&[0x03, 0x42, 0x00, 0x04]);
        der.extend(std::iter::repeat_n(0x11, 64));
        der.push(0xFF);
        let p = find_p256_spki(&der).unwrap();
        assert_eq!(p.len(), 65);
        assert_eq!(p[0], 0x04);
        assert!(find_p256_spki(&der[..30]).is_none());
    }

    #[test]
    fn cert_framing() {
        let bare = [0x30, 0x82, 0x01];
        assert_eq!(strip_cert_header(&bare).unwrap(), &bare);
        let mut wrapped = vec![0xC0, 0x01, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0xFA];
        wrapped.extend_from_slice(&bare);
        assert_eq!(strip_cert_header(&wrapped).unwrap(), &bare);
        assert!(strip_cert_header(&[0x00]).is_err());
    }

    #[test]
    fn bus_argument() {
        assert_eq!(bus_path("3"), "/dev/i2c-3");
        assert_eq!(bus_path("/dev/i2c-3"), "/dev/i2c-3");
        assert_eq!(bus_path("/dev/custom"), "/dev/custom");
    }
}
