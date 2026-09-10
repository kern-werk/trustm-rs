//! Safe, blocking Rust API for the Infineon OPTIGA™ Trust M secure element.
//!
//! The chip is driven over I2C through Infineon's host library, which
//! [`trustm_sys`] compiles from source. That library is asynchronous: every
//! command returns immediately and reports completion through a callback.
//! This crate hides that behind ordinary blocking methods on [`Trustm`].
//!
//! ```no_run
//! use trustm::{EccCurve, KeyId, KeyUsage, Trustm};
//!
//! let mut chip = Trustm::open("/dev/i2c-1", 0x30)?;
//! let public_key = chip.ecc_generate_keypair(EccCurve::NistP256, KeyUsage::SIGN, KeyId::E0F1)?;
//! let digest = chip.hash_sha256(b"hello")?;
//! let signature = chip.ecdsa_sign(KeyId::E0F1, &digest)?;
//! chip.ecdsa_verify(EccCurve::NistP256, &public_key, &digest, &signature)?;
//! # Ok::<(), trustm::Error>(())
//! ```
//!
//! Data formats follow the chip, not any particular crypto crate:
//!
//! - ECC public keys are DER `BIT STRING`s wrapping the uncompressed point
//!   (`03 len 00 04 x y`). [`ecc_public_key_point`] strips the wrapper.
//! - ECDSA signatures are two bare DER `INTEGER`s, `r` then `s`, with no
//!   enclosing `SEQUENCE`. [`ecdsa_signature_to_rs`] converts to fixed-width
//!   `r || s` as used by JWS, COSE and most Rust crates.
//! - RSA public keys are DER `SubjectPublicKeyInfo`-style as exported by the
//!   chip; consult the Solution Reference Manual for the exact encoding.
//!
//! One handle per process: the host library keeps global state and the chip
//! serves one command at a time. [`Trustm`] is `Send` but not `Sync`; put it
//! in a `Mutex` to share it between threads.
//!
//! # Hardware assumptions not yet verified on silicon
//!
//! - ECC public keys are exported as `03 len 00 04 x y`.
//! - Reset type 1 (soft reset over I2C) works with no reset/VDD GPIO wired.
//! - `optiga_util_open_application(restore = 0)` on every open is fine for
//!   the intended call pattern (short-lived processes).
//! - Buffer sizes chosen here (2048 for data objects, 512 for RSA public
//!   keys, 160 for ECDSA signatures) cover every object the chip exposes.

mod types;

pub use trustm_sys as sys;
pub use types::*;

use std::ffi::CString;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};

/// Default I2C bus device node.
pub const DEFAULT_BUS: &str = "/dev/i2c-1";
/// Default 7-bit I2C slave address of the Trust M.
pub const DEFAULT_ADDR: u8 = 0x30;

static OPEN: AtomicBool = AtomicBool::new(false);
static STATUS: AtomicU16 = AtomicU16::new(0);

extern "C" fn on_done(_ctx: *mut c_void, status: u16) {
    STATUS.store(status, Ordering::SeqCst);
}

/// An open session with the chip.
pub struct Trustm {
    util: *mut sys::optiga_util_t,
    crypt: *mut sys::optiga_crypt_t,
    timeout: Duration,
    _bus: CString,
}

impl Trustm {
    /// Open the chip on `bus` (e.g. `/dev/i2c-1`) at 7-bit address `addr`
    /// and start its application. Fails if a handle is already open.
    pub fn open(bus: &str, addr: u8) -> Result<Self> {
        if OPEN.swap(true, Ordering::SeqCst) {
            return Err(Error::AlreadyOpen);
        }
        match Self::open_inner(bus, addr) {
            Ok(me) => Ok(me),
            Err(e) => {
                OPEN.store(false, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    /// [`Trustm::open`] with [`DEFAULT_BUS`] and [`DEFAULT_ADDR`].
    pub fn open_default() -> Result<Self> {
        Self::open(DEFAULT_BUS, DEFAULT_ADDR)
    }

    fn open_inner(bus: &str, addr: u8) -> Result<Self> {
        let bus = CString::new(bus).map_err(|_| Error::InvalidArgument("bus path"))?;
        // SAFETY: `bus` is kept alive in the struct; the C side only stores
        // the pointer. The library instances are freed in Drop.
        unsafe {
            sys::trustm_sys_configure(bus.as_ptr(), addr);
            let util = sys::optiga_util_create(0, Some(on_done), std::ptr::null_mut());
            if util.is_null() {
                return Err(Error::Instance);
            }
            let crypt = sys::optiga_crypt_create(0, Some(on_done), std::ptr::null_mut());
            if crypt.is_null() {
                sys::optiga_util_destroy(util);
                return Err(Error::Instance);
            }
            let mut me = Self {
                util,
                crypt,
                timeout: Duration::from_secs(10),
                _bus: bus,
            };
            let r = me.run(|| sys::optiga_util_open_application(util, 0));
            if let Err(e) = r {
                // Drop will destroy the instances and clear OPEN's guard
                // through the caller.
                drop(me);
                return Err(e);
            }
            Ok(me)
        }
    }

    /// How long to wait for the chip to answer one command. Default 10 s.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Issue one asynchronous library call and block until its callback.
    fn run(&mut self, call: impl FnOnce() -> u16) -> Result<()> {
        STATUS.store(sys::OPTIGA_LIB_BUSY as u16, Ordering::SeqCst);
        Error::from_status(call())?;
        let start = Instant::now();
        loop {
            let s = STATUS.load(Ordering::SeqCst);
            if s as u32 != sys::OPTIGA_LIB_BUSY {
                return Error::from_status(s);
            }
            if start.elapsed() > self.timeout {
                return Err(Error::Timeout);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Close the application on the chip. Dropping the handle without
    /// calling this only frees host-side resources.
    pub fn close(mut self) -> Result<()> {
        let util = self.util;
        // SAFETY: util is a live instance owned by self.
        self.run(|| unsafe { sys::optiga_util_close_application(util, 0) })
    }

    // -----------------------------------------------------------------------
    // Data objects
    // -----------------------------------------------------------------------

    /// Read a data object (certificate, arbitrary data, counter, ...).
    pub fn read_data(&mut self, oid: u16, offset: u16) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let mut len = buf.len() as u16;
        let util = self.util;
        // SAFETY: buffer and length are valid for the duration of the call.
        self.run(|| unsafe {
            sys::optiga_util_read_data(util, oid, offset, buf.as_mut_ptr(), &mut len)
        })?;
        buf.truncate(len as usize);
        Ok(buf)
    }

    pub fn write_data(
        &mut self,
        oid: u16,
        mode: WriteType,
        offset: u16,
        data: &[u8],
    ) -> Result<()> {
        let len = u16::try_from(data.len()).map_err(|_| Error::InvalidArgument("data too long"))?;
        let util = self.util;
        // SAFETY: data outlives the call.
        self.run(|| unsafe {
            sys::optiga_util_write_data(util, oid, mode.raw(), offset, data.as_ptr(), len)
        })
    }

    /// Raw TLV metadata of a data object or key slot.
    pub fn read_metadata(&mut self, oid: u16) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 256];
        let mut len = buf.len() as u16;
        let util = self.util;
        // SAFETY: buffer and length are valid for the duration of the call.
        self.run(|| unsafe {
            sys::optiga_util_read_metadata(util, oid, buf.as_mut_ptr(), &mut len)
        })?;
        buf.truncate(len as usize);
        Ok(buf)
    }

    /// Write TLV metadata. Irreversible for some fields (lifecycle state);
    /// read the Solution Reference Manual first.
    pub fn write_metadata(&mut self, oid: u16, metadata: &[u8]) -> Result<()> {
        let len = u8::try_from(metadata.len())
            .map_err(|_| Error::InvalidArgument("metadata too long"))?;
        let util = self.util;
        // SAFETY: metadata outlives the call.
        self.run(|| unsafe { sys::optiga_util_write_metadata(util, oid, metadata.as_ptr(), len) })
    }

    /// Increment a monotonic counter object (0xE120..0xE123) by `count`.
    pub fn update_counter(&mut self, oid: u16, count: u8) -> Result<()> {
        let util = self.util;
        // SAFETY: plain values.
        self.run(|| unsafe { sys::optiga_util_update_count(util, oid, count) })
    }

    // -----------------------------------------------------------------------
    // Random and hash
    // -----------------------------------------------------------------------

    /// `len` random bytes from the chip. The chip accepts 8..=256 per call.
    pub fn random(&mut self, rng: RngType, len: u16) -> Result<Vec<u8>> {
        if !(8..=256).contains(&len) {
            return Err(Error::InvalidArgument("random length must be 8..=256"));
        }
        let mut buf = vec![0u8; len as usize];
        let crypt = self.crypt;
        // SAFETY: buffer is len bytes.
        self.run(|| unsafe { sys::optiga_crypt_random(crypt, rng.raw(), buf.as_mut_ptr(), len) })?;
        Ok(buf)
    }

    /// SHA-256 computed by the chip.
    pub fn hash_sha256(&mut self, data: &[u8]) -> Result<[u8; 32]> {
        let len = u32::try_from(data.len()).map_err(|_| Error::InvalidArgument("data too long"))?;
        let src = sys::hash_data_from_host_t {
            buffer: data.as_ptr(),
            length: len,
        };
        let mut out = [0u8; 32];
        let crypt = self.crypt;
        // SAFETY: src and out live across the call.
        self.run(|| unsafe {
            sys::optiga_crypt_hash(
                crypt,
                sys::optiga_hash_type::OPTIGA_HASH_TYPE_SHA_256,
                sys::OPTIGA_CRYPT_HOST_DATA as u8,
                &src as *const _ as *const c_void,
                out.as_mut_ptr(),
            )
        })?;
        Ok(out)
    }

    /// SHA-256 over `len` bytes of a data object, computed by the chip.
    pub fn hash_sha256_oid(&mut self, oid: u16, offset: u16, len: u16) -> Result<[u8; 32]> {
        let src = sys::hash_data_in_optiga_t {
            oid,
            offset,
            length: len,
        };
        let mut out = [0u8; 32];
        let crypt = self.crypt;
        // SAFETY: src and out live across the call.
        self.run(|| unsafe {
            sys::optiga_crypt_hash(
                crypt,
                sys::optiga_hash_type::OPTIGA_HASH_TYPE_SHA_256,
                sys::OPTIGA_CRYPT_OID_DATA as u8,
                &src as *const _ as *const c_void,
                out.as_mut_ptr(),
            )
        })?;
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // ECC
    // -----------------------------------------------------------------------

    /// Generate an ECC key pair in `slot`. Returns the DER-encoded public key.
    /// The private key never leaves the chip.
    pub fn ecc_generate_keypair(
        &mut self,
        curve: EccCurve,
        usage: KeyUsage,
        slot: KeyId,
    ) -> Result<Vec<u8>> {
        let mut oid = slot.raw();
        let mut pub_key = vec![0u8; 256];
        let mut pub_len = pub_key.len() as u16;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_ecc_generate_keypair(
                crypt,
                curve.raw(),
                usage.0,
                0,
                &mut oid as *mut sys::optiga_key_id::Type as *mut c_void,
                pub_key.as_mut_ptr(),
                &mut pub_len,
            )
        })?;
        pub_key.truncate(pub_len as usize);
        Ok(pub_key)
    }

    /// Generate an ECC key pair and export both halves to the host, DER
    /// encoded. Nothing is stored on the chip.
    pub fn ecc_generate_keypair_exported(&mut self, curve: EccCurve) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut priv_key = vec![0u8; 256];
        let mut pub_key = vec![0u8; 256];
        let mut pub_len = pub_key.len() as u16;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_ecc_generate_keypair(
                crypt,
                curve.raw(),
                0,
                1,
                priv_key.as_mut_ptr() as *mut c_void,
                pub_key.as_mut_ptr(),
                &mut pub_len,
            )
        })?;
        pub_key.truncate(pub_len as usize);
        // The private key length is not reported; it is a DER OCTET STRING.
        let priv_len = der_len(&priv_key).ok_or(Error::BadData("private key DER"))?;
        priv_key.truncate(priv_len);
        Ok((priv_key, pub_key))
    }

    /// ECDSA over a digest with the key in `slot`. The digest must already be
    /// hashed; up to 64 bytes. Output is `r` and `s` as two DER INTEGERs.
    pub fn ecdsa_sign(&mut self, slot: KeyId, digest: &[u8]) -> Result<Vec<u8>> {
        let dlen =
            u8::try_from(digest.len()).map_err(|_| Error::InvalidArgument("digest too long"))?;
        let mut sig = vec![0u8; 160];
        let mut sig_len = sig.len() as u16;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_ecdsa_sign(
                crypt,
                digest.as_ptr(),
                dlen,
                slot.raw(),
                sig.as_mut_ptr(),
                &mut sig_len,
            )
        })?;
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    /// Verify an ECDSA signature (chip format, see [`Trustm::ecdsa_sign`])
    /// against a DER public key supplied by the host.
    pub fn ecdsa_verify(
        &mut self,
        curve: EccCurve,
        public_key: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let dlen =
            u8::try_from(digest.len()).map_err(|_| Error::InvalidArgument("digest too long"))?;
        let slen = u16::try_from(signature.len())
            .map_err(|_| Error::InvalidArgument("signature too long"))?;
        let klen = u16::try_from(public_key.len())
            .map_err(|_| Error::InvalidArgument("public key too long"))?;
        let key = sys::public_key_from_host_t {
            public_key: public_key.as_ptr() as *mut u8,
            length: klen,
            key_type: curve.raw() as u8,
        };
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_ecdsa_verify(
                crypt,
                digest.as_ptr(),
                dlen,
                signature.as_ptr(),
                slen,
                sys::OPTIGA_CRYPT_HOST_DATA as u8,
                &key as *const _ as *const c_void,
            )
        })
    }

    /// Verify against a public key stored in a data object on the chip.
    pub fn ecdsa_verify_oid(
        &mut self,
        public_key_oid: u16,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let dlen =
            u8::try_from(digest.len()).map_err(|_| Error::InvalidArgument("digest too long"))?;
        let slen = u16::try_from(signature.len())
            .map_err(|_| Error::InvalidArgument("signature too long"))?;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_ecdsa_verify(
                crypt,
                digest.as_ptr(),
                dlen,
                signature.as_ptr(),
                slen,
                sys::OPTIGA_CRYPT_OID_DATA as u8,
                &public_key_oid as *const u16 as *const c_void,
            )
        })
    }

    /// ECDH shared secret between the private key in `slot` and a peer's DER
    /// public key. Returned to the host, `curve.component_len()` bytes.
    pub fn ecdh(
        &mut self,
        slot: KeyId,
        curve: EccCurve,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let klen = u16::try_from(peer_public_key.len())
            .map_err(|_| Error::InvalidArgument("public key too long"))?;
        let mut key = sys::public_key_from_host_t {
            public_key: peer_public_key.as_ptr() as *mut u8,
            length: klen,
            key_type: curve.raw() as u8,
        };
        let mut secret = vec![0u8; curve.component_len()];
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_ecdh(crypt, slot.raw(), &mut key, 1, secret.as_mut_ptr())
        })?;
        Ok(secret)
    }

    // -----------------------------------------------------------------------
    // RSA
    // -----------------------------------------------------------------------

    /// Generate an RSA key pair in `slot` (0xE0FC or 0xE0FD). Returns the
    /// DER-encoded public key.
    pub fn rsa_generate_keypair(
        &mut self,
        key_type: RsaKeyType,
        usage: KeyUsage,
        slot: KeyId,
    ) -> Result<Vec<u8>> {
        let mut oid = slot.raw();
        let mut pub_key = vec![0u8; 512];
        let mut pub_len = pub_key.len() as u16;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_rsa_generate_keypair(
                crypt,
                key_type.raw(),
                usage.0,
                0,
                &mut oid as *mut sys::optiga_key_id::Type as *mut c_void,
                pub_key.as_mut_ptr(),
                &mut pub_len,
            )
        })?;
        pub_key.truncate(pub_len as usize);
        Ok(pub_key)
    }

    /// RSASSA-PKCS1-v1_5 signature over a digest.
    pub fn rsa_sign(
        &mut self,
        scheme: RsaSignatureScheme,
        slot: KeyId,
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        let dlen =
            u8::try_from(digest.len()).map_err(|_| Error::InvalidArgument("digest too long"))?;
        let mut sig = vec![0u8; 256];
        let mut sig_len = sig.len() as u16;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_rsa_sign(
                crypt,
                scheme.raw(),
                digest.as_ptr(),
                dlen,
                slot.raw(),
                sig.as_mut_ptr(),
                &mut sig_len,
                0,
            )
        })?;
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    /// Verify an RSASSA-PKCS1-v1_5 signature against a host-supplied DER key.
    pub fn rsa_verify(
        &mut self,
        scheme: RsaSignatureScheme,
        key_type: RsaKeyType,
        public_key: &[u8],
        digest: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let dlen =
            u8::try_from(digest.len()).map_err(|_| Error::InvalidArgument("digest too long"))?;
        let slen = u16::try_from(signature.len())
            .map_err(|_| Error::InvalidArgument("signature too long"))?;
        let klen = u16::try_from(public_key.len())
            .map_err(|_| Error::InvalidArgument("public key too long"))?;
        let key = sys::public_key_from_host_t {
            public_key: public_key.as_ptr() as *mut u8,
            length: klen,
            key_type: key_type.raw() as u8,
        };
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_rsa_verify(
                crypt,
                scheme.raw(),
                digest.as_ptr(),
                dlen,
                signature.as_ptr(),
                slen,
                sys::OPTIGA_CRYPT_HOST_DATA as u8,
                &key as *const _ as *const c_void,
                0,
            )
        })
    }

    /// RSAES-PKCS1-v1_5 encryption of a short message with a host-supplied
    /// DER public key.
    pub fn rsa_encrypt(
        &mut self,
        key_type: RsaKeyType,
        public_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let mlen =
            u16::try_from(message.len()).map_err(|_| Error::InvalidArgument("message too long"))?;
        let klen = u16::try_from(public_key.len())
            .map_err(|_| Error::InvalidArgument("public key too long"))?;
        let key = sys::public_key_from_host_t {
            public_key: public_key.as_ptr() as *mut u8,
            length: klen,
            key_type: key_type.raw() as u8,
        };
        let mut out = vec![0u8; key_type.modulus_len()];
        let mut out_len = out.len() as u16;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_rsa_encrypt_message(
                crypt,
                sys::optiga_rsa_encryption_scheme::OPTIGA_RSAES_PKCS1_V15,
                message.as_ptr(),
                mlen,
                std::ptr::null(),
                0,
                sys::OPTIGA_CRYPT_HOST_DATA as u8,
                &key as *const _ as *const c_void,
                out.as_mut_ptr(),
                &mut out_len,
            )
        })?;
        out.truncate(out_len as usize);
        Ok(out)
    }

    /// RSAES-PKCS1-v1_5 decryption with the private key in `slot`, result
    /// exported to the host.
    pub fn rsa_decrypt(&mut self, slot: KeyId, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let clen = u16::try_from(ciphertext.len())
            .map_err(|_| Error::InvalidArgument("ciphertext too long"))?;
        let mut out = vec![0u8; 256];
        let mut out_len = out.len() as u16;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_rsa_decrypt_and_export(
                crypt,
                sys::optiga_rsa_encryption_scheme::OPTIGA_RSAES_PKCS1_V15,
                ciphertext.as_ptr(),
                clen,
                std::ptr::null(),
                0,
                slot.raw(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        })?;
        out.truncate(out_len as usize);
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Symmetric, MAC and key derivation
    // -----------------------------------------------------------------------

    /// HMAC with a secret held in data object `secret_oid`.
    pub fn hmac(&mut self, kind: HmacType, secret_oid: u16, data: &[u8]) -> Result<Vec<u8>> {
        let dlen =
            u32::try_from(data.len()).map_err(|_| Error::InvalidArgument("data too long"))?;
        let mut mac = vec![0u8; kind.mac_len()];
        let mut mac_len = mac.len() as u32;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_hmac(
                crypt,
                kind.raw(),
                secret_oid,
                data.as_ptr(),
                dlen,
                mac.as_mut_ptr(),
                &mut mac_len,
            )
        })?;
        mac.truncate(mac_len as usize);
        Ok(mac)
    }

    /// HKDF from a secret in `secret_oid`, `len` bytes exported to the host.
    pub fn hkdf(
        &mut self,
        kind: HkdfType,
        secret_oid: u16,
        salt: &[u8],
        info: &[u8],
        len: u16,
    ) -> Result<Vec<u8>> {
        let slen =
            u16::try_from(salt.len()).map_err(|_| Error::InvalidArgument("salt too long"))?;
        let ilen =
            u16::try_from(info.len()).map_err(|_| Error::InvalidArgument("info too long"))?;
        let mut out = vec![0u8; len as usize];
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_hkdf(
                crypt,
                kind.raw(),
                secret_oid,
                salt.as_ptr(),
                slen,
                info.as_ptr(),
                ilen,
                len,
                1,
                out.as_mut_ptr(),
            )
        })?;
        Ok(out)
    }

    /// TLS 1.2 PRF from a secret in `secret_oid`, `len` bytes to the host.
    pub fn tls_prf(
        &mut self,
        kind: TlsPrfType,
        secret_oid: u16,
        label: &[u8],
        seed: &[u8],
        len: u16,
    ) -> Result<Vec<u8>> {
        let llen =
            u16::try_from(label.len()).map_err(|_| Error::InvalidArgument("label too long"))?;
        let slen =
            u16::try_from(seed.len()).map_err(|_| Error::InvalidArgument("seed too long"))?;
        let mut out = vec![0u8; len as usize];
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_tls_prf(
                crypt,
                kind.raw(),
                secret_oid,
                label.as_ptr(),
                llen,
                seed.as_ptr(),
                slen,
                len,
                1,
                out.as_mut_ptr(),
            )
        })?;
        Ok(out)
    }

    /// Generate an AES key in the symmetric slot ([`KeyId::SecretBased`]).
    pub fn symmetric_generate_key(
        &mut self,
        key_type: SymmetricKeyType,
        usage: KeyUsage,
    ) -> Result<()> {
        let mut oid = KeyId::SecretBased.raw();
        let crypt = self.crypt;
        // SAFETY: oid outlives the call.
        self.run(|| unsafe {
            sys::optiga_crypt_symmetric_generate_key(
                crypt,
                key_type.raw(),
                usage.0,
                0,
                &mut oid as *mut sys::optiga_key_id::Type as *mut c_void,
            )
        })
    }

    /// AES-ECB with the key in the symmetric slot. Input must be a multiple
    /// of 16 bytes.
    pub fn aes_ecb_encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let plen =
            u32::try_from(plain.len()).map_err(|_| Error::InvalidArgument("data too long"))?;
        let mut out = vec![0u8; plain.len()];
        let mut out_len = out.len() as u32;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_symmetric_encrypt_ecb(
                crypt,
                KeyId::SecretBased.raw(),
                plain.as_ptr(),
                plen,
                out.as_mut_ptr(),
                &mut out_len,
            )
        })?;
        out.truncate(out_len as usize);
        Ok(out)
    }

    pub fn aes_ecb_decrypt(&mut self, cipher: &[u8]) -> Result<Vec<u8>> {
        let clen =
            u32::try_from(cipher.len()).map_err(|_| Error::InvalidArgument("data too long"))?;
        let mut out = vec![0u8; cipher.len()];
        let mut out_len = out.len() as u32;
        let crypt = self.crypt;
        // SAFETY: all pointers reference locals that outlive the call.
        self.run(|| unsafe {
            sys::optiga_crypt_symmetric_decrypt_ecb(
                crypt,
                KeyId::SecretBased.raw(),
                cipher.as_ptr(),
                clen,
                out.as_mut_ptr(),
                &mut out_len,
            )
        })?;
        out.truncate(out_len as usize);
        Ok(out)
    }
}

// SAFETY: the two library instances are heap objects with no thread affinity
// (the host library uses no thread-local state; its completion callback runs
// on a PAL timer thread regardless of which thread issued the command). All
// methods take `&mut self`, so only one thread drives the chip at a time.
// Not `Sync`: wrap in a `Mutex` to share.
unsafe impl Send for Trustm {}

impl Drop for Trustm {
    fn drop(&mut self) {
        // SAFETY: both instances were created in open_inner and are destroyed
        // exactly once here.
        unsafe {
            sys::optiga_crypt_destroy(self.crypt);
            sys::optiga_util_destroy(self.util);
        }
        OPEN.store(false, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Format helpers. Pure functions, no chip needed.
// ---------------------------------------------------------------------------

/// Total length of a DER element (tag + length + content) at the start of
/// `buf`, for short and long-form lengths up to two bytes.
fn der_len(buf: &[u8]) -> Option<usize> {
    let l = *buf.get(1)?;
    match l {
        0..=0x7F => Some(2 + l as usize),
        0x81 => Some(3 + *buf.get(2)? as usize),
        0x82 => Some(4 + ((*buf.get(2)? as usize) << 8 | *buf.get(3)? as usize)),
        _ => None,
    }
}

/// Strip the DER `BIT STRING` wrapper from an ECC public key as exported by
/// the chip, leaving the uncompressed point `04 || x || y`. A bare point is
/// returned unchanged.
pub fn ecc_public_key_point(der: &[u8]) -> Result<&[u8]> {
    match der {
        [0x04, ..] => Ok(der),
        [0x03, ..] => {
            let total = der_len(der).ok_or(Error::BadData("public key length"))?;
            if total != der.len() {
                return Err(Error::BadData("public key length"));
            }
            let hdr = total - der.len()
                + if der[1] < 0x80 {
                    2
                } else {
                    2 + (der[1] & 0x7F) as usize
                };
            // One "unused bits" byte follows the length, then the point.
            let point = der
                .get(hdr + 1..)
                .ok_or(Error::BadData("public key too short"))?;
            if point.first() != Some(&0x04) {
                return Err(Error::BadData("public key is not an uncompressed point"));
            }
            Ok(point)
        }
        _ => Err(Error::BadData("public key encoding")),
    }
}

/// Convert a chip ECDSA signature (two bare DER `INTEGER`s) into fixed-width
/// `r || s`, `2 * component_len` bytes, as used by JWS and most Rust crates.
pub fn ecdsa_signature_to_rs(sig: &[u8], component_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; component_len * 2];
    let used_r = der_uint_into(sig, &mut out[..component_len])?;
    let used_s = der_uint_into(&sig[used_r..], &mut out[component_len..])?;
    if used_r + used_s != sig.len() {
        return Err(Error::BadData("trailing bytes after signature"));
    }
    Ok(out)
}

/// Convert fixed-width `r || s` into the chip's signature format, for
/// [`Trustm::ecdsa_verify`].
pub fn ecdsa_signature_from_rs(rs: &[u8]) -> Result<Vec<u8>> {
    if rs.is_empty() || !rs.len().is_multiple_of(2) {
        return Err(Error::InvalidArgument("r||s must have even length"));
    }
    let half = rs.len() / 2;
    let mut out = Vec::with_capacity(rs.len() + 6);
    for part in [&rs[..half], &rs[half..]] {
        let mut v = part;
        while v.len() > 1 && v[0] == 0 {
            v = &v[1..];
        }
        let pad = v[0] & 0x80 != 0;
        out.push(0x02);
        out.push((v.len() + pad as usize) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(v);
    }
    Ok(out)
}

fn der_uint_into(buf: &[u8], out: &mut [u8]) -> Result<usize> {
    if buf.len() < 2 || buf[0] != 0x02 {
        return Err(Error::BadData("expected DER INTEGER"));
    }
    let len = buf[1] as usize;
    if len == 0 || len >= 0x80 || buf.len() < 2 + len {
        return Err(Error::BadData("DER INTEGER length"));
    }
    let mut v = &buf[2..2 + len];
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    if v.len() > out.len() {
        return Err(Error::BadData("integer wider than the curve"));
    }
    out.fill(0);
    let start = out.len() - v.len();
    out[start..].copy_from_slice(v);
    Ok(2 + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_roundtrip() {
        let mut rs = vec![0u8; 64];
        rs[0] = 0x80; // r has the high bit set: needs a padding zero in DER
        rs[63] = 0x01; // s = 1: minimal DER is a single byte
        let der = ecdsa_signature_from_rs(&rs).unwrap();
        assert_eq!(&der[..3], &[0x02, 0x21, 0x00]);
        assert_eq!(&der[der.len() - 3..], &[0x02, 0x01, 0x01]);
        assert_eq!(ecdsa_signature_to_rs(&der, 32).unwrap(), rs);
    }

    #[test]
    fn signature_rejects_garbage() {
        assert!(
            ecdsa_signature_to_rs(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], 32).is_err()
        );
        assert!(ecdsa_signature_to_rs(&[0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00], 32).is_err());
        assert!(ecdsa_signature_to_rs(&[], 32).is_err());
        assert!(ecdsa_signature_from_rs(&[1, 2, 3]).is_err());
    }

    #[test]
    fn public_key_unwrap() {
        let mut point = vec![0x04];
        point.extend(std::iter::repeat_n(0xAB, 64));
        let mut der = vec![0x03, 0x42, 0x00];
        der.extend_from_slice(&point);
        assert_eq!(ecc_public_key_point(&der).unwrap(), &point[..]);
        assert_eq!(ecc_public_key_point(&point).unwrap(), &point[..]);
        assert!(ecc_public_key_point(&der[..10]).is_err());
        assert!(ecc_public_key_point(&[0x02, 0x01, 0x01]).is_err());
        // Long-form length (P-521 point is 133 bytes + 1)
        let mut p521 = vec![0x04];
        p521.extend(std::iter::repeat_n(0xCD, 132));
        let mut der = vec![0x03, 0x81, 0x86, 0x00];
        der.extend_from_slice(&p521);
        assert_eq!(ecc_public_key_point(&der).unwrap(), &p521[..]);
    }

    #[test]
    fn error_names() {
        assert_eq!(
            Error::status_name(0x8007),
            Some("chip: access conditions not satisfied")
        );
        assert_eq!(Error::status_name(0x0403), Some("crypt: invalid input"));
        assert_eq!(Error::status_name(0x1234), None);
        assert_eq!(
            Error::Status(0x8001).to_string(),
            "OPTIGA error 0x8001 (chip: invalid OID)"
        );
    }

    #[test]
    fn key_usage_or() {
        assert_eq!((KeyUsage::SIGN | KeyUsage::KEY_AGREEMENT).0, 0x30);
        assert_eq!(KeyId::E0F1.raw(), 0xE0F1);
        assert_eq!(EccCurve::NistP521.component_len(), 66);
    }
}
