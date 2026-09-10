//! Enums and the error type. Each enum maps one to one onto a constant in
//! `trustm_sys`; the `raw()` methods give the C value.

use std::fmt;
use trustm_sys as sys;

/// Key slots on the chip.
///
/// 0xE0F0 holds the factory key with the Infineon-issued certificate in data
/// object 0xE0E0. 0xE0F1..0xE0F3 are free ECC slots, 0xE0FC..0xE0FD RSA
/// slots, 0xE200 the AES key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyId {
    E0F0,
    E0F1,
    E0F2,
    E0F3,
    E0FC,
    E0FD,
    /// Symmetric (AES) key slot 0xE200.
    SecretBased,
    /// Volatile key from the current session (e.g. an exported ECDH context).
    SessionBased,
}

impl KeyId {
    pub fn raw(self) -> sys::optiga_key_id::Type {
        match self {
            KeyId::E0F0 => sys::optiga_key_id::OPTIGA_KEY_ID_E0F0,
            KeyId::E0F1 => sys::optiga_key_id::OPTIGA_KEY_ID_E0F1,
            KeyId::E0F2 => sys::optiga_key_id::OPTIGA_KEY_ID_E0F2,
            KeyId::E0F3 => sys::optiga_key_id::OPTIGA_KEY_ID_E0F3,
            KeyId::E0FC => sys::optiga_key_id::OPTIGA_KEY_ID_E0FC,
            KeyId::E0FD => sys::optiga_key_id::OPTIGA_KEY_ID_E0FD,
            KeyId::SecretBased => sys::optiga_key_id::OPTIGA_KEY_ID_SECRET_BASED,
            KeyId::SessionBased => sys::optiga_key_id::OPTIGA_KEY_ID_SESSION_BASED,
        }
    }
}

/// What a generated key may be used for. Combine with `|`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage(pub u8);

impl KeyUsage {
    pub const AUTHENTICATION: KeyUsage =
        KeyUsage(sys::optiga_key_usage::OPTIGA_KEY_USAGE_AUTHENTICATION as u8);
    pub const ENCRYPTION: KeyUsage =
        KeyUsage(sys::optiga_key_usage::OPTIGA_KEY_USAGE_ENCRYPTION as u8);
    pub const SIGN: KeyUsage = KeyUsage(sys::optiga_key_usage::OPTIGA_KEY_USAGE_SIGN as u8);
    pub const KEY_AGREEMENT: KeyUsage =
        KeyUsage(sys::optiga_key_usage::OPTIGA_KEY_USAGE_KEY_AGREEMENT as u8);
}

impl std::ops::BitOr for KeyUsage {
    type Output = KeyUsage;
    fn bitor(self, rhs: KeyUsage) -> KeyUsage {
        KeyUsage(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccCurve {
    NistP256,
    NistP384,
    NistP521,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

impl EccCurve {
    pub fn raw(self) -> sys::optiga_ecc_curve::Type {
        use sys::optiga_ecc_curve::*;
        match self {
            EccCurve::NistP256 => OPTIGA_ECC_CURVE_NIST_P_256,
            EccCurve::NistP384 => OPTIGA_ECC_CURVE_NIST_P_384,
            EccCurve::NistP521 => OPTIGA_ECC_CURVE_NIST_P_521,
            EccCurve::BrainpoolP256r1 => OPTIGA_ECC_CURVE_BRAIN_POOL_P_256R1,
            EccCurve::BrainpoolP384r1 => OPTIGA_ECC_CURVE_BRAIN_POOL_P_384R1,
            EccCurve::BrainpoolP512r1 => OPTIGA_ECC_CURVE_BRAIN_POOL_P_512R1,
        }
    }

    /// Size in bytes of one field element / one signature component.
    pub fn component_len(self) -> usize {
        match self {
            EccCurve::NistP256 | EccCurve::BrainpoolP256r1 => 32,
            EccCurve::NistP384 | EccCurve::BrainpoolP384r1 => 48,
            EccCurve::NistP521 => 66,
            EccCurve::BrainpoolP512r1 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyType {
    Rsa1024,
    Rsa2048,
}

impl RsaKeyType {
    pub fn raw(self) -> sys::optiga_rsa_key_type::Type {
        match self {
            RsaKeyType::Rsa1024 => sys::optiga_rsa_key_type::OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL,
            RsaKeyType::Rsa2048 => sys::optiga_rsa_key_type::OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL,
        }
    }
    pub fn modulus_len(self) -> usize {
        match self {
            RsaKeyType::Rsa1024 => 128,
            RsaKeyType::Rsa2048 => 256,
        }
    }
}

/// RSASSA-PKCS1-v1_5 with the given digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSignatureScheme {
    Pkcs1v15Sha256,
    Pkcs1v15Sha384,
    Pkcs1v15Sha512,
}

impl RsaSignatureScheme {
    pub fn raw(self) -> sys::optiga_rsa_signature_scheme::Type {
        use sys::optiga_rsa_signature_scheme::*;
        match self {
            RsaSignatureScheme::Pkcs1v15Sha256 => OPTIGA_RSASSA_PKCS1_V15_SHA256,
            RsaSignatureScheme::Pkcs1v15Sha384 => OPTIGA_RSASSA_PKCS1_V15_SHA384,
            RsaSignatureScheme::Pkcs1v15Sha512 => OPTIGA_RSASSA_PKCS1_V15_SHA512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacType {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacType {
    pub fn raw(self) -> sys::optiga_hmac_type::Type {
        match self {
            HmacType::Sha256 => sys::optiga_hmac_type::OPTIGA_HMAC_SHA_256,
            HmacType::Sha384 => sys::optiga_hmac_type::OPTIGA_HMAC_SHA_384,
            HmacType::Sha512 => sys::optiga_hmac_type::OPTIGA_HMAC_SHA_512,
        }
    }
    pub fn mac_len(self) -> usize {
        match self {
            HmacType::Sha256 => 32,
            HmacType::Sha384 => 48,
            HmacType::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfType {
    Sha256,
    Sha384,
    Sha512,
}

impl HkdfType {
    pub fn raw(self) -> sys::optiga_hkdf_type::Type {
        match self {
            HkdfType::Sha256 => sys::optiga_hkdf_type::OPTIGA_HKDF_SHA_256,
            HkdfType::Sha384 => sys::optiga_hkdf_type::OPTIGA_HKDF_SHA_384,
            HkdfType::Sha512 => sys::optiga_hkdf_type::OPTIGA_HKDF_SHA_512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPrfType {
    Sha256,
    Sha384,
    Sha512,
}

impl TlsPrfType {
    pub fn raw(self) -> sys::optiga_tls_prf_type::Type {
        match self {
            TlsPrfType::Sha256 => sys::optiga_tls_prf_type::OPTIGA_TLS12_PRF_SHA_256,
            TlsPrfType::Sha384 => sys::optiga_tls_prf_type::OPTIGA_TLS12_PRF_SHA_384,
            TlsPrfType::Sha512 => sys::optiga_tls_prf_type::OPTIGA_TLS12_PRF_SHA_512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymmetricKeyType {
    Aes128,
    Aes192,
    Aes256,
}

impl SymmetricKeyType {
    pub fn raw(self) -> sys::optiga_symmetric_key_type::Type {
        match self {
            SymmetricKeyType::Aes128 => sys::optiga_symmetric_key_type::OPTIGA_SYMMETRIC_AES_128,
            SymmetricKeyType::Aes192 => sys::optiga_symmetric_key_type::OPTIGA_SYMMETRIC_AES_192,
            SymmetricKeyType::Aes256 => sys::optiga_symmetric_key_type::OPTIGA_SYMMETRIC_AES_256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngType {
    /// True random number generator.
    Trng,
    /// Deterministic RNG seeded from the TRNG.
    Drng,
}

impl RngType {
    pub fn raw(self) -> sys::optiga_rng_type::Type {
        match self {
            RngType::Trng => sys::optiga_rng_type::OPTIGA_RNG_TYPE_TRNG,
            RngType::Drng => sys::optiga_rng_type::OPTIGA_RNG_TYPE_DRNG,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteType {
    /// Overwrite in place, keeping the rest of the object.
    WriteOnly,
    /// Erase the object, then write. The usual choice.
    EraseAndWrite,
}

impl WriteType {
    pub fn raw(self) -> u8 {
        match self {
            WriteType::WriteOnly => sys::OPTIGA_UTIL_WRITE_ONLY as u8,
            WriteType::EraseAndWrite => sys::OPTIGA_UTIL_ERASE_AND_WRITE as u8,
        }
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Status code returned by the host library or the chip. Codes with the
    /// top bit set (`0x8xxx`) come from the chip; the low byte is its reason.
    Status(u16),
    /// The chip did not answer within the timeout.
    Timeout,
    /// Could not create a library instance (out of instances or memory).
    Instance,
    /// Another `Trustm` handle is alive in this process.
    AlreadyOpen,
    /// A caller-supplied argument was out of range for the chip.
    InvalidArgument(&'static str),
    /// The chip returned data in a shape we could not parse.
    BadData(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn from_status(status: u16) -> Result<()> {
        if status as u32 == sys::OPTIGA_LIB_SUCCESS {
            Ok(())
        } else {
            Err(Error::Status(status))
        }
    }

    /// Human-readable name for a status code, when known.
    pub fn status_name(code: u16) -> Option<&'static str> {
        let c = code as u32;
        if c & sys::OPTIGA_DEVICE_ERROR != 0 {
            // Low byte: chip error codes from the Solution Reference Manual.
            return Some(match c & 0xFF {
                0x01 => "chip: invalid OID",
                0x03 => "chip: invalid parameter field",
                0x04 => "chip: invalid length field",
                0x05 => "chip: invalid parameter in data field",
                0x06 => "chip: internal process error",
                0x07 => "chip: access conditions not satisfied",
                0x08 => "chip: data object boundary exceeded",
                0x09 => "chip: metadata truncation error",
                0x0A => "chip: invalid command field",
                0x0B => "chip: command out of sequence",
                0x0C => "chip: command not available",
                0x0D => "chip: insufficient memory or buffer",
                0x0E => "chip: counter threshold limit exceeded",
                0x0F => "chip: invalid manifest",
                0x10 => "chip: wrong payload version",
                0x21 => "chip: unsorted input data",
                _ => return None,
            });
        }
        Some(match c {
            sys::OPTIGA_COMMS_ERROR => "comms error",
            sys::OPTIGA_COMMS_ERROR_INVALID_INPUT => "comms: invalid input",
            sys::OPTIGA_COMMS_ERROR_MEMORY_INSUFFICIENT => "comms: insufficient memory",
            sys::OPTIGA_COMMS_ERROR_STACK_MEMORY => "comms: stack memory",
            sys::OPTIGA_COMMS_ERROR_FATAL => "comms: fatal",
            sys::OPTIGA_COMMS_ERROR_HANDSHAKE => "comms: handshake",
            sys::OPTIGA_COMMS_ERROR_SESSION => "comms: session",
            sys::OPTIGA_CMD_ERROR => "cmd error",
            sys::OPTIGA_CMD_ERROR_INVALID_INPUT => "cmd: invalid input",
            sys::OPTIGA_CMD_ERROR_MEMORY_INSUFFICIENT => "cmd: insufficient memory",
            sys::OPTIGA_UTIL_ERROR => "util error",
            sys::OPTIGA_UTIL_ERROR_INVALID_INPUT => "util: invalid input",
            sys::OPTIGA_UTIL_ERROR_MEMORY_INSUFFICIENT => "util: insufficient memory",
            sys::OPTIGA_UTIL_ERROR_INSTANCE_IN_USE => "util: instance in use",
            sys::OPTIGA_CRYPT_ERROR => "crypt error",
            sys::OPTIGA_CRYPT_ERROR_INVALID_INPUT => "crypt: invalid input",
            sys::OPTIGA_CRYPT_ERROR_MEMORY_INSUFFICIENT => "crypt: insufficient memory",
            sys::OPTIGA_CRYPT_ERROR_INSTANCE_IN_USE => "crypt: instance in use",
            _ => return None,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Status(code) => match Error::status_name(*code) {
                Some(name) => write!(f, "OPTIGA error 0x{code:04X} ({name})"),
                None => write!(f, "OPTIGA error 0x{code:04X}"),
            },
            Error::Timeout => write!(f, "timed out waiting for the chip"),
            Error::Instance => write!(f, "could not create a host library instance"),
            Error::AlreadyOpen => write!(f, "a Trustm handle is already open in this process"),
            Error::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            Error::BadData(what) => write!(f, "unexpected data from the chip: {what}"),
        }
    }
}

impl std::error::Error for Error {}
