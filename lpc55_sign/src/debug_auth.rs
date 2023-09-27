use byteorder::LittleEndian;
use lpc55_areas::DebugSettings;
use num_traits::ToPrimitive;
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use zerocopy::{FromBytes, U16, U32};

use crate::{
    cert::public_key,
    signed_image::{pad_roots, root_key_hash},
    Error,
};

const SOCC: u32 = 0x0000_0001;

#[derive(Debug, FromBytes)]
#[repr(C)]
pub struct DebugAuthChallenge {
    // NXP UM11126 claims this is a single little-endian u32 version field.
    // NXP's spsdk tooling implements it as done here: two little-endian u16s
    // with version_major at the lower offset.  See
    // https://github.com/nxp-mcuxpresso/spsdk/blob/5da31d96a020bd65e5834ea5ac1b68327ea965ef/spsdk/dat/dac_packet.py#L114.
    pub version_major: U16<LittleEndian>,
    pub version_minor: U16<LittleEndian>,

    pub socc: U32<LittleEndian>,
    pub uuid: [u8; 16],

    pub rotk_revoke: U32<LittleEndian>,
    pub rotkh: [u8; 32],

    pub cc_socu_pin: U32<LittleEndian>,
    pub cc_socu_dflt: U32<LittleEndian>,
    pub vendor_usage: U32<LittleEndian>,

    pub challenge_vector: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DebugCredentialSigningRequest {
    pub debug_public_key: RsaPublicKey,
    // Serialize as a hex literal with mandatory 0x prefix:
    // 0x000102030405060708090a0b0c0d0e0f
    #[serde(with = "SerHex::<StrictPfx>")]
    pub uuid: [u8; 16],
    pub vendor_usage: u32,
    pub debug_settings: DebugSettings,
    pub beacon: u16,
}

pub fn debug_credential_tbs(
    root_certs: Vec<Certificate>,
    root_public_key: RsaPublicKey,
    dcsr: DebugCredentialSigningRequest,
) -> Result<Vec<u8>, Error> {
    root_certs
        .iter()
        .fold(Err(Error::RootNotFound), |acc, cert| {
            match public_key(cert) {
                Err(error) => Err(error),
                Ok(key) => {
                    if key == root_public_key {
                        Ok(())
                    } else {
                        acc
                    }
                }
            }
        })?;

    let debug_key_size_bits = dcsr.debug_public_key.size() * 8;
    let root_key_size_bits = root_public_key.size() * 8;
    if root_key_size_bits != debug_key_size_bits {
        return Err(Error::VaryingPublicKeySizes);
    };
    let (version_major, version_minor): (u16, u16) = match root_key_size_bits {
        2048 => (1, 0),
        4096 => (1, 1),
        _ => {
            return Err(Error::UnsupportedRsaKeySize {
                key_size: root_key_size_bits,
            })
        }
    };

    let mut dc_bytes: Vec<u8> = Vec::new();
    // NXP UM11126 claims this is a single little-endian u32 version field.
    // NXP's spsdk tooling implements it as done here: two little-endian u16s
    // with version_major at the lower offset.  See
    // https://github.com/nxp-mcuxpresso/spsdk/blob/5da31d96a020bd65e5834ea5ac1b68327ea965ef/spsdk/dat/debug_credential.py#L728.
    dc_bytes.extend_from_slice(&version_major.to_le_bytes());
    dc_bytes.extend_from_slice(&version_minor.to_le_bytes());
    dc_bytes.extend_from_slice(&SOCC.to_le_bytes());
    dc_bytes.extend_from_slice(&dcsr.uuid);

    // The hash of each root public key (i.e., of its raw `n` and `e` values).
    // These _must_ match the hash-of-hashes programmed in the CMPA!
    for root in pad_roots(root_certs)? {
        dc_bytes.extend_from_slice(&root_key_hash(root.as_ref())?);
    }

    dc_bytes.extend_from_slice(&dcsr.debug_public_key.n().to_bytes_be());
    dc_bytes.extend_from_slice(
        &dcsr
            .debug_public_key
            .e()
            .to_u32()
            .ok_or(Error::RsaExponentTooLarge)?
            .to_be_bytes(),
    );

    dc_bytes.extend_from_slice(&dcsr.debug_settings.debug_cred_socu().to_le_bytes());
    dc_bytes.extend_from_slice(&dcsr.vendor_usage.to_le_bytes());
    dc_bytes.extend_from_slice(&u32::from(dcsr.beacon).to_le_bytes());

    dc_bytes.extend_from_slice(&root_public_key.n().to_bytes_be());
    dc_bytes.extend_from_slice(
        &root_public_key
            .e()
            .to_u32()
            .ok_or(Error::RsaExponentTooLarge)?
            .to_be_bytes(),
    );

    Ok(dc_bytes)
}

pub fn debug_credential(
    root_certs: Vec<Certificate>,
    root_key: &RsaPrivateKey,
    debug_key: &RsaPublicKey,
    uuid: &[u8; 16],
    vendor_usage: u32,
    debug_settings: DebugSettings,
    beacon: u16,
) -> Result<Vec<u8>, Error> {
    let dcsr = DebugCredentialSigningRequest {
        debug_public_key: debug_key.clone(),
        uuid: *uuid,
        vendor_usage,
        debug_settings,
        beacon,
    };

    let dc_tbs = debug_credential_tbs(root_certs, root_key.to_public_key(), dcsr)?;

    let mut dc_hash = Sha256::new();
    dc_hash.update(&dc_tbs);

    let signature = root_key
        .sign(
            rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
            dc_hash.finalize().as_slice(),
        )
        .map_err(Error::SigningError)?;

    let mut dc = Vec::new();
    dc.extend_from_slice(&dc_tbs);
    dc.extend_from_slice(&signature);

    Ok(dc)
}

pub fn debug_auth_response(
    debug_cred: &[u8],
    debug_key: RsaPrivateKey,
    debug_auth_challenge: DebugAuthChallenge,
    beacon: u16,
) -> Result<Vec<u8>, Error> {
    // Probably should check debug_cred for compatibility with the provided
    // challenge but, for now, trust the user to provide correct inputs.

    let mut debug_auth_response = Vec::<u8>::new();
    debug_auth_response.extend_from_slice(debug_cred);
    debug_auth_response.extend_from_slice(&u32::from(beacon).to_le_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&debug_auth_response);
    hasher.update(debug_auth_challenge.challenge_vector);

    let signature = debug_key
        .sign(
            rsa::pkcs1v15::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
            hasher.finalize().as_slice(),
        )
        .map_err(Error::SigningError)?;

    debug_auth_response.extend_from_slice(&signature);

    Ok(debug_auth_response)
}
