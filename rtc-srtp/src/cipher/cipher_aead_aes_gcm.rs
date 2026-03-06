use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use ring::aead;

use super::{Cipher, Kdf};
use crate::key_derivation::*;
use crate::protection_profile::ProtectionProfile;
use shared::{
    error::{Error, Result},
    marshal::*,
};

pub const CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN: usize = 16;

const RTCP_ENCRYPTION_FLAG: u8 = 0x80;

/// AEAD Cipher based on AES.
pub(crate) struct CipherAeadAesGcm {
    profile: ProtectionProfile,
    srtp_cipher: aead::LessSafeKey,
    srtcp_cipher: aead::LessSafeKey,
    srtp_session_salt: Vec<u8>,
    srtcp_session_salt: Vec<u8>,
}

impl Cipher for CipherAeadAesGcm {
    fn rtp_auth_tag_len(&self) -> usize {
        self.profile.rtp_auth_tag_len()
    }

    /// Get RTCP authenticated tag length.
    fn rtcp_auth_tag_len(&self) -> usize {
        self.profile.rtcp_auth_tag_len()
    }

    /// Get AEAD auth key length of the cipher.
    fn aead_auth_tag_len(&self) -> usize {
        self.profile.aead_auth_tag_len()
    }

    fn encrypt_rtp(&mut self, payload: &[u8], header: &rtp::Header, roc: u32) -> Result<BytesMut> {
        // Grow the given buffer to fit the output.
        let header_len = header.marshal_size();
        let mut writer = BytesMut::with_capacity(payload.len() + self.aead_auth_tag_len());

        // Copy header unencrypted.
        writer.extend_from_slice(&payload[..header_len]);

        let nonce_bytes = self.rtp_initialization_vector(header, roc);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| Error::Other("invalid nonce".into()))?;
        let aad = aead::Aad::from(&writer[..]);

        // in_out = plaintext payload, will be encrypted in place with tag appended
        let mut in_out = payload[header_len..].to_vec();
        self.srtp_cipher
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| Error::Other("SRTP encrypt failed".into()))?;

        writer.extend_from_slice(&in_out);
        Ok(writer)
    }

    fn decrypt_rtp(
        &mut self,
        ciphertext: &[u8],
        header: &rtp::Header,
        roc: u32,
    ) -> Result<BytesMut> {
        if ciphertext.len() < self.aead_auth_tag_len() {
            return Err(Error::ErrFailedToVerifyAuthTag);
        }

        let nonce_bytes = self.rtp_initialization_vector(header, roc);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| Error::Other("invalid nonce".into()))?;
        let payload_offset = header.marshal_size();
        let aad = aead::Aad::from(&ciphertext[..payload_offset]);

        let mut in_out = ciphertext[payload_offset..].to_vec();
        let decrypted = self
            .srtp_cipher
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| Error::ErrFailedToVerifyAuthTag)?;

        let mut writer = BytesMut::with_capacity(payload_offset + decrypted.len());
        writer.extend_from_slice(&ciphertext[..payload_offset]);
        writer.extend_from_slice(decrypted);

        Ok(writer)
    }

    fn encrypt_rtcp(
        &mut self,
        decrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
    ) -> Result<BytesMut> {
        let iv_bytes = self.rtcp_initialization_vector(srtcp_index, ssrc);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(&iv_bytes).map_err(|_| Error::Other("invalid nonce".into()))?;
        let aad_data = self.rtcp_additional_authenticated_data(decrypted, srtcp_index);
        let aad = aead::Aad::from(&aad_data);

        let mut in_out = decrypted[8..].to_vec();
        self.srtcp_cipher
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| Error::Other("SRTCP encrypt failed".into()))?;

        let mut writer = BytesMut::with_capacity(in_out.len() + aad_data.len());
        writer.extend_from_slice(&decrypted[..8]);
        writer.extend_from_slice(&in_out);
        writer.extend_from_slice(&aad_data[8..]);

        Ok(writer)
    }

    fn decrypt_rtcp(
        &mut self,
        encrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
    ) -> Result<BytesMut> {
        if encrypted.len() < self.aead_auth_tag_len() + SRTCP_INDEX_SIZE {
            return Err(Error::ErrFailedToVerifyAuthTag);
        }

        let nonce_bytes = self.rtcp_initialization_vector(srtcp_index, ssrc);
        let nonce =
            aead::Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| Error::Other("invalid nonce".into()))?;
        let aad_data = self.rtcp_additional_authenticated_data(encrypted, srtcp_index);
        let aad = aead::Aad::from(&aad_data);

        let mut in_out = encrypted[8..(encrypted.len() - SRTCP_INDEX_SIZE)].to_vec();
        let decrypted = self
            .srtcp_cipher
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| Error::ErrFailedToVerifyAuthTag)?;

        let mut writer = BytesMut::with_capacity(8 + decrypted.len());
        writer.extend_from_slice(&encrypted[..8]);
        writer.extend_from_slice(decrypted);

        Ok(writer)
    }

    fn get_rtcp_index(&self, input: &[u8]) -> usize {
        let pos = input.len() - 4;
        let val = BigEndian::read_u32(&input[pos..]);

        (val & !((RTCP_ENCRYPTION_FLAG as u32) << 24)) as usize
    }
}

impl CipherAeadAesGcm {
    /// Create a new AEAD instance.
    pub(crate) fn new(
        profile: ProtectionProfile,
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<CipherAeadAesGcm> {
        let algorithm = match profile {
            ProtectionProfile::AeadAes128Gcm => &aead::AES_128_GCM,
            ProtectionProfile::AeadAes256Gcm => &aead::AES_256_GCM,
            _ => unreachable!(),
        };

        assert_eq!(profile.aead_auth_tag_len(), 16);
        assert_eq!(profile.key_len(), algorithm.key_len());
        assert_eq!(profile.salt_len(), master_salt.len());

        let kdf: Kdf = match profile {
            ProtectionProfile::AeadAes128Gcm => aes_cm_key_derivation,
            ProtectionProfile::AeadAes256Gcm => aes_256_cm_key_derivation,
            _ => unreachable!(),
        };

        let srtp_session_key = kdf(
            LABEL_SRTP_ENCRYPTION,
            master_key,
            master_salt,
            0,
            master_key.len(),
        )?;

        let srtp_unbound = aead::UnboundKey::new(algorithm, &srtp_session_key)
            .map_err(|_| Error::Other("invalid SRTP key".into()))?;
        let srtp_cipher = aead::LessSafeKey::new(srtp_unbound);

        let srtcp_session_key = kdf(
            LABEL_SRTCP_ENCRYPTION,
            master_key,
            master_salt,
            0,
            master_key.len(),
        )?;

        let srtcp_unbound = aead::UnboundKey::new(algorithm, &srtcp_session_key)
            .map_err(|_| Error::Other("invalid SRTCP key".into()))?;
        let srtcp_cipher = aead::LessSafeKey::new(srtcp_unbound);

        let srtp_session_salt = kdf(
            LABEL_SRTP_SALT,
            master_key,
            master_salt,
            0,
            master_salt.len(),
        )?;

        let srtcp_session_salt = kdf(
            LABEL_SRTCP_SALT,
            master_key,
            master_salt,
            0,
            master_salt.len(),
        )?;

        Ok(CipherAeadAesGcm {
            profile,
            srtp_cipher,
            srtcp_cipher,
            srtp_session_salt,
            srtcp_session_salt,
        })
    }

    /// The 12-octet IV used by AES-GCM SRTP is formed by first concatenating
    /// 2 octets of zeroes, the 4-octet SSRC, the 4-octet rollover counter
    /// (ROC), and the 2-octet sequence number (SEQ).  The resulting 12-octet
    /// value is then XORed to the 12-octet salt to form the 12-octet IV.
    ///
    /// https://tools.ietf.org/html/rfc7714#section-8.1
    pub(crate) fn rtp_initialization_vector(&self, header: &rtp::Header, roc: u32) -> Vec<u8> {
        let mut iv = vec![0u8; 12];
        BigEndian::write_u32(&mut iv[2..], header.ssrc);
        BigEndian::write_u32(&mut iv[6..], roc);
        BigEndian::write_u16(&mut iv[10..], header.sequence_number);

        for (i, v) in iv.iter_mut().enumerate() {
            *v ^= self.srtp_session_salt[i];
        }

        iv
    }

    /// The 12-octet IV used by AES-GCM SRTCP is formed by first
    /// concatenating 2 octets of zeroes, the 4-octet SSRC identifier,
    /// 2 octets of zeroes, a single "0" bit, and the 31-bit SRTCP index.
    /// The resulting 12-octet value is then XORed to the 12-octet salt to
    /// form the 12-octet IV.
    ///
    /// https://tools.ietf.org/html/rfc7714#section-9.1
    pub(crate) fn rtcp_initialization_vector(&self, srtcp_index: usize, ssrc: u32) -> Vec<u8> {
        let mut iv = vec![0u8; 12];

        BigEndian::write_u32(&mut iv[2..], ssrc);
        BigEndian::write_u32(&mut iv[8..], srtcp_index as u32);

        for (i, v) in iv.iter_mut().enumerate() {
            *v ^= self.srtcp_session_salt[i];
        }

        iv
    }

    /// In an SRTCP packet, a 1-bit Encryption flag is prepended to the
    /// 31-bit SRTCP index to form a 32-bit value we shall call the
    /// "ESRTCP word"
    ///
    /// https://tools.ietf.org/html/rfc7714#section-17
    pub(crate) fn rtcp_additional_authenticated_data(
        &self,
        rtcp_packet: &[u8],
        srtcp_index: usize,
    ) -> Vec<u8> {
        let mut aad = vec![0u8; 12];

        aad[..8].copy_from_slice(&rtcp_packet[..8]);

        BigEndian::write_u32(&mut aad[8..], srtcp_index as u32);

        aad[8] |= RTCP_ENCRYPTION_FLAG;
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_aes_gcm_128() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let master_key = vec![0u8; profile.key_len()];
        let master_salt = vec![0u8; 12];

        let mut cipher = CipherAeadAesGcm::new(profile, &master_key, &master_salt).unwrap();

        let header = rtp::Header {
            ssrc: 0x12345678,
            ..Default::default()
        };

        let payload = vec![0u8; 100];
        let encrypted = cipher.encrypt_rtp(&payload, &header, 0).unwrap();

        let decrypted = cipher.decrypt_rtp(&encrypted, &header, 0).unwrap();
        assert_eq!(&decrypted[..], &payload[..]);
    }

    #[test]
    fn test_aead_aes_gcm_256() {
        let profile = ProtectionProfile::AeadAes256Gcm;
        let master_key = vec![0u8; profile.key_len()];
        let master_salt = vec![0u8; 12];

        let mut cipher = CipherAeadAesGcm::new(profile, &master_key, &master_salt).unwrap();

        let header = rtp::Header {
            ssrc: 0x12345678,
            ..Default::default()
        };

        let payload = vec![0u8; 100];
        let encrypted = cipher.encrypt_rtp(&payload, &header, 0).unwrap();

        let decrypted = cipher.decrypt_rtp(&encrypted, &header, 0).unwrap();
        assert_eq!(&decrypted[..], &payload[..]);
    }
}
