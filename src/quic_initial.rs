//! Stateless QUIC v1/v2 Initial inspection for raw SNI routing.
//!
//! QUIC Initial packets use publicly derivable keys. We decrypt only those
//! packets, reassemble their CRYPTO frames, and inspect the TLS ClientHello;
//! raw routes still forward every original UDP datagram untouched.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::peek::{parse_tls_sni, TlsParse};

pub const MAX_CLIENT_HELLO: usize = 16 * 1024;
const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xbd, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc,
    0xbb, 0x7f, 0x0a, 0xa0,
];
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

struct VersionParams {
    salt: &'static [u8; 20],
    initial_type: u8,
    key_label: &'static [u8],
    iv_label: &'static [u8],
    hp_label: &'static [u8],
}

fn version_params(version: u32) -> Option<VersionParams> {
    match version {
        QUIC_V1 => Some(VersionParams {
            salt: &INITIAL_SALT_V1,
            initial_type: 0x00,
            key_label: b"quic key",
            iv_label: b"quic iv",
            hp_label: b"quic hp",
        }),
        QUIC_V2 => Some(VersionParams {
            salt: &INITIAL_SALT_V2,
            initial_type: 0x10,
            key_label: b"quicv2 key",
            iv_label: b"quicv2 iv",
            hp_label: b"quicv2 hp",
        }),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialSni {
    Name(String),
    NoSni,
    NeedMore,
    Invalid,
}

/// Reassembles one client's Initial CRYPTO stream, bounded before address
/// validation so a fragmented ClientHello cannot exhaust memory. Byte-granular
/// storage makes overlapping retransmissions safe: identical bytes are ignored,
/// while contradictory overlap is rejected as malformed input.
#[derive(Debug, Default)]
pub struct InitialInspector {
    crypto: BTreeMap<u64, u8>,
}

impl InitialInspector {
    pub fn ingest(&mut self, datagram: &[u8]) -> InitialSni {
        let mut at = 0usize;
        let mut saw_initial = false;
        while at < datagram.len() {
            match decrypt_initial(&datagram[at..]) {
                Ok(Some(packet)) => {
                    saw_initial = true;
                    at += packet.consumed;
                    if self.add_frames(&packet.payload).is_err() {
                        return InitialSni::Invalid;
                    }
                }
                Ok(None) => break,
                Err(()) => return InitialSni::Invalid,
            }
        }
        match self.client_hello() {
            Some(hello) => match parse_tls_sni(&tls_record(hello)) {
                TlsParse::Sni(name) => InitialSni::Name(name),
                TlsParse::NoSni => InitialSni::NoSni,
                TlsParse::NeedMore => InitialSni::NeedMore,
                TlsParse::NotClientHello => InitialSni::Invalid,
            },
            None if saw_initial || !self.crypto.is_empty() => InitialSni::NeedMore,
            None => InitialSni::NeedMore,
        }
    }

    fn add_frames(&mut self, payload: &[u8]) -> Result<(), ()> {
        let mut at = 0usize;
        while at < payload.len() {
            match read_varint(payload, &mut at)? {
                0x00 | 0x01 => {} // PADDING and PING
                0x02 => skip_ack(payload, &mut at, false)?,
                0x03 => skip_ack(payload, &mut at, true)?,
                0x06 => {
                    let offset = read_varint(payload, &mut at)?;
                    let len = read_varint(payload, &mut at)? as usize;
                    let end = at.checked_add(len).ok_or(())?;
                    let data = payload.get(at..end).ok_or(())?;
                    at = end;
                    self.insert_crypto(offset, data)?;
                }
                0x1c => skip_transport_close(payload, &mut at)?,
                _ => return Err(()),
            }
        }
        Ok(())
    }

    fn insert_crypto(&mut self, offset: u64, data: &[u8]) -> Result<(), ()> {
        let end = offset.checked_add(data.len() as u64).ok_or(())?;
        if end > MAX_CLIENT_HELLO as u64 {
            return Err(());
        }
        for (index, byte) in data.iter().copied().enumerate() {
            let pos = offset.checked_add(index as u64).ok_or(())?;
            match self.crypto.entry(pos) {
                Entry::Vacant(entry) => {
                    entry.insert(byte);
                }
                Entry::Occupied(entry) if *entry.get() == byte => {}
                Entry::Occupied(_) => return Err(()),
            }
        }
        Ok(())
    }

    fn client_hello(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for offset in 0..MAX_CLIENT_HELLO as u64 {
            match self.crypto.get(&offset) {
                Some(byte) => out.push(*byte),
                None => break,
            }
        }
        (!out.is_empty()).then_some(out)
    }
}

struct DecryptedInitial {
    consumed: usize,
    payload: Vec<u8>,
}

fn decrypt_initial(packet: &[u8]) -> Result<Option<DecryptedInitial>, ()> {
    if packet.len() < 7 || packet[0] & 0xc0 != 0xc0 {
        return Ok(None);
    }
    let version = u32::from_be_bytes(packet[1..5].try_into().map_err(|_| ())?);
    let Some(params) = version_params(version) else {
        return Ok(None);
    };
    if packet[0] & 0x30 != params.initial_type {
        return Ok(None);
    }

    let mut at = 5usize;
    let dcid_len = *packet.get(at).ok_or(())? as usize;
    at += 1;
    let dcid_end = at.checked_add(dcid_len).ok_or(())?;
    let dcid = packet.get(at..dcid_end).ok_or(())?;
    at = dcid_end;
    let scid_len = *packet.get(at).ok_or(())? as usize;
    at += 1;
    at = at.checked_add(scid_len).ok_or(())?;
    if at > packet.len() {
        return Err(());
    }
    let token_len = read_varint(packet, &mut at)? as usize;
    at = at.checked_add(token_len).ok_or(())?;
    if at > packet.len() {
        return Err(());
    }
    let length = read_varint(packet, &mut at)? as usize;
    let pn_at = at;
    let sample = packet.get(pn_at + 4..pn_at + 20).ok_or(())?;

    let keys = InitialKeys::client(version, dcid)?;
    let mask = keys.header_mask(sample)?;
    let first = packet[0] ^ (mask[0] & 0x0f);
    let pn_len = (first as usize & 0x03) + 1;
    let packet_end = pn_at.checked_add(length).ok_or(())?;
    if packet_end > packet.len() || length < pn_len + 16 {
        return Err(());
    }
    let mut header = packet[..pn_at + pn_len].to_vec();
    header[0] = first;
    let mut pn = 0u64;
    for i in 0..pn_len {
        let b = packet[pn_at + i] ^ mask[i + 1];
        header[pn_at + i] = b;
        pn = (pn << 8) | u64::from(b);
    }
    let ciphertext = &packet[pn_at + pn_len..packet_end];
    let split = ciphertext.len() - 16;
    let (body, tag) = ciphertext.split_at(split);
    let mut plain = body.to_vec();
    let nonce = keys.nonce(pn);
    keys.aead
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &header,
            &mut plain,
            Tag::from_slice(tag),
        )
        .map_err(|_| ())?;
    Ok(Some(DecryptedInitial {
        consumed: packet_end,
        payload: plain,
    }))
}

struct InitialMaterial {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn derive_initial_material(version: u32, dcid: &[u8]) -> Result<InitialMaterial, ()> {
    let params = version_params(version).ok_or(())?;
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(params.salt), dcid);
    let mut client_secret = [0u8; 32];
    expand_label(initial_secret.as_slice(), b"client in", &mut client_secret)?;
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    expand_label(&client_secret, params.key_label, &mut key)?;
    expand_label(&client_secret, params.iv_label, &mut iv)?;
    expand_label(&client_secret, params.hp_label, &mut hp)?;
    Ok(InitialMaterial { key, iv, hp })
}

struct InitialKeys {
    aead: Aes128Gcm,
    iv: [u8; 12],
    hp: [u8; 16],
}

impl InitialKeys {
    fn client(version: u32, dcid: &[u8]) -> Result<Self, ()> {
        let material = derive_initial_material(version, dcid)?;
        Ok(Self {
            aead: Aes128Gcm::new_from_slice(&material.key).map_err(|_| ())?,
            iv: material.iv,
            hp: material.hp,
        })
    }

    fn header_mask(&self, sample: &[u8]) -> Result<[u8; 16], ()> {
        let cipher = Aes128::new_from_slice(&self.hp).map_err(|_| ())?;
        let mut block = GenericArray::clone_from_slice(sample);
        cipher.encrypt_block(&mut block);
        Ok(block.into())
    }

    fn nonce(&self, packet_number: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (i, byte) in packet_number.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= byte;
        }
        nonce
    }
}

fn expand_label(secret: &[u8], label: &[u8], out: &mut [u8]) -> Result<(), ()> {
    let full_label = [b"tls13 ".as_slice(), label].concat();
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(0);
    Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| ())?
        .expand(&info, out)
        .map_err(|_| ())
}

fn read_varint(bytes: &[u8], at: &mut usize) -> Result<u64, ()> {
    let first = *bytes.get(*at).ok_or(())?;
    let len = 1usize << (first >> 6);
    let end = at.checked_add(len).ok_or(())?;
    let raw = bytes.get(*at..end).ok_or(())?;
    *at = end;
    let mut value = u64::from(raw[0] & 0x3f);
    for &b in &raw[1..] {
        value = (value << 8) | u64::from(b);
    }
    Ok(value)
}

fn skip_ack(bytes: &[u8], at: &mut usize, ecn: bool) -> Result<(), ()> {
    read_varint(bytes, at)?; // largest acknowledged
    read_varint(bytes, at)?; // ack delay
    let ranges = read_varint(bytes, at)?;
    read_varint(bytes, at)?; // first ack range
    for _ in 0..ranges {
        read_varint(bytes, at)?; // gap
        read_varint(bytes, at)?; // ack range length
    }
    if ecn {
        read_varint(bytes, at)?; // ECT(0)
        read_varint(bytes, at)?; // ECT(1)
        read_varint(bytes, at)?; // CE
    }
    Ok(())
}

fn skip_transport_close(bytes: &[u8], at: &mut usize) -> Result<(), ()> {
    read_varint(bytes, at)?; // error code
    read_varint(bytes, at)?; // triggering frame type
    let reason_len = read_varint(bytes, at)? as usize;
    let end = at.checked_add(reason_len).ok_or(())?;
    bytes.get(*at..end).ok_or(())?;
    *at = end;
    Ok(())
}

fn tls_record(handshake: Vec<u8>) -> Vec<u8> {
    if handshake.len() > u16::MAX as usize {
        return Vec::new();
    }
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_rfc9001_v1_client_initial_keys() {
        let dcid = hex("8394c8f03e515708");
        let material = derive_initial_material(QUIC_V1, &dcid).unwrap();
        assert_eq!(material.key, hex16("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(material.iv, hex12("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(material.hp, hex16("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn reassembles_fragmented_initial_crypto_and_extracts_sni_v1() {
        assert_fragmented_sni(QUIC_V1);
    }

    #[test]
    fn reassembles_fragmented_initial_crypto_and_extracts_sni_v2() {
        assert_fragmented_sni(QUIC_V2);
    }

    #[test]
    fn accepts_identical_overlapping_crypto_retransmission() {
        let hello = client_hello("overlap.test");
        let dcid = b"01234567";
        let first = seal_initial(QUIC_V1, dcid, 1, 0, &hello[..40], &[]);
        let second = seal_initial(QUIC_V1, dcid, 2, 20, &hello[20..], &[]);
        let mut inspector = InitialInspector::default();
        assert_eq!(inspector.ingest(&first), InitialSni::NeedMore);
        assert_eq!(
            inspector.ingest(&second),
            InitialSni::Name("overlap.test".to_string())
        );
    }

    #[test]
    fn rejects_conflicting_overlapping_crypto() {
        let mut inspector = InitialInspector::default();
        inspector.insert_crypto(0, b"abc").unwrap();
        assert_eq!(inspector.insert_crypto(1, b"Z"), Err(()));
    }

    #[test]
    fn accepts_retry_token_on_followup_initial() {
        let hello = client_hello("retry.test");
        let packet = seal_initial(QUIC_V1, b"new-dcid", 7, 0, &hello, b"retry-token");
        let mut inspector = InitialInspector::default();
        assert_eq!(
            inspector.ingest(&packet),
            InitialSni::Name("retry.test".to_string())
        );
    }

    #[test]
    fn skips_ack_ecn_and_transport_close_frames() {
        let mut ack_ecn = vec![0x03];
        ack_ecn.extend([0, 0, 0, 0, 0, 0, 0]);
        let mut at = 1;
        assert_eq!(skip_ack(&ack_ecn, &mut at, true), Ok(()));
        assert_eq!(at, ack_ecn.len());

        let close = [0x1c, 0x01, 0x06, 0x03, b'b', b'y', b'e'];
        let mut at = 1;
        assert_eq!(skip_transport_close(&close, &mut at), Ok(()));
        assert_eq!(at, close.len());
    }

    #[test]
    fn quic_varints_decode_at_each_width() {
        let cases = [
            (vec![0x25], 37),
            (vec![0x40, 0x25], 37),
            (vec![0x80, 0x00, 0x00, 0x25], 37),
            (vec![0xc0, 0, 0, 0, 0, 0, 0, 0x25], 37),
        ];
        for (bytes, expected) in cases {
            let mut at = 0;
            assert_eq!(read_varint(&bytes, &mut at), Ok(expected));
            assert_eq!(at, bytes.len());
        }
    }

    fn assert_fragmented_sni(version: u32) {
        let hello = client_hello("router.test");
        let split = hello.len() / 2;
        let dcid = b"01234567";
        let first = seal_initial(version, dcid, 1, 0, &hello[..split], &[]);
        let second = seal_initial(version, dcid, 2, split as u64, &hello[split..], &[]);
        let mut inspector = InitialInspector::default();
        assert_eq!(inspector.ingest(&first), InitialSni::NeedMore);
        assert_eq!(
            inspector.ingest(&second),
            InitialSni::Name("router.test".to_string())
        );
    }

    fn seal_initial(
        version: u32,
        dcid: &[u8],
        packet_number: u64,
        crypto_offset: u64,
        crypto: &[u8],
        token: &[u8],
    ) -> Vec<u8> {
        let mut plain = Vec::new();
        plain.push(0x06); // CRYPTO
        plain.extend(varint(crypto_offset));
        plain.extend(varint(crypto.len() as u64));
        plain.extend_from_slice(crypto);

        let params = version_params(version).unwrap();
        let pn_len = 2usize;
        let length = pn_len + plain.len() + 16;
        let mut header = vec![0xc1 | params.initial_type];
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // SCID length
        header.extend(varint(token.len() as u64));
        header.extend_from_slice(token);
        header.extend(varint(length as u64));
        let pn_at = header.len();
        header.extend_from_slice(&(packet_number as u16).to_be_bytes());

        let keys = InitialKeys::client(version, dcid).unwrap();
        let nonce = keys.nonce(packet_number);
        let mut body = plain;
        let tag = keys
            .aead
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &header, &mut body)
            .unwrap();
        body.extend_from_slice(&tag);
        let sample = &body[4 - pn_len..4 - pn_len + 16];
        let mask = keys.header_mask(sample).unwrap();
        header[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            header[pn_at + i] ^= mask[i + 1];
        }
        header.extend_from_slice(&body);
        header
    }

    fn varint(value: u64) -> Vec<u8> {
        if value < 64 {
            vec![value as u8]
        } else if value < 1 << 14 {
            ((value as u16) | 0x4000).to_be_bytes().to_vec()
        } else {
            panic!("test value is too large")
        }
    }

    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).unwrap();
                let lo = (pair[1] as char).to_digit(16).unwrap();
                ((hi << 4) | lo) as u8
            })
            .collect()
    }

    fn hex16(input: &str) -> [u8; 16] {
        hex(input).try_into().unwrap()
    }

    fn hex12(input: &str) -> [u8; 12] {
        hex(input).try_into().unwrap()
    }

    fn client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0; 32]);
        body.push(0); // session ID
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut hello = vec![
            1,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        hello.extend_from_slice(&body);
        hello
    }
}
