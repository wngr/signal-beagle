use std::{convert::TryInto, fs::File, io::Read, path::PathBuf};

use aes_ctr::{
    cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher},
    Aes256Ctr,
};
use anyhow::Context;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use clap::Clap;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::{Digest, Sha256, Sha512};
mod model {
    include!(concat!(env!("OUT_DIR"), "/signal.rs"));
}

#[derive(Clap)]
struct Opts {
    /// Pass phrase
    #[clap(short, long)]
    key: String,
    /// Path to backup file
    input: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    let reader = File::open(opts.input)?;
    let mut backup = Backup::new(reader, opts.key)?;
    for _ in 0..100 {
        let next = backup.next()?;
        println!("{:?}", next);
    }
    Ok(())
}

#[derive(Debug)]
struct Backup<R: Read> {
    reader: R,
    cipher_key: [u8; 32],
    hmac: Hmac<Sha256>,
    mac_key: [u8; 32],
    init_vector: [u8; 16],
    counter: u32,
}
impl<R: Read> Backup<R> {
    fn next(&mut self) -> anyhow::Result<model::BackupFrame> {
        let frame_len = self.reader.read_u32::<BigEndian>()? as usize;
        let mut frame = vec![0u8; frame_len];
        self.reader.read_exact(&mut frame)?;

        // https://github.com/signalapp/Signal-Android/blob/d74e9f74103ad76eb7b5378e06fb789e7b365767/app/src/main/java/org/thoughtcrime/securesms/backup/FullBackupImporter.java#L380
        let their_mac = &frame[frame.len() - 10..];
        // self.hmac.reset();
        self.hmac.update(&frame[..frame.len() - 10]);
        let our_mac = self.hmac.finalize_reset().into_bytes();

        // only first 10 bytes of the mac are persisted
        anyhow::ensure!(our_mac.starts_with(&their_mac), "Bad MAC");

        let iv = {
            let mut tmp = [0u8; 16];
            // First 4 bytes are used as counter
            BigEndian::write_u32(&mut tmp[..4], self.counter);
            // Filled with IV from 4 to 16
            tmp[4..].copy_from_slice(&self.init_vector[4..]);
            self.counter += 1;
            tmp
        };

        let cipher = GenericArray::from_slice(&self.cipher_key[..]);
        let nonce = GenericArray::from_slice(&iv[..]);
        let mut cipher = Aes256Ctr::new(&cipher, &nonce);

        let read_to = frame.len() - 10;
        cipher.apply_keystream(&mut frame[..read_to]);

        let frame = model::BackupFrame::decode(&frame[..read_to])?;

        Ok(frame)
    }
    fn new(mut reader: R, key: String) -> anyhow::Result<Backup<R>> {
        let header_len = reader.read_u32::<BigEndian>()? as usize;
        let mut header_frame = vec![0u8; header_len];
        reader.read_exact(&mut header_frame)?;

        let frame = model::BackupFrame::decode(&header_frame[..])?;

        // https://github.com/signalapp/Signal-Android/blob/d74e9f74103ad76eb7b5378e06fb789e7b365767/app/src/main/java/org/thoughtcrime/securesms/backup/FullBackupBase.java
        let mut hasher = Sha512::new();
        let pass_without_whitespace = key.replace(" ", "");
        if let Some(salt) = frame.header.as_ref().and_then(|h| h.salt.as_ref()) {
            hasher.update(salt);
        }
        let init_vector: [u8; 16] = {
            let iv = frame.header.and_then(|h| h.iv).context("Invalid header")?;
            anyhow::ensure!(iv.len() == 16);
            iv[..].try_into().unwrap()
        };
        let mut hash = pass_without_whitespace.as_bytes().to_vec();
        for _ in 0..250000 {
            hasher.update(hash);
            hasher.update(&pass_without_whitespace);
            hash = hasher.finalize_reset().to_vec();
        }
        let key = &hash[..32];
        let derived = derive_secrets(key)?;
        let mac_key: [u8; 32] = derived[32..].try_into().unwrap();
        Ok(Backup {
            reader,
            cipher_key: derived[..32].try_into().unwrap(),
            hmac: hmac::NewMac::new_varkey(&mac_key).map_err(|e| anyhow::anyhow!(e))?,
            mac_key,
            counter: BigEndian::read_u32(&init_vector[..]),
            init_vector,
        })
    }
}

// https://github.com/signalapp/Signal-Android/blob/d74e9f74103ad76eb7b5378e06fb789e7b365767/app/src/main/java/org/thoughtcrime/securesms/backup/FullBackupImporter.java#L311-L322
// https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/java/src/main/java/org/whispersystems/libsignal/kdf/HKDF.java#L28
fn derive_secrets(key: &[u8]) -> anyhow::Result<[u8; 64]> {
    let salt = [0u8; 32];
    let h = hkdf::Hkdf::<Sha256>::new(Some(&salt), key);
    let mut okm = [0u8; 64];
    h.expand(b"Backup Export", &mut okm)
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(okm)
}
