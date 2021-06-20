// Ref: https://spec.matrix.org/unstable/client-server-api/#key-exports

pub(crate) fn import(
	backup: &[u8],
	password: &str,
) -> Result<Vec<BackedUpSessionData>, Error> {
	let pem::Pem { tag, contents } = pem::parse(backup).map_err(Error::MalformedPem)?;
	if tag != "MEGOLM SESSION DATA" {
		return Err(Error::UnexpectedPemTag(tag));
	}

	let backup: Backup<'_> = std::convert::TryInto::try_into(&*contents)?;
	let backup = backup.decrypt(password)?;

	let session_data = serde_json::from_slice(&backup).map_err(Error::MalformedJson)?;
	Ok(session_data)
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct BackedUpSessionData {
	pub(crate) room_id: String,

	pub(crate) session_id: String,

	#[serde(flatten)]
	pub(crate) session_data: crate::state::SessionData,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
	#[error("signature of the backup does not match")]
	SignatureVerificationFailed(#[source] hmac::crypto_mac::MacError),

	#[error("expected backup to be a JSON blob")]
	MalformedJson(#[source] serde_json::Error),

	#[error("expected backup to be a PEM blob")]
	MalformedPem(#[source] pem::PemError),

	#[error("backup is truncated")]
	Truncated,

	#[error("expected backup to have the MEGOLM SESSION DATA tag but its tag is {0}")]
	UnexpectedPemTag(String),

	#[error("unknown backup version {0}")]
	UnknownVersion(u8),
}

enum Backup<'a> {
	V1 {
		salt: &'a [u8; 16],
		iv: &'a [u8; 16],
		rounds: u32,
		ciphertext: &'a [u8],
		hmac: &'a [u8; 32],
	},
}

impl Backup<'_> {
	fn decrypt(&self, password: &str) -> Result<Vec<u8>, Error> {
		match *self {
			Backup::V1 { salt, iv, rounds, ciphertext, hmac } => {
				let mut key = [0_u8; 64];
				pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(password.as_bytes(), salt, rounds, &mut key);
				let decrypt_key: &[u8; 32] = std::convert::TryInto::try_into(&key[..32]).expect("statically guaranteed");

				let stream_cipher: aes::Aes256 = aes::NewBlockCipher::new_from_slice(decrypt_key).unwrap();
				let mut stream_cipher: aes::Aes256Ctr = aes::cipher::FromBlockCipher::from_block_cipher(stream_cipher, iv.into());

				let mac_key = std::convert::TryInto::try_into(&key[32..]).expect("statically guaranteed");
				let mut mac: hmac::Hmac<sha2::Sha256> = hmac::NewMac::new_from_slice(mac_key).unwrap();

				hmac::Mac::update(&mut mac, &[1]);
				hmac::Mac::update(&mut mac, &salt[..]);
				hmac::Mac::update(&mut mac, &iv[..]);
				hmac::Mac::update(&mut mac, &rounds.to_be_bytes());
				hmac::Mac::update(&mut mac, ciphertext);
				let () = hmac::Mac::verify(mac, &hmac[..]).map_err(Error::SignatureVerificationFailed)?;

				let mut plaintext = ciphertext.to_owned();
				let () = aes::cipher::StreamCipher::try_apply_keystream(&mut stream_cipher, &mut plaintext).map_err(|_| Error::Truncated)?;
				Ok(plaintext)
			},
		}
	}
}

impl<'a> std::convert::TryFrom<&'a [u8]> for Backup<'a> {
	type Error = Error;

	fn try_from(backup: &'a [u8]) -> Result<Self, Self::Error> {
		match backup {
			[1, rest @ ..] => {
				let (rest, hmac) = try_split_suffix::<32>(rest).ok_or(Error::Truncated)?;
				let (salt, rest) = try_split_prefix::<16>(rest).ok_or(Error::Truncated)?;
				let (iv, rest) = try_split_prefix::<16>(rest).ok_or(Error::Truncated)?;
				let (rounds, ciphertext) = try_split_prefix::<4>(rest).ok_or(Error::Truncated)?;
				let rounds = u32::from_be_bytes(*rounds);
				Ok(Backup::V1 {
					salt,
					iv,
					rounds,
					ciphertext,
					hmac,
				})
			},

			[version, ..] => Err(Error::UnknownVersion(*version)),

			[] => Err(Error::Truncated),
		}
	}
}

fn try_split_prefix<const N: usize>(s: &[u8]) -> Option<(&[u8; N], &[u8])> {
	if s.len() >= N {
		let (a, b) = s.split_at(N);
		Some((std::convert::TryInto::try_into(a).expect("guaranteed by split_at"), b))
	}
	else {
		None
	}
}

fn try_split_suffix<const N: usize>(s: &[u8]) -> Option<(&[u8], &[u8; N])> {
	if s.len() >= N {
		let (a, b) = s.split_at(s.len() - N);
		Some((a, std::convert::TryInto::try_into(b).expect("guaranteed by split_at")))
	}
	else {
		None
	}
}
