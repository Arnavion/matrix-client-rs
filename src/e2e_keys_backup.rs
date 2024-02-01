// Ref: https://spec.matrix.org/unstable/client-server-api/#key-exports

pub(crate) fn import(
	backup: &[u8],
	password: &str,
) -> Result<Vec<BackedUpSessionData>, Error> {
	let backup = pem::parse(backup).map_err(Error::MalformedPem)?;

	let tag = backup.tag();
	if tag != "MEGOLM SESSION DATA" {
		return Err(Error::UnexpectedPemTag(tag.to_owned()));
	}

	let backup: Backup<'_> = backup.contents()[..].try_into()?;
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
	#[error("could not decrypt backup")]
	Decrypt(ctr::cipher::StreamCipherError),

	#[error("expected backup to be a JSON blob")]
	MalformedJson(#[source] serde_json::Error),

	#[error("expected backup to be a PEM blob")]
	MalformedPem(#[source] pem::PemError),

	#[error("signature of the backup does not match")]
	SignatureVerificationFailed(#[source] hmac::digest::MacError),

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
				let key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 64>(password.as_bytes(), salt, rounds);

				let mut mac: hmac::Hmac<sha2::Sha256> = hmac::Mac::new_from_slice(&key[32..]).expect("Hmac::new_from_slice accepts any key length");

				let mut stream_cipher: ctr::Ctr64BE<aes::Aes256> = ctr::cipher::KeyIvInit::new(key[..32].into(), iv.into());

				hmac::Mac::update(&mut mac, &[1]);
				hmac::Mac::update(&mut mac, &salt[..]);
				hmac::Mac::update(&mut mac, &iv[..]);
				hmac::Mac::update(&mut mac, &rounds.to_be_bytes());
				hmac::Mac::update(&mut mac, ciphertext);
				() = hmac::Mac::verify_slice(mac, &hmac[..]).map_err(Error::SignatureVerificationFailed)?;

				let mut plaintext = ciphertext.to_owned();
				() = aes::cipher::StreamCipher::try_apply_keystream(&mut stream_cipher, &mut plaintext).map_err(Error::Decrypt)?;
				Ok(plaintext)
			},
		}
	}
}

impl<'a> TryFrom<&'a [u8]> for Backup<'a> {
	type Error = Error;

	fn try_from(backup: &'a [u8]) -> Result<Self, Self::Error> {
		match backup {
			[1, rest @ ..] => {
				let (rest, hmac) = crate::std2::try_split_suffix::<32>(rest).ok_or(Error::Truncated)?;
				let (salt, rest) = crate::std2::try_split_prefix::<16>(rest).ok_or(Error::Truncated)?;
				let (iv, rest) = crate::std2::try_split_prefix::<16>(rest).ok_or(Error::Truncated)?;
				let (rounds, ciphertext) = crate::std2::try_split_prefix::<4>(rest).ok_or(Error::Truncated)?;
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
