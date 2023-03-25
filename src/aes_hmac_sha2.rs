impl crate::state::SecretStorageKey {
	pub(crate) fn derive(self, description: crate::KeyDescription) -> Result<(Option<String>, hkdf::Hkdf::<sha2::Sha256>), DeriveKeyError> {
		let crate::KeyDescription_Algorithm::AesHmacSha2 { iv, mac: expected_mac } = description.algorithm;

		let key = match self {
			crate::state::SecretStorageKey::Passphrase(state_passphrase) => {
				// Ref:
				//
				// - https://spec.matrix.org/unstable/client-server-api/#deriving-keys-from-passphrases
				// - https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing/#passphrase

				let crate::KeyDescription_Passphrase::Pbkdf2 { bits, salt, iterations } =
					description.passphrase.ok_or(DeriveKeyError::PassphraseParametersNotProvided)?;

				let key_len = bits.map_or(32, |bits| (bits + 7) / 8);
				if key_len != 32 {
					return Err(DeriveKeyError::InvalidLength { expected: 32, actual: key_len });
				}

				let key = pbkdf2::pbkdf2_hmac_array::<sha2::Sha512, 32>(state_passphrase.as_bytes(), salt.as_bytes(), iterations);

				validate_key(&key, &iv, &expected_mac)?
			},

			crate::state::SecretStorageKey::Keyfile(keyfile) => {
				// Ref:
				//
				// - https://spec.matrix.org/unstable/client-server-api/#recovery-key
				// - https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing/#keyfile

				let mut encoded_key = keyfile.into_bytes();
				encoded_key.retain(|b| !b.is_ascii_whitespace());
				let mut decoded_key = [0_u8; 2 + 32 + 1];
				let key_len =
					bs58::decode(encoded_key)
					.with_alphabet(bs58::Alphabet::BITCOIN)
					.into(&mut decoded_key)
					.map_err(DeriveKeyError::InvalidBase58)?;
				if key_len != decoded_key.len() {
					return Err(DeriveKeyError::InvalidLength { expected: decoded_key.len(), actual: key_len });
				}

				let rest = &decoded_key[..];
				let (magic, rest) = crate::std2::try_split_prefix::<2>(rest).expect("length already validated above");
				if magic != &[0x8B, 0x01] {
					return Err(DeriveKeyError::InvalidHeader);
				}

				if decoded_key.iter().fold(0, std::ops::BitXor::bitxor) != 0 {
					return Err(DeriveKeyError::InvalidParity);
				}

				let (key, _) = crate::std2::try_split_prefix::<32>(rest).expect("length already validated above");
				validate_key(key, &iv, &expected_mac)?
			},
		};
		Ok((description.name, key))
	}
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DeriveKeyError {
	#[error("keyfile is not valid base-58")]
	InvalidBase58(#[source] bs58::decode::Error),

	#[error("decoded keyfile does not have valid header")]
	InvalidHeader,

	#[error("expected decoded keyfile to be {expected} bytes but it is {actual} bytes")]
	InvalidLength { expected: usize, actual: usize },

	#[error("decoded keyfile does not have valid parity")]
	InvalidParity,

	#[error("secret storage key was created from passphrase but account data does not contain passphrase parameters")]
	PassphraseParametersNotProvided,

	#[error("could not encrypt verification plaintext")]
	VerificationFailedEncrypt(ctr::cipher::StreamCipherError),

	#[error("verification ciphertext does not have the expected signature")]
	VerificationFailedSignature,
}

// Ref: https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing/#validating-the-generated-key
fn validate_key(
	key: &[u8; 32],
	iv: &[u8; 16],
	expected_mac: &hmac::digest::CtOutput<hmac::Hmac<sha2::Sha256>>,
) -> Result<hkdf::Hkdf::<sha2::Sha256>, DeriveKeyError> {
	let key = hkdf::Hkdf::<sha2::Sha256>::new(None, key);

	let mut stream = [0_u8; 32];
	let actual_mac = encrypt(&key, "", &mut stream, iv).map_err(DeriveKeyError::VerificationFailedEncrypt)?;

	if actual_mac == *expected_mac {
		Ok(key)
	}
	else {
		Err(DeriveKeyError::VerificationFailedSignature)
	}
}

// Ref:
//
// - https://spec.matrix.org/unstable/client-server-api/#msecret_storagev1aes-hmac-sha2
// - https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing/#encrypting-and-decrypting
pub(crate) fn encrypt(
	key: &hkdf::Hkdf::<sha2::Sha256>,
	secret_name: &str,
	stream: &mut [u8],
	iv: &[u8; 16],
) -> Result<hmac::digest::CtOutput<hmac::Hmac<sha2::Sha256>>, ctr::cipher::StreamCipherError> {
	let (mut stream_cipher, mut mac) = expand_key(key, secret_name, iv);

	let () = ctr::cipher::StreamCipher::try_apply_keystream(&mut stream_cipher, stream)?;

	hmac::Mac::update(&mut mac, stream);
	let mac = hmac::Mac::finalize(mac);
	Ok(mac)
}

impl crate::AesHmacSha2Secret {
	// Ref:
	//
	// - https://spec.matrix.org/unstable/client-server-api/#msecret_storagev1aes-hmac-sha2
	// - https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing/#encrypting-and-decrypting
	pub(crate) fn decrypt(
		self,
		key: &hkdf::Hkdf::<sha2::Sha256>,
		secret_name: &str,
	) -> Result<Vec<u8>, DecryptError> {
		let crate::AesHmacSha2Secret { ciphertext, iv, mac: expected_mac } = self;

		let (mut stream_cipher, mut mac) = expand_key(key, secret_name, &iv);

		hmac::Mac::update(&mut mac, &ciphertext);
		let actual_mac = hmac::Mac::finalize(mac);
		if actual_mac != expected_mac {
			return Err(DecryptError::SignatureVerificationFailed);
		}

		let mut stream = ciphertext;
		let () = aes::cipher::StreamCipher::try_apply_keystream(&mut stream_cipher, &mut stream).map_err(DecryptError::Decrypt)?;

		let plaintext = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &stream).map_err(DecryptError::MalformedPlaintextBase64)?;

		Ok(plaintext)
	}
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DecryptError {
	#[error("could not decrypt ciphertext")]
	Decrypt(ctr::cipher::StreamCipherError),

	#[error("plaintext is not valid")]
	MalformedPlaintextBase64(#[source] base64::DecodeError),

	#[error("ciphertext does not have the expected signature")]
	SignatureVerificationFailed,
}

fn expand_key(
	key: &hkdf::Hkdf::<sha2::Sha256>,
	secret_name: &str,
	iv: &[u8; 16],
) -> (ctr::Ctr64BE<aes::Aes256>, hmac::Hmac<sha2::Sha256>) {
	let mut okm = [0_u8; 64];
	let () = key.expand(secret_name.as_bytes(), &mut okm).expect("output length is statically correct");
	let stream_cipher = ctr::cipher::KeyIvInit::new(okm[..32].into(), iv.into());
	let mac = hmac::Mac::new_from_slice(&okm[32..]).expect("Hmac::new_from_slice accepts any key length");
	(stream_cipher, mac)
}
