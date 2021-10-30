// Ref:
//
// - https://spec.matrix.org/unstable/client-server-api/#deriving-keys-from-passphrases
// - https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing/#passphrase
pub(crate) fn derive_key_from_passphrase(
	passphrase: &[u8],
	bits: Option<usize>,
	salt: &str,
	iterations: u32,
	iv: &str,
	mac: &str,
) -> Result<hkdf::Hkdf::<sha2::Sha256>, DeriveKeyError> {
	let key_len = bits.map_or(32, |bits| (bits + 7) / 8);
	if key_len != 32 {
		return Err(DeriveKeyError::InvalidLength { expected: 32, actual: key_len });
	}

	let mut key = [0_u8; 32];
	pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(passphrase, salt.as_bytes(), iterations, &mut key);

	verify_key(&key, iv, mac)
}

// Ref:
//
// - https://spec.matrix.org/unstable/client-server-api/#recovery-key
// - https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing/#keyfile
pub(crate) fn derive_key_from_keyfile(
	keyfile: String,
	iv: &str,
	mac: &str,
) -> Result<hkdf::Hkdf::<sha2::Sha256>, DeriveKeyError> {
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

	if !decoded_key.starts_with(&[0x8B, 0x01]) {
		return Err(DeriveKeyError::InvalidHeader);
	}

	if decoded_key.iter().fold(0, std::ops::BitXor::bitxor) != 0 {
		return Err(DeriveKeyError::InvalidParity);
	}

	verify_key(&decoded_key[2..][..32], iv, mac)
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

	#[error("MAC is not valid base-64")]
	MalformedMac(#[source] base64::DecodeError),

	#[error("could not encrypt verification plaintext")]
	VerificationFailedEncrypt(EncryptError),

	#[error("verification ciphertext does not have the expected signature")]
	VerificationFailedSignature,
}

fn verify_key(
	key: &[u8],
	iv: &str,
	mac: &str,
) -> Result<hkdf::Hkdf::<sha2::Sha256>, DeriveKeyError> {
	let key = hkdf::Hkdf::<sha2::Sha256>::new(None, key);

	let expected_mac = base64::decode(mac).map_err(DeriveKeyError::MalformedMac)?;

	let mut stream = [0_u8; 32];
	let actual_mac =
		encrypt(
			&key,
			"",
			&mut stream,
			iv,
		).map_err(DeriveKeyError::VerificationFailedEncrypt)?;
	let ok: bool = subtle::ConstantTimeEq::ct_eq(&expected_mac[..], &*actual_mac.into_bytes()).into();
	if ok {
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
	iv: &str,
) -> Result<hmac::crypto_mac::Output<hmac::Hmac<sha2::Sha256>>, EncryptError> {
	let iv = base64::decode(iv).map_err(EncryptError::MalformedIvBase64)?;
	let iv: &[u8; 16] = iv[..].try_into().map_err(EncryptError::MalformedIvLength)?;

	let mut okm = [0_u8; 64];
	let () = key.expand(secret_name.as_bytes(), &mut okm).expect("output length is statically correct");

	let stream_cipher: aes::Aes256 = aes::NewBlockCipher::new(okm[..32].into());
	let mut stream_cipher: aes::Aes256Ctr = aes::cipher::FromBlockCipher::from_block_cipher(stream_cipher, iv.into());
	let () = aes::cipher::StreamCipher::try_apply_keystream(&mut stream_cipher, stream).map_err(|_| EncryptError::Truncated)?;

	let mut mac: hmac::Hmac<sha2::Sha256> = hmac::NewMac::new_from_slice(&okm[32..]).expect("Hmac::new_from_slice accepts any key length");
	hmac::Mac::update(&mut mac, stream);
	let mac = hmac::Mac::finalize(mac);
	Ok(mac)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EncryptError {
	#[error("IV is not valid")]
	MalformedIvBase64(#[source] base64::DecodeError),

	#[error("IV is not valid")]
	MalformedIvLength(#[source] std::array::TryFromSliceError),

	#[error("ciphertext is truncated")]
	Truncated,
}

// Ref:
//
// - https://spec.matrix.org/unstable/client-server-api/#msecret_storagev1aes-hmac-sha2
// - https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing/#encrypting-and-decrypting
pub(crate) fn decrypt(
	key: &hkdf::Hkdf::<sha2::Sha256>,
	secret_name: &str,
	stream: &mut [u8],
	iv: &str,
	mac: &str,
) -> Result<(), DecryptError> {
	let iv = base64::decode(iv).map_err(DecryptError::MalformedIvBase64)?;
	let iv: &[u8; 16] = iv[..].try_into().map_err(DecryptError::MalformedIvLength)?;

	let hmac = base64::decode(mac).map_err(DecryptError::MalformedMac)?;

	let mut okm = [0_u8; 64];
	let () = key.expand(secret_name.as_bytes(), &mut okm).expect("output length is statically correct");

	let mut mac: hmac::Hmac<sha2::Sha256> = hmac::NewMac::new_from_slice(&okm[32..]).expect("Hmac::new_from_slice accepts any key length");

	hmac::Mac::update(&mut mac, stream);
	let () = hmac::Mac::verify(mac, &hmac).map_err(DecryptError::SignatureVerificationFailed)?;

	let stream_cipher: aes::Aes256 = aes::NewBlockCipher::new(okm[..32].into());
	let mut stream_cipher: aes::Aes256Ctr = aes::cipher::FromBlockCipher::from_block_cipher(stream_cipher, iv.into());

	let () = aes::cipher::StreamCipher::try_apply_keystream(&mut stream_cipher, stream).map_err(|_| DecryptError::Truncated)?;

	Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DecryptError {
	#[error("IV is not valid")]
	MalformedIvBase64(#[source] base64::DecodeError),

	#[error("IV is not valid")]
	MalformedIvLength(#[source] std::array::TryFromSliceError),

	#[error("MAC is not valid base-64")]
	MalformedMac(#[source] base64::DecodeError),

	#[error("plaintext does not have the expected signature")]
	SignatureVerificationFailed(#[source] hmac::crypto_mac::MacError),

	#[error("ciphertext is truncated")]
	Truncated,
}
