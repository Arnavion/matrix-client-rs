#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
	#[error("could not get user config directory")]
	GetConfigDirectory,

	#[error("could not load config")]
	LoadIo(#[source] std::io::Error),

	#[error("could not load config")]
	LoadJson(#[source] serde_json::Error),

	#[error("could not save config")]
	SaveIo(#[source] std::io::Error),

	#[error("could not save config")]
	SaveJson(#[source] serde_json::Error),
}

pub(crate) struct Manager {
	path: std::path::PathBuf,
}

impl Manager {
	pub(crate) fn new(user_id: &str) -> Result<Self, Error> {
		let mut path = dirs::config_dir().ok_or(Error::GetConfigDirectory)?;
		path.push("matrix-client");
		path.push(format!("{}.json", user_id));
		Ok(Manager {
			path,
		})
	}

	pub(crate) fn load(&mut self) -> Result<State, Error> {
		if let Some(parent) = &self.path.parent() {
			let () = std::fs::create_dir_all(parent).map_err(Error::LoadIo)?;
		}

		match std::fs::File::open(&self.path) {
			Ok(file) => serde_json::from_reader(file).map_err(Error::LoadJson),
			Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
				let state = Default::default();
				self.save(&state)?;
				Ok(state)
			},
			Err(err) => Err(Error::LoadIo(err)),
		}
	}

	pub(crate) fn save(&mut self, state: &State) -> Result<(), Error> {
		if let Some(parent) = &self.path.parent() {
			let () = std::fs::create_dir_all(parent).map_err(Error::SaveIo)?;
		}

		match std::fs::File::create(&self.path) {
			Ok(mut file) => {
				let () = serde_json::to_writer(&mut file, state).map_err(Error::SaveJson)?;
				let () = std::io::Write::write_all(&mut file, b"\n").map_err(Error::SaveIo)?;
				Ok(())
			},
			Err(err) => Err(Error::SaveIo(err)),
		}
	}
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
pub(crate) struct State {
	pub(crate) access_token: Option<String>,

	#[serde(default)]
	pub(crate) e2e_keys: std::collections::BTreeMap<String, std::collections::BTreeMap<String, SessionData>>,

	#[serde(default)]
	pub(crate) secret_storage_keys: std::collections::BTreeMap<String, SecretStorageKey>,

	pub(crate) tmux_conf: Option<std::path::PathBuf>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "algorithm")]
pub(crate) enum SessionData {
	#[serde(rename = "m.megolm.v1.aes-sha2")]
	MegolmV1AesSha2 {
		forwarding_curve25519_key_chain: Vec<String>,
		sender_key: String,
		sender_claimed_keys: SessionData_MegolmV1AesSha2_SenderClaimedKeys,
		session_key: String,
	},

	#[serde(other)]
	Other,
}

#[allow(non_camel_case_types)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct SessionData_MegolmV1AesSha2_SenderClaimedKeys {
	ed25519: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) enum SecretStorageKey {
	#[serde(rename = "passphrase")]
	Passphrase(String),

	#[serde(rename = "keyfile")]
	Keyfile(String),
}
