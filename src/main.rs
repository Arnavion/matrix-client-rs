#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::default_trait_access,
	clippy::similar_names,
	clippy::let_underscore_drop,
	clippy::let_unit_value,
	clippy::too_many_lines,
)]

mod aes_hmac_sha2;
mod controller;
mod e2e_keys_backup;
mod http_client;
mod state;
mod std2;
mod view;

use anyhow::Context;

#[derive(clap::Parser)]
struct Options {
	user_id: String,

	#[clap(subcommand)]
	command: Option<Command>,
}

#[derive(clap::Parser)]
enum Command {
	Config {
		#[clap(subcommand)]
		options: ConfigOptions,
	},

	#[clap(name = "_controller", hide(true))]
	Controller,

	#[clap(name = "_view", hide(true))]
	View {
		room_id: String,

		lines: std::path::PathBuf,
	},
}

#[derive(clap::Parser)]
enum ConfigOptions {
	ImportE2EKeysBackup {
		filename: std::path::PathBuf,
	},

	#[clap(group = clap::ArgGroup::new("import_secret_storage_key_type").required(true))]
	ImportSecretStorageKey {
		id: String,

		#[clap(group = "import_secret_storage_key_type", long)]
		passphrase: Option<String>,

		#[clap(group = "import_secret_storage_key_type", long)]
		keyfile: Option<String>,
	},

	Logout,
}

fn main() -> anyhow::Result<()> {
	let Options { user_id, command } = clap::Parser::parse();
	match command {
		None => {
			let mut args = std::env::args_os();
			let arg0 = args.next().context("argv[0] is not set")?;

			let mut controller = tmux(&user_id)?;
			controller.args(["new-session", "-s", "matrix-client", "-n", &user_id]);
			if std::env::var_os("DEBUG").is_some() {
				controller.args(["-e", "DEBUG=1"]);
			}
			controller.arg(arg0);
			controller.args([&user_id, "_controller"]);
			let err = std::os::unix::process::CommandExt::exec(&mut controller);
			return Err(err).context("execvp failed")?;
		},

		Some(Command::Config { options: ConfigOptions::ImportE2EKeysBackup { filename } }) => {
			use std::io::Write;

			let backup = std::fs::read(filename).context("could not read file")?;
			let password = rpassword::prompt_password("Enter password: ").context("could not read password")?;

			let backed_up_session_data = e2e_keys_backup::import(&backup, &password)?;

			let mut state_manager = state::Manager::new(&user_id).context("could not create state manager")?;
			let mut state = state_manager.load().context("could not load state")?;

			let mut stderr = std::io::stderr().lock();

			for e2e_keys_backup::BackedUpSessionData { room_id, session_id, session_data } in backed_up_session_data {
				let _ = writeln!(stderr, "Importing session data for room {room_id} session {session_id} ...");
				state.e2e_keys.entry(room_id).or_default().insert(session_id, session_data);
			}

			let () = state_manager.save(&state).context("could not save state")?;

			let _ = writeln!(stderr, "Done.");
		},

		Some(Command::Config { options: ConfigOptions::ImportSecretStorageKey { id, passphrase, keyfile } }) => {
			use std::io::Write;

			let mut state_manager = state::Manager::new(&user_id).context("could not create state manager")?;
			let mut state = state_manager.load().context("could not load state")?;

			let mut stderr = std::io::stderr().lock();

			if let Some(passphrase) = passphrase {
				state.secret_storage_keys.insert(id, state::SecretStorageKey::Passphrase(passphrase));
			}
			else if let Some(keyfile) = keyfile {
				state.secret_storage_keys.insert(id, state::SecretStorageKey::Keyfile(keyfile));
			}

			let () = state_manager.save(&state).context("could not save state")?;

			let _ = writeln!(stderr, "Done.");
		},

		Some(Command::Config { options: ConfigOptions::Logout }) => {
			use std::io::Write;

			let mut stderr = std::io::stderr().lock();

			let mut state_manager = state::Manager::new(&user_id).context("could not create state manager")?;
			let mut state = state_manager.load().context("could not load state")?;

			if let Some(_access_token) = state.access_token.take() {
				// TODO: Log out from the homeserver too
				// https://matrix.org/docs/spec/client_server/r0.6.1#id206
			}

			let () = state_manager.save(&state).context("could not save state")?;

			let _ = writeln!(stderr, "Done.");
		},

		Some(Command::Controller) => controller::run(user_id)?,

		Some(Command::View { room_id, lines }) => view::run(&user_id, &room_id, &lines)?,
	}

	Ok(())
}

fn tmux(user_id: &str) -> anyhow::Result<std::process::Command> {
	let mut command = std::process::Command::new("tmux");

	let mut state_manager = state::Manager::new(user_id).context("could not create state manager")?;
	let state = state_manager.load().context("could not load state")?;
	if let Some(tmux_conf) = state.tmux_conf.as_ref() {
		command.arg("-f");
		command.arg(tmux_conf);
	}

	Ok(command)
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
enum RoomViewLine {
	AccountData {
		account_data: SyncResponse_AccountData,
	},

	Summary {
		summary: SyncResponse_RoomSummary,
	},

	State {
		event: SyncResponse_RoomStateEvent,
	},

	Timeline {
		event: SyncResponse_RoomEvent,
	},
}

#[allow(non_camel_case_types)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SyncResponse_RoomSummary {
	#[serde(default, rename = "m.heroes")]
	heroes: Vec<String>,

	#[serde(rename = "m.invited_member_count")]
	invited_member_count: Option<usize>,

	#[serde(rename = "m.joined_member_count")]
	joined_member_count: Option<usize>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SyncResponse_RoomStateEvent {
	content: serde_json::Map<String, serde_json::Value>,
	#[serde(with = "chrono::serde::ts_milliseconds")]
	origin_server_ts: chrono::DateTime<chrono::Utc>,
	sender: String,
	r#type: String,
	unsigned: Option<serde_json::Map<String, serde_json::Value>>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SyncResponse_RoomEvent {
	content: serde_json::Map<String, serde_json::Value>,
	#[serde(with = "chrono::serde::ts_milliseconds")]
	origin_server_ts: chrono::DateTime<chrono::Utc>,
	sender: String,
	r#type: String,
	unsigned: Option<serde_json::Map<String, serde_json::Value>>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SyncResponse_AccountData {
	events: Vec<SyncResponse_AccountData_Event>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SyncResponse_AccountData_Event {
	content: serde_json::Map<String, serde_json::Value>,
	r#type: String,
}

macro_rules! define_events {
	(
		$(
			$s:literal => $ident:ident { $($field_name:ident : $field_ty:ty),* },
		)*
	) => {
		#[allow(non_camel_case_types)]
		enum Event {
			$($ident { $($field_name : $field_ty ,)* },)*

			M_Room_Message(Event_M_Room_Message_Content),

			Unknown {
				r#type: String,
				content: serde_json::Map<String, serde_json::Value>,
			},
		}

		impl Event {
			fn parse(
				r#type: String,
				mut content: serde_json::Map<String, serde_json::Value>,
				unsigned: Option<serde_json::Map<String, serde_json::Value>>,
			) -> Result<Self, serde_json::Error> {
				Ok(match &*r#type {
					$(
						$s => {
							#[derive(serde::Deserialize)]
							struct Content {
								$($field_name : $field_ty ,)*
							}

							let Content { $($field_name),* } = serde::Deserialize::deserialize(serde_json::Value::Object(content))?;
							Event::$ident { $($field_name),* }
						},
					)*

					"m.room.message" => {
						let msgtype = content.remove("msgtype");
						let msgtype = match msgtype {
							Some(serde_json::Value::String(s)) => Some(s),
							Some(msgtype) => return Err(serde::de::Error::custom(format!(r#"non-string "msgtype" in event {type} {content:?}: {msgtype:?}"#))),
							None => None,
						};
						let content = match (msgtype.as_deref(), unsigned) {
							(Some("m.file"), _) => Event_M_Room_Message_Content::File(serde::Deserialize::deserialize(serde_json::Value::Object(content))?),

							(Some("m.image"), _) => Event_M_Room_Message_Content::Image(serde::Deserialize::deserialize(serde_json::Value::Object(content))?),

							(Some("m.notice"), _) => Event_M_Room_Message_Content::Notice(serde::Deserialize::deserialize(serde_json::Value::Object(content))?),

							(Some("m.text"), _) => Event_M_Room_Message_Content::Text(serde::Deserialize::deserialize(serde_json::Value::Object(content))?),

							(None, Some(unsigned)) => Event_M_Room_Message_Content::Redacted(serde::Deserialize::deserialize(serde_json::Value::Object(unsigned))?),

							(_, unsigned) => Event_M_Room_Message_Content::Other(Event_M_Room_Message_Content_Other {
								msgtype,
								content,
								unsigned,
							}),
						};
						Event::M_Room_Message(content)
					},

					_ => Event::Unknown { r#type, content },
				})
			}
		}
	};
}

define_events! {
	"m.room.canonical_alias" => M_Room_CanonicalAlias { alias: Option<String> },
	"m.room.create" => M_Room_Create { room_version: Option<String> },
	"m.room.encrypted" => M_Room_Encrypted { algorithm: String, ciphertext: String, device_id: String, sender_key: String, session_id: String },
	"m.room.guest_access" => M_Room_GuestAccess { guest_access: String },
	"m.room.history_visibility" => M_Room_HistoryVisibility { history_visibility: String },
	"m.room.join_rules" => M_Room_JoinRules { join_rule: String },
	"m.room.name" => M_Room_Name { name: String },
	"m.room.power_levels" => M_Room_PowerLevels { users: std::collections::BTreeMap<String, usize>, users_default: Option<usize> },
	"m.room.related_groups" => M_Room_RelatedGroups { groups: Vec<String> },
	"m.room.tombstone" => M_Room_Tombstone { body: String, replacement_room: String },
	"m.room.topic" => M_Room_Topic { topic: String },
}

#[allow(non_camel_case_types)]
enum Event_M_Room_Message_Content {
	File(Event_M_Room_Message_Content_File),
	Image(Event_M_Room_Message_Content_Image),
	Notice(Event_M_Room_Message_Content_Notice),
	Redacted(Event_M_Room_Message_Content_Redacted),
	Text(Event_M_Room_Message_Content_Text),
	Other(Event_M_Room_Message_Content_Other),
}

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize)]
struct Event_M_Room_Message_Content_File {
	body: String,
	url: String,
}

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize)]
struct Event_M_Room_Message_Content_Image {
	body: String,
	url: String,
}

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize)]
struct Event_M_Room_Message_Content_Notice {
	body: String,
}

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize)]
struct Event_M_Room_Message_Content_Redacted {
	redacted_because: Option<SyncResponse_RoomEvent>,
	redacted_by: Option<String>,
}

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize)]
struct Event_M_Room_Message_Content_Text {
	body: String,
}

#[allow(non_camel_case_types)]
struct Event_M_Room_Message_Content_Other {
	msgtype: Option<String>,
	content: serde_json::Map<String, serde_json::Value>,
	unsigned: Option<serde_json::Map<String, serde_json::Value>>,
}

macro_rules! define_account_data_events {
	(
		$(
			$s:literal => $ident:ident { $($field_name:ident : $field_ty:ty),* },
		)*
	) => {
		#[allow(non_camel_case_types)]
		enum AccountDataEvent {
			$($ident { $($field_name : $field_ty ,)* },)*

			M_SecretStorage_Key {
				id: String,
				description: KeyDescription,
			},

			Unknown {
				#[allow(unused)]
				r#type: String,
				#[allow(unused)]
				content: serde_json::Map<String, serde_json::Value>,
			},
		}

		impl AccountDataEvent {
			fn parse(
				r#type: String,
				content: serde_json::Map<String, serde_json::Value>,
			) -> Result<Self, serde_json::Error> {
				Ok(match &*r#type {
					$(
						$s => {
							#[derive(serde::Deserialize)]
							struct Content {
								$($field_name : $field_ty ,)*
							}

							let Content { $($field_name),* } = serde::Deserialize::deserialize(serde_json::Value::Object(content))?;
							AccountDataEvent::$ident { $($field_name),* }
						},
					)*

					_ => match r#type.strip_prefix("m.secret_storage.key.") {
						Some(key_id) => {
							let description = serde::Deserialize::deserialize(serde_json::Value::Object(content))?;
							AccountDataEvent::M_SecretStorage_Key {
								id: key_id.to_owned(),
								description,
							}
						},

						None => AccountDataEvent::Unknown { r#type, content },
					},
				})
			}
		}
	};
}

define_account_data_events! {
	"m.secret_storage.default_key" => M_SecretStorage_DefaultKey { key: String },
	"m.cross_signing.master" => M_CrossSigning_Master { encrypted: std::collections::BTreeMap<String, Secret> },
	"m.cross_signing.self_signing" => M_CrossSigning_SelfSigning { encrypted: std::collections::BTreeMap<String, Secret> },
	"m.cross_signing.user_signing" => M_CrossSigning_UserSigning { encrypted: std::collections::BTreeMap<String, Secret> },
	"m.megolm_backup.v1" => M_MegolmBackup_V1 { encrypted: std::collections::BTreeMap<String, Secret> },
}

#[derive(serde::Deserialize)]
struct KeyDescription {
	#[serde(flatten)]
	algorithm: KeyDescription_Algorithm,
	name: Option<String>,
	passphrase: Option<KeyDescription_Passphrase>,
}

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize)]
#[serde(tag = "algorithm")]
enum KeyDescription_Algorithm {
	#[serde(rename = "m.secret_storage.v1.aes-hmac-sha2")]
	AesHmacSha2 {
		#[serde(deserialize_with = "deserialize_base64_fixed_len")]
		iv: [u8; 16],
		#[serde(deserialize_with = "deserialize_base64_mac")]
		mac: hmac::digest::CtOutput<hmac::Hmac<sha2::Sha256>>,
	},
}

#[allow(non_camel_case_types)]
#[derive(serde::Deserialize)]
#[serde(tag = "algorithm")]
enum KeyDescription_Passphrase {
	#[serde(rename = "m.pbkdf2")]
	Pbkdf2 {
		bits: Option<usize>,
		salt: String,
		iterations: u32,
	},
}

#[derive(serde::Deserialize)]
struct Secret {
	#[serde(flatten)]
	raw: serde_json::Map<String, serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct AesHmacSha2Secret {
	#[serde(deserialize_with = "deserialize_base64_variable_len")]
	ciphertext: Vec<u8>,
	#[serde(deserialize_with = "deserialize_base64_fixed_len")]
	iv: [u8; 16],
	#[serde(deserialize_with = "deserialize_base64_mac")]
	mac: hmac::digest::CtOutput<hmac::Hmac<sha2::Sha256>>,
}

impl Secret {
	fn into_aes_hmac_sha2(self) -> anyhow::Result<AesHmacSha2Secret> {
		let Secret { raw } = self;
		let secret =
			serde::Deserialize::deserialize(serde_json::Value::Object(raw))
			.context("could not reinterpret as m.secret_storage.v1.aes-hmac-sha2")?;
		Ok(secret)
	}
}

fn deserialize_base64_fixed_len<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error> where D: serde::Deserializer<'de> {
	let result = deserialize_base64_variable_len(deserializer)?;
	let result = result[..].try_into().map_err(serde::de::Error::custom)?;
	Ok(result)
}

fn deserialize_base64_mac<'de, D>(deserializer: D) -> Result<hmac::digest::CtOutput<hmac::Hmac<sha2::Sha256>>, D::Error> where D: serde::Deserializer<'de> {
	let result: [u8; 32] = deserialize_base64_fixed_len(deserializer)?;
	let result: hmac::digest::Output<hmac::Hmac<sha2::Sha256>> = result.into();
	let result = result.into();
	Ok(result)
}

fn deserialize_base64_variable_len<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error> where D: serde::Deserializer<'de> {
	struct Visitor;

	impl<'de> serde::de::Visitor<'de> for Visitor {
		type Value = Vec<u8>;

		fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.write_str("base64-encoded string")
		}

		fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error {
			base64::decode(v).map_err(serde::de::Error::custom)
		}
	}

	deserializer.deserialize_str(Visitor)
}
