mod controller;
mod http_client;
mod state;
mod view;

use anyhow::Context;

#[derive(clap::Parser)]
struct Options {
	user_id: String,

	#[command(subcommand)]
	command: Option<Command>,
}

#[derive(clap::Parser)]
enum Command {
	Config {
		#[command(subcommand)]
		options: ConfigOptions,
	},

	#[command(name = "_controller", hide(true))]
	Controller,

	#[command(name = "_view", hide(true))]
	View {
		room_id: String,

		lines: std::path::PathBuf,
	},
}

#[derive(clap::Parser)]
enum ConfigOptions {
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
			if let Ok(value) = std::env::var("DEBUG") {
				controller.args(["-e", &format!("DEBUG={value}")]);
			}
			if let Ok(value) = std::env::var("MATRIX_HOMESERVER_BASE_URL") {
				controller.args(["-e", &format!("MATRIX_HOMESERVER_BASE_URL={value}")]);
			}
			controller.arg(arg0);
			controller.args([&user_id, "_controller"]);
			let err = std::os::unix::process::CommandExt::exec(&mut controller);
			return Err(err).context("execvp failed");
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

			() = state_manager.save(&state).context("could not save state")?;

			_ = writeln!(stderr, "Done.");
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
