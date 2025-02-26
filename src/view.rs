use anyhow::Context;

pub(crate) fn run(user_id: &str, room_id: &str, lines: &std::path::Path) -> anyhow::Result<()> {
	use std::io::Write;

	let mut stdout = std::io::stdout().lock();

	let mut stderr = std::io::stderr().lock();

	let mut terminfo = terminal::terminfo::Terminfo::from_env().context("could not get terminfo")?;
	let (to_status_line, from_status_line) = terminfo.write_status_line();

	let tmux_pane = std::env::var_os("TMUX_PANE").context("could not read TMUX_PANE env var")?;

	let lines = std::fs::File::open(lines).context("could not open lines file")?;
	let lines = std::io::BufReader::new(lines);
	let lines = serde_json::Deserializer::from_reader(lines);
	let mut lines = lines.into_iter();

	let mut last_event_origin_server_date = None;

	let mut room_joined_member_count = 0;
	let mut room_invited_member_count = 0;
	let mut room_heroes = vec![];

	let mut room_name = None;
	let mut room_canonical_alias: Option<String> = None;
	let mut room_is_tombstoned = false;
	let mut room_display_name_changed = true;

	let mut user_power_levels: std::collections::BTreeMap<String, usize> = Default::default();
	let mut user_power_level_default = 0;

	loop {
		if room_display_name_changed {
			let room_display_name: std::borrow::Cow<'_, str> =
				if let Some(room_canonical_alias) = room_canonical_alias.as_deref() {
					room_canonical_alias.into()
				}
				else if let Some(room_name) = room_name.as_deref() {
					format!("{room_name} ({room_id})").into()
				}
				else if room_heroes.len() + 1 >= room_joined_member_count + room_invited_member_count {
					format!("{} ({room_id})", room_heroes.join(", ")).into()
				}
				else {
					room_id.into()
				};
			let room_display_name: std::borrow::Cow<'_, str> =
				if room_is_tombstoned {
					format!("\u{1faa6} {room_display_name} \u{1faa6}").into()
				}
				else {
					room_display_name
				};

			_ = stdout.write_all(to_status_line);
			_ = stdout.write_all(room_display_name.as_bytes());
			_ = stdout.write_all(from_status_line);
			_ = stdout.flush();

			let mut rename_command = crate::tmux(user_id)?;
			rename_command.args(["rename-window", "-t"]);
			rename_command.arg(&tmux_pane);
			// Replace `#` with `##` because tmux has special handling for some sequences like `#T`
			rename_command.arg(room_display_name.replace('#', "##"));
			_ = rename_command.output().context("could not rename tmux window to new room display name")?;

			room_display_name_changed = false;
		}

		let line =
			lines.next()
			.context("could not read line from lines file")?
			.context("could not read line from lines file")?;

		if std::env::var("DEBUG").as_deref() == Ok("1") {
			_ = writeln!(stderr, "{line:?}");
		}

		let (origin_server_ts, sender, event) = match line {
			crate::RoomViewLine::Summary { summary } => {
				if let Some(invited_member_count) = summary.invited_member_count {
					room_invited_member_count = invited_member_count;
				}

				if let Some(joined_member_count) = summary.joined_member_count {
					room_joined_member_count = joined_member_count;
				}

				if !summary.heroes.is_empty() {
					room_heroes = summary.heroes;
				}

				room_display_name_changed = true;
				continue;
			},

			crate::RoomViewLine::State { event: crate::SyncResponse_RoomStateEvent { content, origin_server_ts, sender, r#type, unsigned } } |
			crate::RoomViewLine::Timeline { event: crate::SyncResponse_RoomEvent { content, origin_server_ts, sender, r#type, unsigned } } => {
				let event = crate::Event::parse(r#type, content, unsigned).context("could not parse event")?;
				(origin_server_ts, sender, event)
			},
		};

		let origin_server_ts = origin_server_ts.with_timezone(&chrono::Local);
		let origin_server_date = origin_server_ts.date_naive();
		if last_event_origin_server_date != Some(origin_server_date) {
			if last_event_origin_server_date.is_some() {
				_ = writeln!(stdout);
			}
			_ = writeln!(stdout, "--- {origin_server_date} ---");

			last_event_origin_server_date = Some(origin_server_date);
		}

		_ = write!(stdout, "[{}] ", origin_server_ts.format_with_items([
			chrono::format::Item::Numeric(chrono::format::Numeric::Hour, chrono::format::Pad::Zero),
			chrono::format::Item::Literal(":"),
			chrono::format::Item::Numeric(chrono::format::Numeric::Minute, chrono::format::Pad::Zero),
			chrono::format::Item::Literal(":"),
			chrono::format::Item::Numeric(chrono::format::Numeric::Second, chrono::format::Pad::Zero),
		].into_iter()));

		match event {
			crate::Event::M_Room_CanonicalAlias { alias } => {
				if let Some(alias) = &alias {
					write_with_sender(
						&mut stdout, &sender, &user_power_levels, user_power_level_default,
						SenderDecoration::Event,
						format_args!("set room canonical alias to {alias}\n"),
					);
				}
				else {
					write_with_sender(
						&mut stdout, &sender, &user_power_levels, user_power_level_default,
						SenderDecoration::Event,
						format_args!("removed room canonical alias\n"),
					);
				}
				room_canonical_alias = alias;
				room_display_name_changed = true;
			},

			crate::Event::M_Room_Create { room_version } =>
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("created room with version {room_version}\n", room_version = room_version.as_deref().unwrap_or("1")),
				),

			crate::Event::M_Room_Encrypted { algorithm, ciphertext, device_id, sender_key, session_id } =>
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Message,
					format_args!("[encrypted message] {algorithm:?} {session_id:?} {sender_key:?} {device_id:?} {ciphertext:?}\n"),
				),

			crate::Event::M_Room_Encryption { algorithm } =>
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("enabled room encryption with algorithm {algorithm}\n"),
				),

			crate::Event::M_Room_GuestAccess { guest_access } =>
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("set room guest access to {guest_access}\n"),
				),

			crate::Event::M_Room_HistoryVisibility { history_visibility } =>
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("set room history visibility to {history_visibility}\n"),
				),

			crate::Event::M_Room_JoinRules { join_rule } =>
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("set room join rules to {join_rule}\n"),
				),

			crate::Event::M_Room_Message(content) => match content {
				crate::Event_M_Room_Message_Content::Emote(crate::Event_M_Room_Message_Content_Emote { body }) => {
					write_with_sender(
						&mut stdout, &sender, &user_power_levels, user_power_level_default,
						SenderDecoration::Emote,
						format_args!(""),
					);
					print_multiline(&mut stdout, &body);
				},

				crate::Event_M_Room_Message_Content::File(crate::Event_M_Room_Message_Content_File { body, url }) =>
					write_with_sender(
						&mut stdout, &sender, &user_power_levels, user_power_level_default,
						SenderDecoration::Event,
						format_args!("posted file {body} at {url}\n"),
					),

				crate::Event_M_Room_Message_Content::Image(crate::Event_M_Room_Message_Content_Image { body, url }) =>
					write_with_sender(
						&mut stdout, &sender, &user_power_levels, user_power_level_default,
						SenderDecoration::Event,
						format_args!("posted image {body} at {url}\n"),
					),

				crate::Event_M_Room_Message_Content::Notice(crate::Event_M_Room_Message_Content_Notice { body }) |
				crate::Event_M_Room_Message_Content::Text(crate::Event_M_Room_Message_Content_Text { body }) => {
					write_with_sender(
						&mut stdout, &sender, &user_power_levels, user_power_level_default,
						SenderDecoration::Message,
						format_args!(""),
					);
					print_multiline(&mut stdout, &body);
				},

				crate::Event_M_Room_Message_Content::Redacted(crate::Event_M_Room_Message_Content_Redacted { redacted_because, redacted_by }) =>
					write_with_sender(
						&mut stdout, &sender, &user_power_levels, user_power_level_default,
						SenderDecoration::Message,
						format_args!(
							"<redacted by {redacted_by}> {redacted_because:?}\n",
							redacted_by = redacted_by.as_deref().unwrap_or("(unknown)"),
						),
					),

				crate::Event_M_Room_Message_Content::Other(crate::Event_M_Room_Message_Content_Other { msgtype, content, unsigned }) =>
					write_with_sender(
						&mut stdout, &sender, &user_power_levels, user_power_level_default,
						SenderDecoration::Event,
						format_args!("{msgtype:?} {content:?} {unsigned:?}\n"),
					),
			},

			crate::Event::M_Room_Name { name } => {
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("set room name to {name}\n"),
				);
				room_name = Some(name);
				room_display_name_changed = true;
			},

			crate::Event::M_Room_PowerLevels { users, users_default } => {
				user_power_level_default = users_default.unwrap_or(0);

				let mut users_by_power_level: std::collections::BTreeMap<std::cmp::Reverse<usize>, Vec<String>> = Default::default();
				for (user_id, power_level) in users {
					users_by_power_level.entry(std::cmp::Reverse(power_level)).or_default().push(user_id.clone());
					user_power_levels.insert(user_id, power_level);
				}

				let mut result = String::new();
				for (std::cmp::Reverse(power_level), mut users) in users_by_power_level {
					use std::fmt::Write;

					if !result.is_empty() {
						result.push_str("; ");
					}
					users.sort();
					write!(result, "{power_level}: {}", users.join(", ")).unwrap();
				}

				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("set room power levels: {result}\n"),
				);
			},

			crate::Event::M_Room_RelatedGroups { groups } =>
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("set room related groups to {groups}\n", groups = groups.join(", ")),
				),

			crate::Event::M_Room_Tombstone { body, replacement_room } => {
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("tombstoned room with replacement {replacement_room}: "),
				);
				print_multiline(&mut stdout, &body);
				room_is_tombstoned = true;
				room_display_name_changed = true;
			},

			crate::Event::M_Room_Topic { topic } => {
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("set room topic to "),
				);
				print_multiline(&mut stdout, &topic);
			},

			crate::Event::Unknown { r#type, content } =>
				write_with_sender(
					&mut stdout, &sender, &user_power_levels, user_power_level_default,
					SenderDecoration::Event,
					format_args!("{type} {content:?}\n"),
				),
		}
	}
}

fn print_multiline(stdout: &mut impl std::io::Write, s: &str) {
	if let Some((mut line, rest)) = s.split_once('\n') {
		let mut rest = Some(rest);

		_ = writeln!(stdout, ">");

		loop {
			_ = writeln!(stdout, "           | {line}");

			let Some(rest_) = rest else { break; };
			let (next_line, next_rest) = rest_.split_once('\n').map_or((rest_, None), |(line, rest)| (line, Some(rest)));
			line = next_line;
			rest = next_rest;
		}
	}
	else {
		_ = writeln!(stdout, "{s}");
	}
}

#[derive(Clone, Copy)]
enum SenderDecoration {
	Emote,
	Event,
	Message,
}

fn write_with_sender(
	stdout: &mut impl std::io::Write,
	sender: &str,
	user_power_levels: &std::collections::BTreeMap<String, usize>,
	user_power_level_default: usize,
	decoration: SenderDecoration,
	rest: std::fmt::Arguments<'_>,
) {
	let (decoration_start, decoration_end) = match decoration {
		SenderDecoration::Emote => ("<", "> /me"),
		SenderDecoration::Event => ("", ""),
		SenderDecoration::Message => ("<", ">"),
	};

	let user_power_level = user_power_levels.get(sender).copied().unwrap_or(user_power_level_default);
	if user_power_level == user_power_level_default {
		_ = write!(stdout, "{decoration_start}{sender}{decoration_end}");
	}
	else {
		_ = write!(stdout, "{decoration_start}[{user_power_level}] {sender}{decoration_end}");
	}

	_ = write!(stdout, " {rest}");
}
