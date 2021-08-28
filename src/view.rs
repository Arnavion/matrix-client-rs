use anyhow::Context;

pub(crate) fn run(room_id: &str, lines: &std::path::Path) -> anyhow::Result<()> {
	use std::io::Write;

	let stdout = std::io::stdout();
	let mut stdout = stdout.lock();

	let stderr = std::io::stderr();
	let mut stderr = stderr.lock();

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
					format!("{} ({})", room_name, room_id).into()
				}
				else if room_heroes.len() + 1 >= room_joined_member_count + room_invited_member_count {
					format!("{} ({})", room_heroes.join(", "), room_id).into()
				}
				else {
					(&*room_id).into()
				};

			let _ = write!(stdout, "\x1B]2;{}\x1B\\", room_display_name);
			let _ = stdout.flush();

			let mut rename_command = std::process::Command::new("tmux");
			rename_command.args(&["rename-window", "-t"]);
			rename_command.arg(&tmux_pane);
			rename_command.arg(&*room_display_name);
			let _ = rename_command.output().context("could not rename tmux window to new room display name")?;

			room_display_name_changed = false;
		}

		let line =
			lines.next()
			.context("could not read line from lines file")?
			.context("could not read line from lines file")?;

		if std::env::var_os("DEBUG").is_some() {
			let _ = writeln!(stderr, "{:?}", line);
		}

		let (origin_server_ts, sender, event) = match line {
			crate::RoomViewLine::AccountData { account_data } => {
				if !account_data.events.is_empty() {
					eprintln!("{}", serde_json::to_string(&account_data).unwrap());
				}
				continue;
			},

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
		let origin_server_date = origin_server_ts.date();
		if last_event_origin_server_date != Some(origin_server_date) {
			if last_event_origin_server_date.is_some() {
				let _ = writeln!(stdout);
			}
			let _ = writeln!(stdout, "--- {} ---", origin_server_date);

			last_event_origin_server_date = Some(origin_server_date);
		}

		let _ = write!(stdout, "[{}] ", origin_server_ts.format_with_items(std::array::IntoIter::new([
			chrono::format::Item::Numeric(chrono::format::Numeric::Hour, chrono::format::Pad::Zero),
			chrono::format::Item::Literal(":"),
			chrono::format::Item::Numeric(chrono::format::Numeric::Minute, chrono::format::Pad::Zero),
			chrono::format::Item::Literal(":"),
			chrono::format::Item::Numeric(chrono::format::Numeric::Second, chrono::format::Pad::Zero),
		])));

		match event {
			crate::Event::M_Room_CanonicalAlias { alias } => {
				let _ = writeln!(stdout,
					"![{power_level}] {sender}! set room canonical alias to {alias}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					alias = alias,
				);
				room_canonical_alias = Some(alias);
				room_display_name_changed = true;
			},

			crate::Event::M_Room_Create { room_version } => {
				let _ = writeln!(stdout,
					"![{power_level}] {sender}! created room with version {room_version}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					room_version = room_version.as_deref().unwrap_or("1"),
				);
			},

			crate::Event::M_Room_Encrypted { algorithm, ciphertext, device_id, sender_key, session_id } => {
				let _ = writeln!(stdout,
					"<[{power_level}] {sender}> [encrypted message] {algorithm} {session_id} {sender_key} {device_id} {ciphertext}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					algorithm = algorithm,
					session_id = session_id,
					sender_key = sender_key,
					device_id = device_id,
					ciphertext = ciphertext,
				);
			},

			crate::Event::M_Room_GuestAccess { guest_access } => {
				let _ = writeln!(stdout,
					"![{power_level}] {sender}! set room guest access to {guest_access}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					guest_access = guest_access,
				);
			},

			crate::Event::M_Room_HistoryVisibility { history_visibility } => {
				let _ = writeln!(stdout,
					"![{power_level}] {sender}! set room history visibility to {history_visibility}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					history_visibility = history_visibility,
				);
			},

			crate::Event::M_Room_JoinRules { join_rule } => {
				let _ = writeln!(stdout,
					"![{power_level}] {sender}! set room join rules to {join_rule}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					join_rule = join_rule,
				);
			},

			crate::Event::M_Room_Message(content) => match content {
				crate::Event_M_Room_Message_Content::File(crate::Event_M_Room_Message_Content_File { body, url }) => {
					let _ = writeln!(stdout,
						"![{power_level}] {sender}! posted file {body} at {url}",
						power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
						sender = sender,
						body = body,
						url = url,
					);
				},

				crate::Event_M_Room_Message_Content::Image(crate::Event_M_Room_Message_Content_Image { body, url }) => {
					let _ = writeln!(stdout,
						"![{power_level}] {sender}! posted image {body} at {url}",
						power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
						sender = sender,
						body = body,
						url = url,
					);
				},

				crate::Event_M_Room_Message_Content::Notice(crate::Event_M_Room_Message_Content_Notice { body }) => {
					let _ = write!(stdout,
						"<[{power_level}] {sender}> ",
						power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
						sender = sender,
					);
					print_multiline(&mut stdout, &body);
				},

				crate::Event_M_Room_Message_Content::Redacted(crate::Event_M_Room_Message_Content_Redacted { redacted_because, redacted_by }) => {
					let _ = writeln!(stdout,
						"<[{power_level}] {sender}> <redacted by {redacted_by}> {redacted_because:?}",
						power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
						sender = sender,
						redacted_by = redacted_by.as_deref().unwrap_or("(unknown)"),
						redacted_because = redacted_because,
					);
				},

				crate::Event_M_Room_Message_Content::Text(crate::Event_M_Room_Message_Content_Text { body }) => {
					let _ = write!(stdout,
						"<[{power_level}] {sender}> ",
						power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
						sender = sender,
					);
					print_multiline(&mut stdout, &body);
				},

				crate::Event_M_Room_Message_Content::Other(crate::Event_M_Room_Message_Content_Other { msgtype, content, unsigned }) => {
					let _ = writeln!(stdout,
						"![{power_level}] {sender}! {msgtype:?} {content:?} {unsigned:?}",
						power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
						sender = sender,
						msgtype = msgtype,
						content = content,
						unsigned = unsigned,
					);
				},
			},

			crate::Event::M_Room_Name { name } => {
				let _ = writeln!(stdout,
					"![{power_level}] {sender}! set room name to {name}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					name = name,
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
					if !result.is_empty() {
						result.push_str("; ");
					}
					users.sort();
					result.push_str(&format!("{}: {}", power_level, users.join(", ")));
				}

				let _ = writeln!(stdout,
					"![{power_level}] {sender}! set room power levels: {result}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					result = result,
				);
			},

			crate::Event::M_Room_RelatedGroups { groups } => {
				let _ = writeln!(stdout,
					"![{power_level}] {sender}! set room related groups to {groups}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					groups = groups.join(", "),
				);
			},

			crate::Event::M_Room_Topic { topic } => {
				let _ = write!(stdout,
					"![{power_level}] {sender}! set room topic to ",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
				);
				print_multiline(&mut stdout, &topic);
			},

			crate::Event::Unknown { r#type, content } => {
				let _ = writeln!(stdout,
					"![{power_level}] {sender}! {type} {content:?}",
					power_level = user_power_levels.get(&sender).unwrap_or(&user_power_level_default),
					sender = sender,
					r#type = r#type,
					content = content,
				);
			},
		}
	}
}

fn print_multiline(stdout: &mut impl std::io::Write, s: &str) {
	if let Some((mut line, rest)) = s.split_once('\n') {
		let mut rest = Some(rest);

		let _ = writeln!(stdout, ">");

		loop {
			let _ = writeln!(stdout, "           | {}", line);

			if let Some(rest_) = rest {
				let (next_line, next_rest) = rest_.split_once('\n').map_or((rest_, None), |(line, rest)| (line, Some(rest)));
				line = next_line;
				rest = next_rest;
			}
			else {
				break;
			}
		}
	}
	else {
		let _ = writeln!(stdout, "{}", s);
	}
}
