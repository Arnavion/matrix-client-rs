use anyhow::Context;

pub(crate) fn run(user_id: String) -> anyhow::Result<()> {
	let runtime =
		tokio::runtime::Builder::new_current_thread()
		.enable_io()
		.enable_time()
		.build()?;
	let local_set = tokio::task::LocalSet::new();

	let () = local_set.block_on(&runtime, run_inner(user_id))?;
	Ok(())
}

async fn run_inner(user_id: String) -> anyhow::Result<()> {
	use std::io::Write;

	let stdout = std::io::stdout();
	let mut stdout = stdout.lock();

	let stderr = std::io::stderr();
	let mut stderr = stderr.lock();

	write!(stdout, "\x1B]2;{}\x1B\\", user_id)?;
	stdout.flush()?;

	let mut state_manager = crate::state::Manager::new(&user_id).context("could not create state manager")?;

	let client = crate::http_client::Client::new(http::HeaderValue::from_static("github.com/Arnavion/matrix-client"));

	let homeserver_base_url =
		get_homeserver_base_url(&client, &user_id)
		.await.context("could not get homeserver base URL")?;

	let mut auth_header =
		login(&client, &mut state_manager, &homeserver_base_url, &user_id, &mut stderr)
		.await.context("could not log in")?;

	let sync_filter_id =
		create_sync_filter(&client, &homeserver_base_url, auth_header.clone(), &user_id)
		.await.context("could not create sync filter")?;

	let mut sync_next_batch = None;

	let mut keys: std::collections::BTreeMap<String, (Option<String>, hkdf::Hkdf<sha2::Sha256>)> = Default::default();
	#[allow(unused)] // TODO
	let mut default_key_id = None;
	#[allow(unused)] // TODO
	let mut backup_key = None;

	let mut view_fds: std::collections::BTreeMap<String, std::os::unix::io::RawFd> = Default::default();

	loop {
		#[derive(serde::Deserialize)]
		struct SyncResponse {
			account_data: crate::SyncResponse_AccountData,
			next_batch: String,
			rooms: SyncResponse_Rooms,
		}

		#[allow(non_camel_case_types)]
		#[derive(serde::Deserialize)]
		struct SyncResponse_Rooms {
			join: std::collections::BTreeMap<String, SyncResponse_JoinedRoom>,
			leave: std::collections::BTreeMap<String, SyncResponse_LeftRoom>,
		}

		#[allow(non_camel_case_types)]
		#[derive(serde::Deserialize)]
		struct SyncResponse_JoinedRoom {
			account_data: crate::SyncResponse_AccountData,
			state: SyncResponse_RoomState,
			summary: crate::SyncResponse_RoomSummary,
			timeline: SyncResponse_RoomTimeline,
		}

		#[allow(non_camel_case_types)]
		#[derive(serde::Deserialize)]
		struct SyncResponse_LeftRoom {
			account_data: crate::SyncResponse_AccountData,
			state: SyncResponse_RoomState,
			timeline: SyncResponse_RoomTimeline,
		}

		#[allow(non_camel_case_types)]
		#[derive(serde::Deserialize)]
		struct SyncResponse_RoomState {
			events: Vec<crate::SyncResponse_RoomStateEvent>,
		}

		#[allow(non_camel_case_types)]
		#[derive(serde::Deserialize)]
		struct SyncResponse_RoomTimeline {
			events: Vec<crate::SyncResponse_RoomEvent>,
		}

		let sync: SyncResponse = loop {
			write!(stdout, "\rSyncing at {} ... ", chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false))?;
			stdout.flush()?;

			let sync = if let Some(sync_next_batch) = sync_next_batch.as_deref() {
				client.request(
					&homeserver_base_url,
					&format!(
						"/_matrix/client/r0/sync?filter={}&since={}&timeout=10000",
						PercentEncode(&sync_filter_id),
						PercentEncode(sync_next_batch),
					),
					Some(auth_header.clone()),
					crate::http_client::RequestMethod::Get::<()>,
				).await.context("could not sync")?
			}
			else {
				client.request(
					&homeserver_base_url,
					&format!("/_matrix/client/r0/sync?filter={}", PercentEncode(&sync_filter_id)),
					Some(auth_header.clone()),
					crate::http_client::RequestMethod::Get::<()>,
				).await.context("could not sync")?
			};
			match sync {
				crate::http_client::HomeserverResponse::Ok(response) => {
					write!(stdout, "\rSynced at {}      ", chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false))?;
					stdout.flush()?;
					break response;
				},

				crate::http_client::HomeserverResponse::Err(err) => {
					let _ = writeln!(stderr, "{}", err);

					let mut state = state_manager.load().context("could not load state")?;
					state.access_token = None;
					let () = state_manager.save(&state).context("could not save state")?;

					let _ = writeln!(stdout);
					let _ = writeln!(stderr, "Reconnecting to homeserver...");
					auth_header =
						login(&client, &mut state_manager, &homeserver_base_url, &user_id, &mut stderr)
						.await.context("could not log in")?;
				},
			}
		};

		sync_next_batch = Some(sync.next_batch);

		for crate::SyncResponse_AccountData_Event { r#type, content } in sync.account_data.events {
			let event = crate::AccountDataEvent::parse(r#type, content).context("could not parse event")?;
			match event {
				crate::AccountDataEvent::M_SecretStorage_DefaultKey { key } => {
					#[allow(unused)] // TODO
					{
						default_key_id = Some(key);
					}
				},

				crate::AccountDataEvent::M_SecretStorage_Key { id, description: crate::KeyDescription { algorithm, name, passphrase } } => {
					let mut state = state_manager.load().context("could not load state")?;

					if let Some(secret_storage_key) = state.secret_storage_keys.remove(&id) {
						let crate::KeyDescription_Algorithm::AesHmacSha2 { iv, mac } = algorithm;

						let key = match (secret_storage_key, passphrase) {
							(crate::state::SecretStorageKey::Passphrase(state_passphrase), Some(event_passphrase)) => {
								let crate::KeyDescription_Passphrase::Pbkdf2 { bits, salt, iterations } = event_passphrase;
								crate::aes_hmac_sha2::derive_key_from_passphrase(
									state_passphrase.as_bytes(),
									bits,
									&salt,
									iterations,
									&iv,
									&mac,
								).context("could not derive secret storage key from passphrase")?
							},

							(crate::state::SecretStorageKey::Keyfile(keyfile), _) =>
								crate::aes_hmac_sha2::derive_key_from_keyfile(keyfile, &iv, &mac).context("could not decode server backup recovery key")?,

							_ => continue,
						};
						keys.insert(id, (name, key));
					}
				},

				crate::AccountDataEvent::M_MegolmBackup_V1 { encrypted } =>
					for (key_id, secret) in encrypted {
						if let Some((_, key)) = keys.get(&key_id) {
							let crate::AesHmacSha2Secret { ciphertext, iv, mac } =
								secret.into_aes_hmac_sha2()
								.context("could not parse m.megolm_backup.v1 secret")?;
							let mut stream = base64::decode(ciphertext).context("could not parse m.megolm_backup.v1 secret")?;
							let () =
								crate::aes_hmac_sha2::decrypt(
									key,
									"m.megolm_backup.v1",
									&mut stream,
									&iv,
									&mac,
								)
								.context("could not parse m.megolm_backup.v1 secret")?;
							#[allow(unused)] // TODO
							{
								backup_key = Some(base64::decode(&stream).context("could not parse decrypted m.megolm_backup.v1 secret")?);
							}
						}
					},

				crate::AccountDataEvent::Unknown { r#type: _, content: _ } => (),
			}
		}

		let mut to_write: std::collections::BTreeMap<String, Vec<crate::RoomViewLine>> = Default::default();

		for (room_id, room) in sync.rooms.join {
			let lines = to_write.entry(room_id).or_default();

			lines.push(crate::RoomViewLine::Summary { summary: room.summary });
			lines.push(crate::RoomViewLine::AccountData { account_data: room.account_data });

			for event in room.state.events {
				lines.push(crate::RoomViewLine::State { event });
			}

			for event in room.timeline.events {
				lines.push(crate::RoomViewLine::Timeline { event });
			}
		}

		for (room_id, room) in sync.rooms.leave {
			let lines = to_write.entry(room_id).or_default();

			lines.push(crate::RoomViewLine::AccountData { account_data: room.account_data });

			for event in room.state.events {
				lines.push(crate::RoomViewLine::State { event });
			}

			for event in room.timeline.events {
				lines.push(crate::RoomViewLine::Timeline { event });
			}
		}

		for (room_id, lines) in to_write {
			let view_fd = match view_fds.entry(room_id) {
				std::collections::btree_map::Entry::Vacant(entry) => {
					let tempdir =
						tempfile::tempdir()
						.with_context(|| format!("could not create view fd for {}", entry.key()))?;
					let fifo_path = tempdir.path().join("lines");
					let () =
						nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
						.with_context(|| format!("could not create view fd for {}", entry.key()))?;
					let fifo =
						std::fs::OpenOptions::new()
						.read(true)
						.write(true)
						.open(fifo_path)
						.with_context(|| format!("could not create view fd for {}", entry.key()))?;
					drop(tempdir);
					let view_fd = std::os::unix::io::AsRawFd::as_raw_fd(&fifo);

					let mut args = std::env::args_os();
					let arg0 = args.next().context("argv[0] is not set")?;

					let mut view = std::process::Command::new("tmux");
					view.args(&["new-window", "-d"]);
					if std::env::var_os("DEBUG").is_some() {
						view.args(&["-e", "DEBUG=1"]);
					}
					view.arg(arg0);
					view.args(&[&user_id, "_view", entry.key()]);
					view.arg(&format!("/proc/{}/fd/{}", nix::unistd::Pid::this().as_raw(), view_fd));
					let _ =
						view.output()
						.with_context(|| format!("could not create view for {}", entry.key()))?;

					std::mem::forget(fifo);

					*entry.insert(view_fd)
				},

				std::collections::btree_map::Entry::Occupied(entry) => *entry.into_mut(),
			};
			let mut f = std::mem::ManuallyDrop::new(unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(view_fd) });

			for line in lines {
				let () = serde_json::to_writer(&mut *f, &line).context("could not write view line")?;
				f.flush().context("could not write view line")?;
			}
		}
	}
}

async fn get_homeserver_base_url(client: &crate::http_client::Client, user_id: &str) -> anyhow::Result<String> {
	#[derive(serde::Deserialize)]
	struct ClientDiscoveryInfoResponse {
		#[serde(rename = "m.homeserver")]
		m_homeserver: ClientDiscoveryInfoResponse_MHomeserver,
	}

	#[allow(non_camel_case_types)]
	#[derive(serde::Deserialize)]
	struct ClientDiscoveryInfoResponse_MHomeserver {
		base_url: String,
	}

	#[derive(serde::Deserialize)]
	struct ClientVersions {
		versions: Vec<String>,
	}

	let (_, homeserver_name) = user_id.split_once(':').context("could not extract homeserver name from user ID")?;

	let ClientDiscoveryInfoResponse { m_homeserver: ClientDiscoveryInfoResponse_MHomeserver { base_url: homeserver_base_url } } =
		client.request(&format!("https://{}", homeserver_name), "/.well-known/matrix/client", None, crate::http_client::RequestMethod::Get::<()>)
		.await.context("could not get client discovery info")?
		.into_result()
		.context("could not get client discovery info")?;

	let ClientVersions { versions } =
		client.request(&homeserver_base_url, "/_matrix/client/versions", None, crate::http_client::RequestMethod::Get::<()>)
		.await.context("could not get client versions supported by homeserver")?
		.into_result()
		.context("could not get client versions supported by homeserver")?;
	if !versions.into_iter().any(|version| version == "r0.6.0") {
		return Err(anyhow::anyhow!("homeserver does not support client version r0.6.0"));
	}

	Ok(homeserver_base_url)
}

async fn login(
	client: &crate::http_client::Client,
	state_manager: &mut crate::state::Manager,
	homeserver_base_url: &str,
	user_id: &str,
	stderr: &mut impl std::io::Write,
) -> anyhow::Result<http::HeaderValue> {
	let mut state = state_manager.load().context("could not load state")?;

	let access_token =
		if let Some(access_token) = state.access_token {
			access_token
		}
		else {
			#[derive(serde::Deserialize)]
			struct SupportedLoginTypesResponse {
				flows: Vec<SupportedLoginTypesResponse_Flow>,
			}

			#[allow(non_camel_case_types)]
			#[derive(serde::Deserialize)]
			struct SupportedLoginTypesResponse_Flow {
				r#type: String,
			}

			#[derive(serde::Serialize)]
			struct LoginRequest<'a> {
				r#type: &'static str,
				identifier: LoginRequest_Identifier<'a>,
				password: &'a str,
				device_id: &'a str,
				initial_device_display_name: &'a str,
			}

			#[allow(non_camel_case_types)]
			#[derive(serde::Serialize)]
			struct LoginRequest_Identifier<'a> {
				r#type: &'static str,
				user: &'a str,
			}

			#[derive(serde::Deserialize)]
			struct LoginResponse {
				access_token: String,
			}

			let SupportedLoginTypesResponse { flows } =
				client.request(homeserver_base_url, "/_matrix/client/r0/login", None, crate::http_client::RequestMethod::Get::<()>)
				.await.context("could not get supported login types")?
				.into_result()
				.context("could not get supported login types")?;
			if !flows.into_iter().any(|SupportedLoginTypesResponse_Flow { r#type }| r#type == "m.login.password") {
				return Err(anyhow::anyhow!("homeserver does not supported password login"));
			}

			let device_id = {
				use sha2::Digest;

				struct HexDisplay<'a>(&'a [u8]);

				impl std::fmt::Display for HexDisplay<'_> {
					fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
						for b in self.0 {
							write!(f, "{:02x}", b)?;
						}
						Ok(())
					}
				}

				let mut machine_id = std::fs::read("/etc/machine-id").context("could not read /etc/machine-id")?;
				if machine_id.last().copied() == Some(b'\n') {
					machine_id.pop();
				}

				let unique_id = sha2::Sha256::new().chain(&machine_id).finalize();

				format!("matrix-client:{}", HexDisplay(&unique_id))
			};

			let initial_device_display_name = {
				let hostname_max_len =
					nix::unistd::sysconf(nix::unistd::SysconfVar::HOST_NAME_MAX).context("could not get hostname")?
					.unwrap_or(64);
				let hostname_max_len: usize =
					std::convert::TryInto::try_into(hostname_max_len)
					.context("could not get hostname")?;
				let mut hostname = vec![0_u8; hostname_max_len + 1];
				let hostname = nix::unistd::gethostname(&mut hostname).context("could not get hostname")?;
				format!("matrix-client ({})", hostname.to_string_lossy())
			};

			let access_token = loop {
				let password = rpassword::read_password_from_tty(Some("Enter password: ")).context("could not read password")?;

				let login_response =
					client.request(homeserver_base_url, "/_matrix/client/r0/login", None, crate::http_client::RequestMethod::Post(LoginRequest {
						r#type: "m.login.password",
						identifier: LoginRequest_Identifier {
							r#type: "m.id.user",
							user: user_id,
						},
						password: &password,
						device_id: &device_id,
						initial_device_display_name: &initial_device_display_name,
					})).await.context("could not send login request")?;
				match login_response {
					crate::http_client::HomeserverResponse::Ok(LoginResponse { access_token }) => break access_token,

					crate::http_client::HomeserverResponse::Err(err) => {
						let _ = writeln!(stderr, "{}", err);
					},
				}
			};

			state.access_token = Some(access_token.clone());

			let () = state_manager.save(&state).context("could not save state")?;

			access_token
		};

	let auth_header = format!("Bearer {}", access_token).parse().context("could not construct auth header from access token")?;
	Ok(auth_header)
}

async fn create_sync_filter(
	client: &crate::http_client::Client,
	homeserver_base_url: &str,
	auth_header: http::HeaderValue,
	user_id: &str,
) -> anyhow::Result<String> {
	#[derive(serde::Serialize)]
	struct CreateFilterRequest<'a> {
		presence: CreateFilterRequest_EventFilter<'a>,
		room: CreateFilterRequest_RoomFilter<'a>,
	}

	#[allow(non_camel_case_types)]
	#[derive(serde::Serialize)]
	struct CreateFilterRequest_EventFilter<'a> {
		not_types: &'a [&'a str],
	}

	#[allow(non_camel_case_types)]
	#[derive(serde::Serialize)]
	struct CreateFilterRequest_RoomFilter<'a> {
		ephemeral: CreateFilterRequest_RoomEventFilter<'a>,
		include_leave: bool,
		state: CreateFilterRequest_StateFilter<'a>,
		timeline: CreateFilterRequest_RoomEventFilter<'a>,
	}

	#[allow(non_camel_case_types)]
	#[derive(serde::Serialize)]
	struct CreateFilterRequest_RoomEventFilter<'a> {
		lazy_load_members: bool,
		not_types: &'a [&'a str],
	}

	#[allow(non_camel_case_types)]
	#[derive(serde::Serialize)]
	struct CreateFilterRequest_StateFilter<'a> {
		lazy_load_members: bool,
		not_types: &'a [&'a str],
	}

	#[derive(serde::Deserialize)]
	struct CreateFilterResponse {
		filter_id: String,
	}

	let CreateFilterResponse { filter_id } =
		client.request(
			homeserver_base_url,
			&format!("/_matrix/client/r0/user/{}/filter", PercentEncode(user_id)),
			Some(auth_header),
			crate::http_client::RequestMethod::Post(CreateFilterRequest {
				presence: CreateFilterRequest_EventFilter {
					not_types: &["*"],
				},
				room: CreateFilterRequest_RoomFilter {
					ephemeral: CreateFilterRequest_RoomEventFilter {
						lazy_load_members: true,
						not_types: &["*"],
					},
					include_leave: true,
					state: CreateFilterRequest_StateFilter {
						lazy_load_members: true,
						not_types: &[
							"m.reaction",
							"m.room.avatar",
							"m.room.member",
						],
					},
					timeline: CreateFilterRequest_RoomEventFilter {
						lazy_load_members: true,
						not_types: &[
							"m.reaction",
							"m.room.avatar",
							"m.room.member",
						],
					},
				},
			},
		))
		.await.context("could not create sync filter")?
		.into_result()
		.context("could not create sync filter")?;
	Ok(filter_id)
}

struct PercentEncode<'a>(&'a str);

impl std::fmt::Display for PercentEncode<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		for b in self.0.as_bytes() {
			write!(f, "%{:02x}", b)?;
		}
		Ok(())
	}
}
