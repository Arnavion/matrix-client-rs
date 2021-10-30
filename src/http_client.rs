use anyhow::Context;

pub(crate) struct Client {
	inner: hyper::Client<hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>, hyper::Body>,
	user_agent: http::HeaderValue,
}

impl Client {
	pub(crate) fn new(user_agent: http::HeaderValue) -> Self {
		// Use this long form instead of just `hyper_rustls::HttpsConnector::with_webpki_roots()`
		// because otherwise it tries to initiate HTTP/2 connections with some hosts.
		//
		// Ref: https://github.com/ctz/hyper-rustls/issues/143
		let connector: hyper_rustls::HttpsConnector<_> = {
			let mut connector = hyper::client::connect::HttpConnector::new();
			connector.enforce_http(false);

			let mut config = rustls::ClientConfig::new();
			config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
			config.alpn_protocols = vec![b"http/1.1".to_vec()];
			config.ct_logs = Some(&ct_logs::LOGS);

			(connector, config).into()
		};

		let inner = hyper::Client::builder().build(connector);

		Client {
			inner,
			user_agent,
		}
	}

	pub(crate) async fn request<TBody, TResponse>(
		&self,
		base: &str,
		path: &str,
		mut auth_header: Option<http::HeaderValue>,
		mut method: RequestMethod<TBody>,
	) -> anyhow::Result<HomeserverResponse<TResponse>>
	where
		TBody: serde::Serialize,
		TResponse: serde::de::DeserializeOwned,
	{
		enum Response {
			Json(serde_json::Value),
			Redirect(http::Uri),
		}

		// This fn encapsulates the non-generic parts of `request` to reduce code size from monomorphization.
		async fn request_inner(
			client: &Client,
			mut req: hyper::Request<hyper::Body>,
			uri: http::Uri,
			auth_header: Option<http::HeaderValue>,
		) -> anyhow::Result<Response> {
			*req.uri_mut() = uri;

			if let Some(auth_header) = auth_header {
				req.headers_mut().append(http::header::AUTHORIZATION, auth_header);
			}

			req.headers_mut().insert(http::header::ACCEPT, APPLICATION_JSON.clone());
			req.headers_mut().insert(http::header::USER_AGENT, client.user_agent.clone());

			let res = client.inner.request(req).await.context("could not execute request")?;

			let (http::response::Parts { status, mut headers, .. }, body) = res.into_parts();

			Ok(if status.is_redirection() {
				let location =
					headers.remove(http::header::LOCATION)
					.with_context(|| format!("could not execute request: received {} but no location header", status))?;
				let location = location.as_bytes();
				let location =
					location.try_into()
					.context("could not execute request: received redirect resposne with malformed location header")?;
				Response::Redirect(location)
			}
			else {
				let content_type = headers.remove(http::header::CONTENT_TYPE);
				if content_type.as_ref() != Some(&*APPLICATION_JSON) {
					return Err(anyhow::anyhow!("could not execute request: unexpected content-type {:?}", content_type));
				}
				let body = hyper::body::aggregate(body).await.context("could not execute request: could not read response body")?;
				let body = hyper::body::Buf::reader(body);
				let body: serde_json::Value = serde_json::from_reader(body).context("could not execute request")?;
				Response::Json(body)
			})
		}

		let mut uri = format!("{}{}", base, path).try_into().context("could not request")?;

		loop {
			let follow_redirect = matches!(method, RequestMethod::Get) && auth_header.is_none();

			let req = match method {
				RequestMethod::Get => {
					let mut req = http::Request::new(Default::default());
					*req.method_mut() = http::Method::GET;
					req
				},
				RequestMethod::Post(body) => {
					let body = serde_json::to_vec(&body).context("could not request")?;
					let mut req = http::Request::new(body.into());
					*req.method_mut() = http::Method::POST;
					req.headers_mut().append(http::header::CONTENT_TYPE, APPLICATION_JSON.clone());
					req
				},
			};

			let body = request_inner(self, req, uri, auth_header).await?;

			match body {
				Response::Json(body) =>
					break Ok(if let Ok(err) = serde::Deserialize::deserialize(&body) {
						HomeserverResponse::Err(err)
					}
					else {
						let body = serde::Deserialize::deserialize(body).context("could not execute request")?;
						HomeserverResponse::Ok(body)
					}),

				Response::Redirect(redirect_uri) if follow_redirect => {
					uri = redirect_uri;
					auth_header = None;
					method = RequestMethod::Get;
				},

				Response::Redirect(_) => 
					return Err(anyhow::anyhow!("could not execute request: unredirectable request got redirect response")),
			}
		}
	}
}

pub(crate) enum RequestMethod<TBody> {
	Get,
	Post(TBody),
}

#[derive(Debug, serde::Deserialize, thiserror::Error)]
#[error("{errcode}: {error}")]
pub(crate) struct HomeserverError {
	pub(crate) errcode: String,
	pub(crate) error: String,
}

pub(crate) enum HomeserverResponse<TResponse> {
	Ok(TResponse),
	Err(HomeserverError),
}

impl<TResponse> HomeserverResponse<TResponse> {
	pub(crate) fn into_result(self) -> Result<TResponse, HomeserverError> {
		match self {
			HomeserverResponse::Ok(response) => Ok(response),
			HomeserverResponse::Err(err) => Err(err),
		}
	}
}

static APPLICATION_JSON: once_cell2::race::LazyBox<http::HeaderValue> =
	once_cell2::race::LazyBox::new(|| http::HeaderValue::from_static("application/json"));
