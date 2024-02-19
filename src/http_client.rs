use anyhow::Context;

pub(crate) struct Client {
	inner: hyper_util::client::legacy::Client<
		hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
		http_body_util::Full<std::collections::VecDeque<u8>>,
	>,
	user_agent: http::HeaderValue,
}

impl Client {
	pub(crate) fn new(user_agent: http::HeaderValue) -> Self {
		let connector =
			hyper_rustls::HttpsConnectorBuilder::new()
			.with_webpki_roots()
			.https_or_http()
			.enable_http1()
			.build();

		let inner = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector);

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
			req: hyper::Request<Vec<u8>>,
			uri: http::Uri,
			auth_header: Option<http::HeaderValue>,
		) -> anyhow::Result<Response> {
			let mut req = req.map(|body| http_body_util::Full::new(body.into()));

			*req.uri_mut() = uri;

			if let Some(auth_header) = auth_header {
				req.headers_mut().append(http::header::AUTHORIZATION, auth_header);
			}

			req.headers_mut().insert(http::header::ACCEPT, APPLICATION_JSON);
			req.headers_mut().insert(http::header::USER_AGENT, client.user_agent.clone());

			let res = client.inner.request(req).await.context("could not execute request")?;

			let (http::response::Parts { status, mut headers, .. }, body) = res.into_parts();

			Ok(if status.is_redirection() {
				let location =
					headers.remove(http::header::LOCATION)
					.with_context(|| format!("could not execute request: received {status} but no location header"))?;
				let location = location.as_bytes();
				let location =
					location.try_into()
					.context("could not execute request: received redirect resposne with malformed location header")?;
				Response::Redirect(location)
			}
			else {
				let content_type = headers.remove(http::header::CONTENT_TYPE);
				let content_type = content_type.as_ref();
				#[allow(clippy::borrow_interior_mutable_const)]
				if content_type != Some(&APPLICATION_JSON) && content_type != Some(&APPLICATION_JSON_CHARSET_UTF8) {
					return Err(anyhow::anyhow!("could not execute request: unexpected content-type {content_type:?}"));
				}
				let body = http_body_util::BodyExt::collect(body).await.context("could not execute request: could not read response body")?.aggregate();
				let body = hyper::body::Buf::reader(body);
				let body: serde_json::Value = serde_json::from_reader(body).context("could not execute request")?;
				Response::Json(body)
			})
		}

		let mut uri = format!("{base}{path}").try_into().context("could not request")?;

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
					let mut req = http::Request::new(body);
					*req.method_mut() = http::Method::POST;
					req.headers_mut().append(http::header::CONTENT_TYPE, APPLICATION_JSON);
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

#[allow(clippy::declare_interior_mutable_const)]
const APPLICATION_JSON: http::HeaderValue = http::HeaderValue::from_static("application/json");

#[allow(clippy::declare_interior_mutable_const)]
const APPLICATION_JSON_CHARSET_UTF8: http::HeaderValue = http::HeaderValue::from_static("application/json; charset=utf-8");
