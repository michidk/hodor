use axum::body::Body;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Bytes;

pub(crate) const MAX_LOGIN_BODY_SIZE: usize = 16 * 1024;

pub(crate) fn parse_form_body(body: &Bytes) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode_form_component(key), decode_form_component(value))
        })
        .collect()
}

pub(crate) fn form_value<'a>(form: &'a [(String, String)], key: &str) -> Option<&'a str> {
    form.iter()
        .find_map(|(form_key, form_value)| (form_key == key).then_some(form_value.as_str()))
}

pub(crate) fn decode_form_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    decoded.push(byte);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

pub(crate) fn sanitize_redirect(redirect: &str) -> String {
    if redirect.starts_with('/') && !redirect.starts_with("//") {
        redirect.to_string()
    } else {
        "/".to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyError {
    TooLarge,
    Invalid,
}

impl IntoResponse for BodyError {
    fn into_response(self) -> Response<Body> {
        match self {
            Self::TooLarge => {
                (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response()
            }
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid request body").into_response(),
        }
    }
}

pub(crate) async fn collect_body(body: Body) -> Result<Bytes, BodyError> {
    match Limited::new(body, MAX_LOGIN_BODY_SIZE).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
            Err(BodyError::TooLarge)
        }
        Err(_) => Err(BodyError::Invalid),
    }
}
