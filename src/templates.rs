use axum::body::Body;
use axum::http::{Response, StatusCode};
use axum::response::{Html, IntoResponse};
use minijinja::{Environment, context};
use tracing::warn;

use crate::state::AppState;

pub(crate) const BUILTIN_TEMPLATE: &str = include_str!("template.html");
pub(crate) const BUILTIN_ERROR_TEMPLATE: &str = include_str!("error_template.html");
const ERROR_TEMPLATE_NAME: &str = "error.html";
const TEMPLATE_NAME: &str = "login.html";

pub(crate) fn load_template(template_path: Option<&str>) -> String {
    match template_path {
        Some(path) => std::fs::read_to_string(path)
            .expect("failed to read custom template from TEMPLATE path"),
        None => BUILTIN_TEMPLATE.to_string(),
    }
}

pub(crate) fn load_error_template(template_path: Option<&str>) -> String {
    match template_path {
        Some(path) => std::fs::read_to_string(path)
            .expect("failed to read custom error template from ERROR_TEMPLATE path"),
        None => BUILTIN_ERROR_TEMPLATE.to_string(),
    }
}

pub(crate) fn validate_template(
    template_source: &str,
    title: &str,
    custom_css: &str,
    disable_default_css: bool,
) -> Result<(), minijinja::Error> {
    render_login_page(
        template_source,
        title,
        custom_css,
        disable_default_css,
        false,
    )
    .map(|_| ())
}

pub(crate) fn validate_error_template(
    template_source: &str,
    title: &str,
    custom_css: &str,
    disable_default_css: bool,
) -> Result<(), minijinja::Error> {
    render_error_page(
        template_source,
        title,
        custom_css,
        disable_default_css,
        StatusCode::BAD_GATEWAY,
        "Bad Gateway",
        "The upstream service could not be reached.",
    )
    .map(|_| ())
}

pub(crate) fn render_login_page(
    template_source: &str,
    title: &str,
    custom_css: &str,
    disable_default_css: bool,
    show_error: bool,
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template(TEMPLATE_NAME, template_source)?;
    env.get_template(TEMPLATE_NAME)?.render(context!(
        title => title,
        custom_css => custom_css,
        disable_default_css => disable_default_css,
        show_error => show_error,
    ))
}

pub(crate) fn render_error_page(
    template_source: &str,
    title: &str,
    custom_css: &str,
    disable_default_css: bool,
    status: StatusCode,
    heading: &str,
    message: &str,
) -> Result<String, minijinja::Error> {
    let mut env = Environment::new();
    env.add_template(ERROR_TEMPLATE_NAME, template_source)?;
    env.get_template(ERROR_TEMPLATE_NAME)?.render(context!(
        title => title,
        custom_css => custom_css,
        disable_default_css => disable_default_css,
        status_code => status.as_u16(),
        heading => heading,
        message => message,
    ))
}

pub(crate) fn login_page_response(state: &AppState, show_error: bool) -> Response<Body> {
    match render_login_page(
        &state.template_source,
        &state.title,
        &state.custom_css,
        state.disable_default_css,
        show_error,
    ) {
        Ok(page) => (StatusCode::UNAUTHORIZED, Html(page)).into_response(),
        Err(error) => {
            warn!(%error, "failed to render login page");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

pub(crate) fn error_page_response(
    state: &AppState,
    status: StatusCode,
    heading: &str,
    message: &str,
) -> Response<Body> {
    match render_error_page(
        &state.error_template_source,
        &state.title,
        &state.custom_css,
        state.disable_default_css,
        status,
        heading,
        message,
    ) {
        Ok(page) => (status, Html(page)).into_response(),
        Err(error) => {
            warn!(%error, "failed to render error page");
            (status, message.to_string()).into_response()
        }
    }
}

pub(crate) fn internal_server_error(state: &AppState) -> Response<Body> {
    error_page_response(
        state,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal Server Error",
        "Something went wrong while processing this request.",
    )
}

pub(crate) fn bad_gateway(state: &AppState) -> Response<Body> {
    error_page_response(
        state,
        StatusCode::BAD_GATEWAY,
        "Upstream Unavailable",
        "Hodor is running, but the downstream service could not be reached.",
    )
}
