use axum::http::StatusCode;

use crate::templates::{
    BUILTIN_ERROR_TEMPLATE, BUILTIN_TEMPLATE, render_error_page, render_login_page,
    validate_error_template, validate_template,
};

#[test]
fn validate_template_accepts_builtin() {
    assert!(validate_template(BUILTIN_TEMPLATE, "Test", "", false).is_ok());
}

#[test]
fn validate_template_rejects_invalid_syntax() {
    assert!(validate_template("{% invalid %}", "Test", "", false).is_err());
}

#[test]
fn validate_error_template_accepts_builtin() {
    assert!(validate_error_template(BUILTIN_ERROR_TEMPLATE, "Test", "", false).is_ok());
}

#[test]
fn validate_error_template_rejects_invalid_syntax() {
    assert!(validate_error_template("{% invalid %}", "Test", "", false).is_err());
}

#[test]
fn render_login_page_includes_title() {
    let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", "", false, false).unwrap();
    assert!(html.contains("My Gate"));
}

#[test]
fn render_login_page_escapes_title() {
    let html =
        render_login_page(BUILTIN_TEMPLATE, "<script>xss</script>", "", false, false).unwrap();
    assert!(!html.contains("<script>xss</script>"));
}

#[test]
fn render_login_page_includes_custom_css_verbatim() {
    let css = ".card > button { background: \"hotpink\"; }";
    let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", css, false, false).unwrap();
    assert!(html.contains(css));
}

#[test]
fn render_login_page_omits_custom_css_block_when_unset() {
    let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", "", false, false).unwrap();
    assert_eq!(html.matches("<style>").count(), 1);
}

#[test]
fn render_login_page_disable_default_css_removes_builtin_styles() {
    let css = "body { background: hotpink; }";
    let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", css, true, false).unwrap();
    assert!(!html.contains("box-sizing"));
    assert!(html.contains(css));
    assert_eq!(html.matches("<style>").count(), 1);
}

#[test]
fn render_login_page_keeps_builtin_styles_by_default() {
    let html = render_login_page(BUILTIN_TEMPLATE, "My Gate", "", false, false).unwrap();
    assert!(html.contains("box-sizing"));
}

#[test]
fn render_error_page_disable_default_css_removes_builtin_styles() {
    let css = "body { background: hotpink; }";
    let html = render_error_page(
        BUILTIN_ERROR_TEMPLATE,
        "My Gate",
        css,
        true,
        StatusCode::BAD_GATEWAY,
        "Bad Gateway",
        "Oops",
    )
    .unwrap();
    assert!(!html.contains("box-sizing"));
    assert!(html.contains(css));
    assert_eq!(html.matches("<style>").count(), 1);
}

#[test]
fn render_error_page_includes_custom_css_verbatim() {
    let css = "body { background: #1e3a5f; }";
    let html = render_error_page(
        BUILTIN_ERROR_TEMPLATE,
        "My Gate",
        css,
        false,
        StatusCode::BAD_GATEWAY,
        "Bad Gateway",
        "Oops",
    )
    .unwrap();
    assert!(html.contains(css));
}

#[test]
fn render_error_page_omits_custom_css_block_when_unset() {
    let html = render_error_page(
        BUILTIN_ERROR_TEMPLATE,
        "My Gate",
        "",
        false,
        StatusCode::BAD_GATEWAY,
        "Bad Gateway",
        "Oops",
    )
    .unwrap();
    assert_eq!(html.matches("<style>").count(), 1);
}

#[test]
fn render_error_page_includes_fields() {
    let html = render_error_page(
        BUILTIN_ERROR_TEMPLATE,
        "My Gate",
        "",
        false,
        StatusCode::BAD_GATEWAY,
        "Upstream Unavailable",
        "The downstream service could not be reached.",
    )
    .unwrap();
    assert!(html.contains("My Gate"));
    assert!(html.contains("502"));
    assert!(html.contains("Upstream Unavailable"));
    assert!(html.contains("The downstream service could not be reached."));
}

#[test]
fn render_error_page_escapes_title() {
    let html = render_error_page(
        BUILTIN_ERROR_TEMPLATE,
        "<script>xss</script>",
        "",
        false,
        StatusCode::BAD_GATEWAY,
        "Bad Gateway",
        "Oops",
    )
    .unwrap();
    assert!(!html.contains("<script>xss</script>"));
}
