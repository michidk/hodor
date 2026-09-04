const WILDCARD_SUFFIX: &str = "/*";
const WILDCARD_ERROR: &str = "may only use '*' as a trailing '/*' segment";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BypassPath {
    Exact(String),
    Prefix(String),
}

impl BypassPath {
    pub(crate) fn parse(pattern: &str) -> Result<Self, String> {
        if !pattern.starts_with('/') {
            return Err(format!("{pattern:?} must start with '/'"));
        }

        let Some(prefix) = pattern.strip_suffix(WILDCARD_SUFFIX) else {
            if pattern.contains('*') {
                return Err(format!("{pattern:?} {WILDCARD_ERROR}"));
            }
            return Ok(Self::Exact(pattern.to_string()));
        };

        if prefix.contains('*') {
            return Err(format!("{pattern:?} {WILDCARD_ERROR}"));
        }
        Ok(Self::Prefix(format!("{prefix}/")))
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(exact) => path == exact,
            Self::Prefix(prefix) => path.starts_with(prefix.as_str()),
        }
    }
}

// Hodor forwards the client's raw path, so a public-path decision taken on a
// rewritten path could disagree with the upstream's own normalisation and expose
// a private route. Non-canonical paths therefore fail closed into the password
// gate instead of being normalised here.
fn is_canonical(path: &str) -> bool {
    !path.contains("//")
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        && !contains_encoded_separator(path)
}

// Rejects the traversal-relevant escapes: %2e (dot), %2f (slash), and %25
// (percent), the last because a double-decoding upstream would see the others.
fn contains_encoded_separator(path: &str) -> bool {
    path.as_bytes().windows(3).any(|window| {
        window[0] == b'%'
            && window[1] == b'2'
            && matches!(window[2], b'e' | b'E' | b'f' | b'F' | b'5')
    })
}

pub(crate) fn is_bypass_path(path: &str, paths: &[BypassPath]) -> bool {
    if paths.is_empty() || !is_canonical(path) {
        return false;
    }
    paths.iter().any(|candidate| candidate.matches(path))
}
