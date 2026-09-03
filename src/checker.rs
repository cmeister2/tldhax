//! ASCII DNS syntax validation helpers.

/// Validates a lowercased ASCII domain name for basic DNS syntax.
///
/// # Errors
///
/// Returns an error string when the domain is empty, too long, or contains an
/// invalid label.
pub fn validate_ascii_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() {
        return Err("DNS syntax: empty domain".to_string());
    }

    if domain.len() > 253 {
        return Err("DNS syntax: domain exceeds 253 characters".to_string());
    }

    for label in domain.split('.') {
        validate_ascii_label(label)?;
    }

    Ok(())
}

/// Validates a single lowercased ASCII DNS label.
///
/// # Errors
///
/// Returns an error string when the label is empty, too long, starts or ends
/// with a hyphen, or contains characters outside `[a-z0-9-]`.
pub fn validate_ascii_label(label: &str) -> Result<(), String> {
    if label.is_empty() {
        return Err("DNS syntax: empty label".to_string());
    }

    if label.len() > 63 {
        return Err("DNS syntax: label exceeds 63 characters".to_string());
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err("DNS syntax: label cannot start or end with a hyphen".to_string());
    }

    if label.as_bytes().get(2..4) == Some(b"--") && !label.starts_with("xn--") {
        return Err(
            "IDNA syntax: hyphens in positions three and four require an A-label".to_string(),
        );
    }

    if !label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("DNS syntax: label contains invalid characters".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_ascii_domain, validate_ascii_label};

    #[test]
    fn accepts_valid_ascii_domain() {
        assert!(validate_ascii_domain("foo.co.uk").is_ok());
    }

    #[test]
    fn rejects_invalid_label_character() {
        let error = validate_ascii_label("foo_bar").unwrap_err();
        assert!(error.contains("invalid characters"));
    }

    #[test]
    fn rejects_reserved_r_ldh_labels() {
        let error = validate_ascii_label("ab--cd").unwrap_err();
        assert!(error.contains("positions three and four"));
    }
}
