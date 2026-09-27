//! Host image references accepted for a Host update.

/// One registry reference. It becomes a `bootc switch` argument, so it must
/// not read as an option or carry more than one word.
pub fn valid_reference(image: &str) -> bool {
    !image.is_empty()
        && image.len() <= 512
        && !image.starts_with('-')
        && !image.chars().any(|c| c.is_whitespace() || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_registry_reference_that_is_not_an_option() {
        assert!(valid_reference("10.0.2.2:5000/fwos:next"));
        assert!(valid_reference("quay.io/coldboot-labs/fwos@sha256:abc"));
        assert!(!valid_reference(""));
        assert!(!valid_reference("--apply"));
        assert!(!valid_reference("quay.io/fwos:next --apply"));
        assert!(!valid_reference(&"a".repeat(513)));
    }
}
