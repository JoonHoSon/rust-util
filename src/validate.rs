//! 유효성 검사 관련 함수 모음

use regex::bytes::Regex;

const EMAIL_EXPRESSION: &str = r"^[\w-]+(\.[\w-]+)*@([A-Za-z0-9-]+\.)+[A-Za-z]{2,4}$";

/// 이메일 유효성 검사
///
/// # Arguments
///
/// - `email` - 검증 대상 이메일 주소
///
/// # Return
///
/// - 유효성 검사 결과
///
/// # Example
///
/// ```rust
/// use cliff3_util::validate::validate_email;
///
/// let email = "email@email.com";
///
/// assert!(validate_email(email));
///
/// let email = "email";
///
/// assert!(!validate_email(email));
///
/// let email = "email@";
///
/// assert!(!validate_email(email));
///
/// let email = "email!#$@email.com";
///
/// assert!(!validate_email(email));
///
/// let email = "@email.com";
///
/// assert!(!validate_email(email));
///
/// let email = "@email@.com";
///
/// assert!(!validate_email(email));
/// ```
pub fn validate_email(email: &str) -> bool {
    Regex::new(EMAIL_EXPRESSION)
        .unwrap()
        .is_match(email.as_bytes())
}

#[cfg(test)]
mod tests {
    use crate::validate::validate_email;

    #[test]
    fn test_validate_email() {
        assert!(validate_email("email@email.com"));
        assert!(!validate_email("email"));
        assert!(!validate_email("email@"));
        assert!(!validate_email("email!#$@email.com"));
        assert!(!validate_email("@email.com"));
        assert!(!validate_email("@email@"));
    }
}
