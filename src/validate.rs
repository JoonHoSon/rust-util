//! 유효성 검사 관련 함수 모음

use regex::bytes::Regex;

/// 다음 항목 참고
/// - https://stackoverflow.com/a/201378
/// - https://stackoverflow.com/a/2049510
const EMAIL_EXPRESSION: &str = r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#;

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
/// assert!(validate_email(email));
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
        assert!(validate_email("email!#($@email.com"));
        assert!(!validate_email("@email.com"));
        assert!(!validate_email("@email@"));
    }

    #[test]
    fn validate_email_test() {
        let mut email = "joonho.son@me.com";

        assert!(validate_email(email), "정상적인 이메일 유효성 검사 실패");

        email = "test@test";

        assert!(!validate_email(email));

        email = "test@test.";

        assert!(!validate_email(email));

        email = "";

        assert!(!validate_email(email));
    }

    #[test]
    fn korean_domain_fail_test() {
        let mut email = "한글ID@test.com";

        assert!(
            !validate_email(email),
            "한글 ID를 포함하는 이메일 검사 실패"
        );

        email = "test@한글도메인.com";

        assert!(
            !validate_email(email),
            "한글 도메인을 포함하는 이메일 검사 실패"
        );

        email = "홍길동@한글도메인.com";

        assert!(
            !validate_email(email),
            "한글 ID 및 한글 도메인을 포함하는 이메일 검사 실패"
        );
    }
}
