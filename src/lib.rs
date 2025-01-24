//! 암/복호화(RSA, AES), Hash(SHA 256/512), 문자열 유틸리티 함수, I/O 유틸리티 함수 및 날짜 관련 함수 모음입니다.
//!
//! # Feature flags
//!
//! - `string` - 문자열 유틸리티 함수 활성화
//! - `encrypt` - 암복호화 및 Hash 관련 함수 활성화
//! - `io` - I/O 유틸리티 관련 함수 활성화
//! - `date` - 날짜(chrono) 관련 함수 활성화
//! - `validate` - 유효성 검사 관련 함수 활성화
//! - `default` - 위 함수 모두 포함

pub mod error;

// string.rs 파일에 다음과 같이 설정하여도 됨
// #![cfg(any(feature = "default", feature = "string"))]
#[cfg(any(feature = "string", feature = "default"))]
pub mod string;

#[cfg(any(feature = "encrypt", feature = "default"))]
pub mod encrypt;

#[cfg(any(feature = "io", feature = "default"))]
pub mod io;

#[cfg(any(feature = "date", feature = "default"))]
pub mod date;

#[cfg(any(feature = "validate", feature = "default"))]
pub mod validate;
