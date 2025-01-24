//! SHA(256, 512), AES 및 RSA 암호화 관련 함수 모음
//!
//! 사용한 crate 목록은 다음과 같다.
//! * [sha256](https://crates.io/crates/sha256)
//! * [rsa](https://crates.io/crates/rsa)

use std::fmt::{Display, Formatter};

use openssl::error::ErrorStack;
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{decrypt, encrypt, Cipher};
use sha2::{Digest, Sha256 as sha2_256, Sha512 as sha2_512};

use crate::error::{InvalidArgumentError, LibError, MissingArgumentError};

// 반복 횟수 기본값
// const DEFAULT_REPEAT: u16 = 1_000;

// /// TODO(joonho): 2024-02-14 주석 추가
// #[allow(non_camel_case_types)]
// pub enum Transformation {
//     /// RSA/ECB/PKCS1Padding
//     RSA_ECB_PKCS1PADDING,
//
//     // AES/CBC/PKCS5Padding
//     AES_CBC_PKCS5PADDING,
//
//     /// [Transformation::RSA_ECB_PKCS1PADDING]와 동일
//     RSA,
// }
//
// impl Transformation {
//     /// [Transformation] 항목을 문자열 형태로 반환
//     pub fn get_transformation(&self) -> &'static str {
//         match self {
//             Transformation::RSA_ECB_PKCS1PADDING => "RSA/ECB/PKCS1Padding",
//             Transformation::AES_CBC_PKCS5PADDING => "AES/CBC/PKCS5Padding",
//             _ => "RSA/ECB/PKCS1Padding",
//         }
//     }
// }

// CryptoError -------------------------------------------------------------------------------------
/// 암호화 처리 중 발생하는 오류
#[derive(PartialEq, Debug)]
pub struct CryptoError {
    message: String,
}

impl Default for CryptoError {
    fn default() -> Self {
        CryptoError {
            message: "암호화 처리중 오류가 발생하였습니다.".to_owned(),
        }
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Encrypt/Decrypt error.")
    }
}

impl From<&str> for CryptoError {
    fn from(value: &str) -> Self {
        CryptoError {
            message: value.to_owned(),
        }
    }
}

impl LibError for CryptoError {
    fn get_message(&self) -> &str {
        self.message.as_str()
    }

    fn get_type_name_from_instance(&self) -> &str {
        std::any::type_name::<CryptoError>()
    }
}

// Define enum -------------------------------------------------------------------------------------
/// SHA 256/512
#[derive(PartialEq)]
#[allow(non_camel_case_types)]
pub enum SHA_TYPE {
    /// SHA-256
    SHA_256,

    /// SHA-512
    SHA_512,
}

/// AES 128/256
#[derive(PartialEq)]
#[allow(non_camel_case_types)]
pub enum AES_TYPE {
    /// AES-128
    AES_128,

    /// AES-256
    AES_256,
}

/// 대상 문자열을 `SHA` 알고리즘을 이용하여 hash 처리 후 반환
///
/// 두 번째 인자 `salt`가 존재할 경우 이를 반영하여 처리함.
///
/// # Arguments
///
/// - `hash_type` - [SHA_TYPE]
/// - `target` - Hash 대상
/// - `salt` - Salt
///
/// # Return
///
/// - 생성 결과 `Result<Box<u8>, MissingArgumentError>`
///
/// # Errors
///
/// - [MissingArgumentError] - Hash 대상 문자열 미지정
///
/// # Link
///
/// - [SHA_TYPE]
/// - [MissingArgumentError]
///
/// # Example
///
/// ```rust
/// use cliff3_util::encrypt::{make_sha_hash, SHA_TYPE};
///
/// let mut result = make_sha_hash(SHA_TYPE::SHA_256, "test".as_bytes(), Some("salt"));
///
/// assert!(!result.is_err());
///
/// let mut v: Vec<String> = result.unwrap().iter().map(|b| format!("{:02x}", b)).collect();
///
/// assert_eq!(v.join(""), "4edf07edc95b2fdcbcaf2378fd12d8ac212c2aa6e326c59c3e629be3039d6432");
///
/// result = make_sha_hash(SHA_TYPE::SHA_512, "test".as_bytes(), Some("salt"));
///
/// assert!(!result.is_err());
///
/// v = result.unwrap().iter().map(|b| format!("{:02x}", b)).collect();
///
/// assert_eq!(v.join(""), "6c838e934e3feefae6cfa53af11375d4954f85c6f5ed888c02cd7806a71696d1cb449f2be78e9e6ea301a95c81f28ad8766f3ae582f9beaac33c7dc2b7ba9187")
/// ```
pub fn make_sha_hash(
    hash_type: SHA_TYPE,
    target: &[u8],
    salt: Option<&str>,
) -> Result<Box<[u8]>, MissingArgumentError> {
    if target.is_empty() {
        return Err(MissingArgumentError::from("Hash 대상이 빈 문자열 입니다."));
    }

    return match hash_type {
        SHA_TYPE::SHA_256 => _hash_::<sha2_256>(target, salt),
        SHA_TYPE::SHA_512 => _hash_::<sha2_512>(target, salt),
    };

    fn _hash_<D: Digest>(
        target: &[u8],
        salt: Option<&str>,
    ) -> Result<Box<[u8]>, MissingArgumentError> {
        let mut _hash = D::new();

        _hash.update(target);

        if !salt.is_none() && !salt.unwrap().is_empty() {
            _hash.update(salt.unwrap().as_bytes());
        }

        let result: Vec<u8> = _hash.finalize().to_vec();

        return Ok(Box::from(result.as_slice()));
    }
}

/// 대상 문자열을 `SHA` 알고리즘을 이용하여 hash 처리 후 문자열 형태로 반환
///
/// 두 번째 인자 `salt`가 존재할 경우 이를 반영하여 처리함.
///
/// # Arguments
///
/// - `hash_type` - [SHA_TYPE]
/// - `target`- Hash 대상
/// - `salt`- Salt
///
/// # Return
///
/// - 생성 결과 `Result<Box<u8>, MissingArgumentError>`
///
/// # Errors
///
/// - [MissingArgumentError] - Hash 대상 문자열 미지정
///
/// # Link
///
/// - [SHA_TYPE]
/// - [MissingArgumentError]
///
/// # Example
///
/// ```rust
/// use cliff3_util::encrypt::{make_sha_hash_string, SHA_TYPE};
///
/// let result = make_sha_hash_string(SHA_TYPE::SHA_256, "test".as_bytes(), Some("salt"));
///
/// assert!(result.is_ok());
///
/// assert_eq!("4edf07edc95b2fdcbcaf2378fd12d8ac212c2aa6e326c59c3e629be3039d6432", result.unwrap());
/// ```
pub fn make_sha_hash_string(
    hash_type: SHA_TYPE,
    target: &[u8],
    salt: Option<&str>,
) -> Result<String, MissingArgumentError> {
    let result = make_sha_hash(hash_type, target, salt);

    match result {
        Ok(r) => {
            let v: Vec<String> = r.iter().map(|b| format!("{:02x}", b)).collect();

            Ok(v.join(""))
        }
        Err(e) => Err(e),
    }
}

/// AES 암호화 결과
#[derive(Debug)]
pub struct AESResult {
    /// Salt
    salt: Option<Vec<u8>>,

    /// 암호화 결과
    result: Vec<u8>,

    /// 암호화 결과(16진수 문자열)
    result_str: Option<String>,

    /// 생성된 Initialize vector
    iv: Vec<u8>,
}

impl AESResult {
    fn new(salt: Option<&[u8]>, result: &[u8], iv: &[u8]) -> Self {
        AESResult {
            salt: match salt {
                None => None,
                Some(v) => Some(Vec::from(v)),
            },
            result: Vec::from(result),
            result_str: {
                let v = Vec::from(result);
                let v: Vec<String> = v.iter().map(|b| format!("{:02x}", b)).collect();

                Some(v.join(""))
            },
            iv: Vec::from(iv),
        }
    }

    /// `salt` 반환
    #[inline]
    pub fn salt(&self) -> Option<&[u8]> {
        return match &self.salt {
            None => None,
            Some(v) => {
                return Some(v.as_ref());
            }
        };
    }

    /// 암호화 결과 반환
    #[inline]
    pub fn result(&self) -> &[u8] {
        self.result.as_ref()
    }

    /// 암호화 결과(16진수 문자열) 반환
    #[inline]
    pub fn result_str(&self) -> Option<&str> {
        match &self.result_str {
            None => None,
            Some(v) => Some(v.as_str()),
        }
    }

    /// `iv` 반환
    #[inline]
    pub fn iv(&self) -> &[u8] {
        self.iv.as_ref()
    }

    // ---------------------------------------------------------------------------------------------
    // deprecated
    // ---------------------------------------------------------------------------------------------

    /// `salt` 반환
    #[deprecated(note = "salt(&self)로 대체. 삭제 예정.")]
    pub fn get_salt(&self) -> Option<&[u8]> {
        return match &self.salt {
            None => None,
            Some(v) => {
                return Some(v.as_ref());
            }
        };
    }

    /// 암호화 결과 반환
    #[deprecated(note = "result(&self)로 대체. 삭제 예정.")]
    pub fn get_result(&self) -> &[u8] {
        return self.result.as_ref();
    }

    /// `iv` 반환
    #[deprecated(note = "iv(&self)로 대체. 삭제 예정.")]
    pub fn get_iv(&self) -> &[u8] {
        return self.iv.as_ref();
    }
}

impl Display for AESResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "salt : {:#?}\n, result : {:#?}\n, iv : {:#?}",
            self.salt, self.result, self.iv
        )
    }
}

/// 인자로 전달된 `salt` 유효성 검사. 만약 `salt`가 전달 되었을 경우 **8 bytes** 여부를 확인
///
/// # Arguments
///
/// - `salt` - Salt
///
/// # Return
///
/// - 유효성 검사 결과
///
/// # Errors
///
/// - [InvalidArgumentError] - **8 bytes** 조건 불일치
pub fn validate_salt(salt: Option<&[u8]>) -> Result<(), InvalidArgumentError> {
    return match salt {
        None => Ok(()),
        Some(v) => {
            return if v.len() != 8 {
                Err(InvalidArgumentError::from(
                    "Salt length is invalid(must 8 bytes)",
                ))
            } else {
                Ok(())
            };
        }
    };
}

/// [AES_TYPE]을 이용한 `AES 128/256` 암호화
///
/// 정상적으로 처리된 경우 [AESResult]를 반환한다. `salt`는 **8 bytes**여야 한다.
///
/// ### `salt` 관련 참고 사항
/// - [openssl::pkcs5::bytes_to_key] => `pub const PKCS5_SALT_LEN: c_int = 8;`
/// - [Git hub comment][github_comment]
/// - [openssl-enc options][openssl_enc_options]
///
/// # Arguments
///
/// - `enc_type` - [AES_TYPE]
/// - `target` - 암호화 대상
/// - `secret` - Secret key
/// - `salt` - salt (8 bytes) ([validate_salt] 참고)
/// - `repeat_count` - 반복 횟수
///
/// # Return
///
/// - 암호화 결과 `Result<AESResult, Box<dyn LibError>>`
///
/// # Errors
///
/// - [MissingArgumentError] - 암호화 대상 문자열 미지정
/// - [InvalidArgumentError] - `salt`의 길이가 `8 bytes`가 아닐 경우 혹은 암호화 대상 문자열이 빈 문자열일 경우
/// - [CryptoError] - [openssl::pkcs5::KeyIvPair] 생성 실패
///
/// # Link
///
/// - [AES_TYPE]
/// - [AESResult]
///
/// # Example
///
/// [github_comment]: https://github.com/openssl/openssl/issues/19026#issuecomment-1251538241
/// [openssl_enc_options]: https://www.openssl.org/docs/manmaster/man1/openssl-enc.html
///
/// ```rust
/// use cliff3_util::encrypt::{aes_encrypt, AES_TYPE, AESResult};
///
/// let plain_text = "This 이것 that 저것";
/// let secret = "this is secret key";
/// let salt = "12ag3$s!"; // 8 bytes
/// let result = aes_encrypt(AES_TYPE::AES_128, plain_text.as_bytes(), secret.as_bytes(), Some(salt.as_bytes()), 10);
///
/// assert!(!result.is_err());
///
/// let unwrapped: AESResult = result.unwrap();
///
/// assert!(unwrapped.result().len() > 0);
/// ```
pub fn aes_encrypt(
    enc_type: AES_TYPE,
    target: &[u8],
    secret: &[u8],
    salt: Option<&[u8]>,
    repeat_count: usize,
) -> Result<AESResult, Box<dyn LibError>> {
    if target.is_empty() {
        return Err(Box::from(InvalidArgumentError::from(
            "암호화 대상이 빈 문자열 입니다",
        )));
    }

    let validate_salt = validate_salt(salt);

    if validate_salt.is_err() {
        return Err(Box::from(validate_salt.err().unwrap()));
    }

    let cipher = if AES_TYPE::AES_128 == enc_type {
        Cipher::aes_128_cbc()
    } else {
        Cipher::aes_256_cbc()
    };
    let key_spec = openssl::pkcs5::bytes_to_key(
        cipher,
        openssl::hash::MessageDigest::md5(),
        secret,
        salt,
        repeat_count as i32,
    );

    if key_spec.is_err() {
        eprintln!("AES error : {:#?}", key_spec.err());

        return Err(Box::from(CryptoError::from(
            "AES 암호화 처리 중 오류가 발생하였습니다.",
        )));
    }

    let unwrapped_spec = key_spec.unwrap();
    let key = unwrapped_spec.key;
    let iv = unwrapped_spec.iv.unwrap();

    // let mut iv: [u8; 16] = [0u8; 16];
    //
    // rand::thread_rng().fill_bytes(&mut iv);

    let result: Result<Vec<u8>, ErrorStack> =
        encrypt(cipher, key.as_slice(), Some(iv.as_slice()), target);

    match result {
        Ok(vv) => Ok(AESResult::new(salt, vv.as_slice(), iv.as_slice())),
        Err(e) => {
            eprintln!("AES encrypt error : {:#?}", e);

            Err(Box::from(InvalidArgumentError::from("암호화 처리 오류")))
        }
    }
}

/// [AES_TYPE]을 이용한 암호화(`AES 128/256`) 결과를 복호화 처리
///
/// 정상적으로 처리된 경우 `Box<u8>`을 반환한다.
///
/// # Arguments
///
/// - `enc_type` - [AES_TYPE]
/// - `target` - [aes_encrypt]를 이용한 암호화 결과
/// - `secret` - Secret key
/// - `iv` - Initialize vector
/// - `salt` - [aes_encrypt]시 사용한 `salt` ([validate_salt] 참고)
/// - `repeat_count` - [aes_encrypt]시 지정한 반복 횟수
///
/// # Return
///
/// - 복호화 결과 `Result<Box<u8>, Box<dyn LibError>>`
///
/// # Errors
///
/// - [MissingArgumentError] - 복호화 대상 미지정
/// - [InvalidArgumentError] - `salt`의 길이가 `8 bytes`가 아닐 경우 혹은 복호화 대상의 길이가 `0`일 경우
/// - [CryptoError] - [openssl::pkcs5::KeyIvPair] 생성 실패
///
/// # Example
///
/// ```rust
/// use cliff3_util::encrypt::{aes_decrypt, aes_encrypt, AES_TYPE, AESResult};
/// use cliff3_util::encrypt::AES_TYPE::AES_128;
///
/// let plain_text = "abcd한글";
/// let salt = "4s8sdf*!"; // 8 bytes
/// let secret = "LSDIy8&%^&Dfshfbsjf";
/// let result = aes_encrypt(AES_128, plain_text.as_bytes(), secret.as_bytes(), Some(salt.as_bytes()), 10);
///
/// assert!(!result.is_err());
///
/// let unwrapped: AESResult = result.unwrap();
///
/// println!("unwrapped: {:#?}", unwrapped);
///
/// let decrypted_result = aes_decrypt(AES_128, Some(unwrapped.result()), secret.as_bytes(), unwrapped.iv(), Some(salt.as_bytes()), 10);
///
/// assert!(!decrypted_result.is_err());
///
/// let decrypted_raw = decrypted_result.unwrap();
///
/// assert_eq!(plain_text, String::from_utf8_lossy(decrypted_raw.as_ref()));
/// ```
pub fn aes_decrypt(
    enc_type: AES_TYPE,
    target: Option<&[u8]>,
    secret: &[u8],
    iv: &[u8],
    salt: Option<&[u8]>,
    repeat_count: usize,
) -> Result<Box<[u8]>, Box<dyn LibError>> {
    match target {
        None => Err(Box::from(MissingArgumentError::from(
            "복호화 대상이 지정되지 않았습니다.",
        ))),
        Some(v) => {
            if v.len() == 0 {
                return Err(Box::from(InvalidArgumentError::from(
                    "복호화 대상의 길이가 0 입니다.",
                )));
            }

            let validate_salt = validate_salt(salt);

            if validate_salt.is_err() {
                return Err(Box::from(validate_salt.err().unwrap()));
            }

            let cipher = if AES_TYPE::AES_128 == enc_type {
                Cipher::aes_128_cbc()
            } else {
                Cipher::aes_256_cbc()
            };
            let key_spec = openssl::pkcs5::bytes_to_key(
                cipher,
                openssl::hash::MessageDigest::md5(),
                secret,
                salt,
                repeat_count as i32,
            );

            if key_spec.is_err() {
                eprintln!("AES error: {:#?}", key_spec.err());

                return Err(Box::from(CryptoError::from(
                    "AES 복호화 처리 중 오류가 발생하였습니다.",
                )));
            }

            let unwrapped_spec = key_spec.unwrap();
            let key = unwrapped_spec.key;

            let result = decrypt(cipher, key.as_slice(), Some(iv), v);

            match result {
                Ok(vv) => Ok(Box::from(vv.as_slice())),

                Err(e) => {
                    eprintln!("AES decrypt error: {:#?}", e);

                    Err(Box::from(InvalidArgumentError::from("복호화 처리 오류")))
                }
            }
        }
    }
}

// RSA ---------------------------------------------------------------------------------------------
// #[allow(non_camel_case_types)]
// enum LoadKeyType {
//     /// 공개키
//     PUBLIC_KEY,
//
//     /// 개인키
//     PRIVATE_KEY,
// }

/// RSA 암호화 bit 지정
#[allow(non_camel_case_types)]
pub enum RSA_BIT {
    /// 1024 bit, 암호화 결과는 128 bytes
    B_1024,

    /// 2048 bit, 암호화 결과는 256 bytes
    B_2048,

    /// 4096 bit, 암호화 결과는 512 bytes
    B_4096,

    /// 8192 bit, 암호화 결과는 1024 bytes
    B_8192,
}

impl RSA_BIT {
    /// 해당 값을 `usize` 형태로 반환
    pub fn bit(&self) -> usize {
        match self {
            RSA_BIT::B_1024 => 1024usize,
            RSA_BIT::B_2048 => 2048usize,
            RSA_BIT::B_4096 => 4096usize,
            RSA_BIT::B_8192 => 8192usize,
        }
    }

    pub fn bytes(&self) -> u16 {
        match self {
            RSA_BIT::B_1024 => 128,
            RSA_BIT::B_2048 => 256,
            RSA_BIT::B_4096 => 512,
            RSA_BIT::B_8192 => 1024,
        }
    }
}

/// RSA 암호화 결과
pub struct RSAResult {
    /// 공개키
    public_key: Vec<u8>,

    /// 공개키 계수(modulus)
    public_modulus: Vec<u8>,

    /// 공개키 지수(exponent)
    public_exponent: Vec<u8>,

    /// 개인키
    private_key: Vec<u8>,

    /// 개인키 계수(modulus)
    private_modulus: Vec<u8>,

    /// 개인키 지수(exponent)
    private_exponent: Vec<u8>,

    /// 암호화 결과
    result: Vec<u8>,

    /// 암호화 결과(16진수 문자열)
    result_str: Option<String>,
}

impl RSAResult {
    pub fn new(
        pub_key: &[u8],
        pub_mod: &[u8],
        pub_exp: &[u8],
        prv_key: &[u8],
        prv_mod: &[u8],
        prv_exp: &[u8],
        result: &[u8],
    ) -> Self {
        RSAResult {
            public_key: Vec::from(pub_key),
            public_modulus: Vec::from(pub_mod),
            public_exponent: Vec::from(pub_exp),
            private_key: Vec::from(prv_key),
            private_modulus: Vec::from(prv_mod),
            private_exponent: Vec::from(prv_exp),
            result: Vec::from(result),
            result_str: {
                let v = Vec::from(result);
                let v: Vec<String> = v.iter().map(|b| format!("{:02x}", b)).collect();

                Some(v.join(""))
            },
        }
    }

    /// 공개키 반환
    #[inline]
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    /// 공개키 계수(modulus) 반환
    #[inline]
    pub fn public_modulus(&self) -> &[u8] {
        self.public_modulus.as_ref()
    }

    /// 공개키 지수(exponent) 반환
    #[inline]
    pub fn public_exponent(&self) -> &[u8] {
        self.public_exponent.as_ref()
    }
    /// 개인키 반환
    #[inline]
    pub fn private_key(&self) -> &[u8] {
        self.private_key.as_ref()
    }

    /// 개인키 계수(modulus) 반환
    #[inline]
    pub fn private_modulus(&self) -> &[u8] {
        self.private_modulus.as_ref()
    }

    /// 개인키 지수(exponent) 반환
    #[inline]
    pub fn private_exponent(&self) -> &[u8] {
        self.private_exponent.as_ref()
    }

    /// 암호화 결과 반환
    #[inline]
    pub fn result(&self) -> &[u8] {
        self.result.as_ref()
    }

    /// 암호화 결과(16진수 문자열) 반환
    #[inline]
    pub fn result_str(&self) -> Option<&str> {
        match &self.result_str {
            None => None,
            Some(v) => Some(v.as_str()),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // deprecated
    // ---------------------------------------------------------------------------------------------

    /// 공개키 반환
    #[deprecated(note = "public_key(&self)로 대체. 삭제 예정.")]
    pub fn get_public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    /// 공개키 계수(modulus) 반환
    #[deprecated(note = "public_modulus(&self)로 대체. 삭제 예정.")]
    pub fn get_public_modulus(&self) -> &[u8] {
        self.public_modulus.as_ref()
    }

    /// 공개키 지수(exponent) 반환
    #[deprecated(note = "public_exponent(&self)로 대체. 삭제 예정.")]
    pub fn get_public_exponent(&self) -> &[u8] {
        self.public_exponent.as_ref()
    }

    /// 개인키 반환
    #[deprecated(note = "private_key(&self)로 대체. 삭제 예정.")]
    pub fn get_private_key(&self) -> &[u8] {
        self.private_key.as_ref()
    }

    /// 개인키 계수(modulus) 반환
    #[deprecated(note = "private_modulus(&self)로 대체. 삭제 예정.")]
    pub fn get_private_modulus(&self) -> &[u8] {
        self.private_modulus.as_ref()
    }

    /// 개인키 지수(exponent) 반환
    #[deprecated(note = "private_exponent(&self)로 대체. 삭제 예정.")]
    pub fn get_private_exponent(&self) -> &[u8] {
        self.private_exponent.as_ref()
    }

    /// 암호화 결과 반환
    #[deprecated(note = "result(&self)로 대체. 삭제 예정.")]
    pub fn get_result(&self) -> &[u8] {
        self.result.as_ref()
    }
}

/// 지정된 [RSA_BIT] 기준으로 RSA keypair를 생성하여 반환
///
/// # Arguments
///
/// - `bit_size` - [RSA_BIT]
///
/// # Return
///
/// - 생성된 keypair 결과 `Result<Rsa<Private>, CryptoError>`
///
/// # Errors
///
/// - [CryptoError] - Keypair 생성 오류
///
/// # Link
///
/// - [Rsa]
/// - [Private]
/// - [CryptoError]
pub fn generate_rsa_keypair(bit_size: RSA_BIT) -> Result<Rsa<Private>, CryptoError> {
    let rsa: Result<Rsa<Private>, ErrorStack> = Rsa::generate(bit_size.bit() as u32);

    if rsa.is_err() {
        eprintln!("Generate RSA key pair fail : {:#?}", rsa.err());

        return Err(CryptoError::from(
            "RSA key pair 생성 중 오류가 발생하였습니다.",
        ));
    }

    return Ok(rsa.unwrap());
}

/// [RSA_BIT]를 이용한 RSA 암호화 처리
///
/// 자동으로 [`Rsa<Private>`]를 생성하여 암호화 처리를 한 후 [RSAResult]에 생성된 키 정보와 암호화
/// 결과를 포함하여 반환한다.
///
/// # Arguments
///
/// - `target` - 암호화 대상
/// - `bit_size` - [RSA_BIT]
///
/// # Return
///
/// - RSA 암호화 결과 `Result<Box<RSAResult>, CryptoError>`
///
/// # Errors
///
/// ## [CryptoError]
///
/// - [generate_rsa_keypair] 호출에서 발생
///     - `Rsa<Private>.public_key_to_pem` 호출에서 발생
///     - `Rsa<Private>.private_key_to_pem` 호출에서 발생
///     - [rsa_encrypt] 호출에서 발생
///
/// # Link
///
/// - [RSA_BIT]
/// - [RSAResult]
/// - [CryptoError]
///
/// # Example
///
/// ```rust
/// use cliff3_util::encrypt::{RSA_BIT, rsa_encrypt_without_key};
///
/// const PLAIN_TEXT: &str = "이것은 테스트 입니다.";
/// let result =rsa_encrypt_without_key(PLAIN_TEXT.as_bytes(), RSA_BIT::B_4096);
///
/// assert!(!result.is_err());
///
/// let raw = result.unwrap();
///
/// assert!(raw.private_key().len() > 0, "개인키 반환 실패");
/// assert!(raw.private_exponent().len() > 0, "개인키 지수 반환 실패");
/// assert!(raw.private_modulus().len() > 0, "개인키 계수 반환 실패");
/// assert!(raw.public_key().len() > 0, "공개키 반환 실패");
/// assert!(raw.public_exponent().len() > 0, "공개키 지수 반환 실패");
/// assert!(raw.public_modulus().len() > 0, "공개키 계수 반환 실패");
/// assert_eq!(raw.result().len(), RSA_BIT::B_4096.bytes() as usize, "암호화 결과 길이 불일치");
/// ```
pub fn rsa_encrypt_without_key(
    target: &[u8],
    bit_size: RSA_BIT,
) -> Result<Box<RSAResult>, CryptoError> {
    let key_pair: Rsa<Private> = generate_rsa_keypair(bit_size)?;
    let public_key = key_pair.public_key_to_pem();
    let private_key = key_pair.private_key_to_pem();

    if public_key.is_err() {
        eprintln!("public key error: {:#?}", public_key.err());

        return Err(CryptoError::from("Public key에서 오류가 발생하였습니다."));
    }

    if private_key.is_err() {
        eprintln!("private key error: {:#?}", private_key.err());

        return Err(CryptoError::from("Private key에서 오류가 발생하였습니다."));
    }

    let unwrapped_pub_key = public_key.unwrap();
    let unwrapped_prv_key = private_key.unwrap();

    let result = rsa_encrypt(target, unwrapped_pub_key.as_slice())?;

    let rsa_result = RSAResult::new(
        unwrapped_pub_key.as_slice(),
        key_pair.n().to_vec().as_slice(),
        key_pair.e().to_vec().as_slice(),
        unwrapped_prv_key.as_slice(),
        key_pair.n().to_vec().as_slice(),
        key_pair.d().to_vec().as_slice(),
        result.as_ref(),
    );

    return Ok(Box::from(rsa_result));
}

/// RSA 복호화
///
/// # Arguments
///
/// - `target` - 복호화 대상
/// - `prv_key` - 암호화시 생성된 개인키
///
/// # Return
///
/// - RSA 복호화 결과 `Result<Vec<u8>, CryptoError>`
///
/// # Errors
///
/// - [CryptoError] - 암호화 처리 중 오류 발생
///
/// # Example
///
/// ```rust
/// use cliff3_util::encrypt::{RSA_BIT, rsa_decrypt, rsa_encrypt_without_key, RSAResult};
///
/// let plaint_text = "This 이것 that 저것";
/// let result = rsa_encrypt_without_key(plaint_text.as_bytes(), RSA_BIT::B_2048);
///
/// assert!(!result.is_err());
///
/// let unwrapped_encrypt_result = result.unwrap();
///
/// assert_eq!(unwrapped_encrypt_result.result().len(), RSA_BIT::B_2048.bytes() as usize, "암호화 결과 불일치");
///
/// let decrypt_result = rsa_decrypt(unwrapped_encrypt_result.result(), unwrapped_encrypt_result.private_key());
///
/// assert!(!decrypt_result.is_err());
///
/// let unwrapped_decrypt_result = decrypt_result.unwrap();
/// let decrypted_text = String::from_utf8(unwrapped_decrypt_result.to_vec()).unwrap();
///
/// assert_eq!(decrypted_text, plaint_text, "복호화 실패");
/// ```
pub fn rsa_decrypt(target: &[u8], prv_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let private_key = Rsa::private_key_from_pem(prv_key);

    if private_key.is_err() {
        eprintln!("개인키 생성 오류: {:#?}", private_key.err());

        return Err(CryptoError::from("개인키 오류가 발생하였습니다."));
    }

    let rsa = private_key.unwrap();
    let mut buffer: Vec<u8> = vec![0; rsa.size() as usize];

    let result = rsa.private_decrypt(target, &mut buffer, Padding::PKCS1);

    if result.is_err() {
        eprintln!("RSA decrypt error : {:#?}", result.err());

        return Err(CryptoError::from(
            "RSA 복호화 처리 중 오류가 발생하였습니다.",
        ));
    }

    let real_size = result.unwrap();
    let final_result = &buffer[0..real_size];

    return Ok(Vec::from(final_result)); // 실제 복호화된 길이 만큼만 반환
}

/// RSA 암호화 처리
///
/// 암호화 대상 정보(`target`)를 `pub_key`를 이용하여 암호화 처리 한다.
///
/// # Arguments
///
/// - `target` - 암호화 대상 정보
/// - `pub_key` - 공개키 정보
///
/// # Return
///
/// - RSA 암호화 결과 `Result<Box<u8>, CryptoError>`
fn rsa_encrypt(target: &[u8], pub_key: &[u8]) -> Result<Box<[u8]>, CryptoError> {
    // let rsa = Rsa::generate(bit_size.bit() as u32).unwrap();
    let public_key = Rsa::public_key_from_pem(pub_key).unwrap();
    let rsa = Rsa::from(public_key);
    let mut buffer = vec![0; rsa.size() as usize];
    let result = rsa.public_encrypt(target, &mut buffer, Padding::PKCS1);

    if result.is_err() {
        eprintln!("RSA encrypt error : {:#?}", result.err());

        return Err(CryptoError::from(
            "RSA 암호화 처리 중 오류가 발생하였습니다.",
        ));
    }

    return Ok(Box::from(buffer.as_slice()));
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;

    use super::*;

    const PLAIN_TEXT: &str = "This 이것, That 저것";

    #[test]
    pub fn make_sha_hash_test() {
        let mut result: Result<Box<[u8]>, MissingArgumentError> =
            make_sha_hash(SHA_TYPE::SHA_256, "test".as_bytes(), Some("salt"));

        assert!(!result.is_err());

        let v: Vec<String> = result
            .unwrap()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        println!("SHA-256 result : {}", v.join(""));

        result = make_sha_hash(SHA_TYPE::SHA_512, "test".as_bytes(), Some("salt"));

        assert!(!result.is_err());

        let v: Vec<String> = result
            .unwrap()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let v = v.join("");

        println!("SHA-512 result : {}", v);

        let vv = make_sha_hash_string(SHA_TYPE::SHA_512, "test".as_bytes(), Some("salt"));

        assert!(vv.is_ok(), "make_sha_hash_string error => {:#?}", vv.err());

        assert_eq!(v, vv.unwrap(), "hash string 불일치")
    }

    // #[test]
    // #[should_panic]
    // pub fn aes_key_length_mismatch_test() {
    //     // let key = Aes256Gcm::generate_key(OsRng);
    //
    //     // println!("{:#?}", key);
    //
    //     // length 32 mismatched
    //     let key = Key::<Aes256Gcm>::from_slice(b"abc");
    //     let cipher = Aes256Gcm::new(&key);
    // }

    #[test]
    pub fn aes_encrypt_test() {
        let repeat_count = 10usize;
        let result: Result<AESResult, Box<dyn LibError>> = aes_encrypt(
            AES_TYPE::AES_128,
            PLAIN_TEXT.as_bytes(),
            "abc".as_bytes(),
            Some("salt".as_bytes()),
            10,
        );

        assert!(result.is_err());

        let err = result.err().unwrap();
        let err_name = err.get_type_name_from_instance();

        assert_eq!(err_name, std::any::type_name::<InvalidArgumentError>());
        println!("err_name : {}", err_name);

        let encrypt_result = aes_encrypt(
            AES_TYPE::AES_128,
            PLAIN_TEXT.as_bytes(),
            "abcdefgh".as_bytes(),
            Some("saltsalt".as_bytes()), // 8 bytes
            repeat_count,
        );

        assert!(!encrypt_result.is_err(), "aes 암호화 오류 발생");

        // LibError + Debug mixin 하지 않았을 경우 unwrap()을 호출하면 에러 발생
        // 만일 LibError + Debug mixin을 하지 않을 경우 unwrap_or_default() 호출해야 함
        let result_value = encrypt_result.unwrap();

        println!("unwrapped value : {:#?}", result_value);
        println!("unwrapped result value : {:#?}", result_value.result);

        // result_str 비교
        assert!(result_value.result_str().is_some());

        let raw_result: Vec<String> = result_value
            .result()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let raw_result: String = raw_result.join("");

        assert_eq!(raw_result, result_value.result_str().unwrap());

        println!("aes result str ===> {}", result_value.result_str().unwrap());

        let encoded_value = BASE64_STANDARD.encode(result_value.result.clone());

        println!("aes base64 encoded value : {:#?}", encoded_value);

        let mut salt: Option<&[u8]> = None;
        let unwrapped_salt: Vec<u8>;

        if result_value.salt.is_some() {
            unwrapped_salt = result_value.salt.unwrap();
            salt = Some(unwrapped_salt.as_slice());
        }

        println!("final sal : {:#?}", salt);

        let decrypt_result = aes_decrypt(
            AES_TYPE::AES_128,
            Some(result_value.result.as_ref()),
            b"abcdefgh",
            result_value.iv.as_ref(),
            salt,
            repeat_count,
        );

        assert!(!decrypt_result.is_err(), "aes 복호화 오류 발생");

        let decrypted_raw_value = decrypt_result.unwrap();
        let decrypted_value = decrypted_raw_value.as_ref();

        assert_eq!(
            PLAIN_TEXT,
            String::from_utf8_lossy(decrypted_value),
            "복호화 값 불일치"
        );

        println!(
            "decrypted text: {:?}",
            String::from_utf8_lossy(decrypted_value)
        );
    }

    #[test]
    pub fn rsa_encrypt_test() {
        let key_pair = generate_rsa_keypair(RSA_BIT::B_4096);
        let result1 = rsa_encrypt(
            PLAIN_TEXT.as_bytes(),
            key_pair.unwrap().public_key_to_pem().unwrap().as_slice(),
        );

        assert!(!result1.is_err(), "RSA 2048 암호화 실패");

        let result_raw = result1.unwrap();

        assert_eq!(
            result_raw.len(),
            RSA_BIT::B_4096.bytes() as usize,
            "암호화 결과 길이 불일치"
        );

        println!(
            "rsa result(4096) : {:?}\nlength : {}",
            result_raw,
            result_raw.len()
        );

        let encoded_value = BASE64_STANDARD.encode(result_raw);

        println!("rsa base 64 encoded value : {:?}", encoded_value);

        let key_pair = generate_rsa_keypair(RSA_BIT::B_8192);
        let result1 = rsa_encrypt(
            PLAIN_TEXT.as_bytes(),
            key_pair.unwrap().public_key_to_pem().unwrap().as_slice(),
        );

        assert!(!result1.is_err(), "RSA 8192 암호화 실패");

        let result_raw = result1.unwrap();

        assert_eq!(
            result_raw.len(),
            RSA_BIT::B_8192.bytes() as usize,
            "암호화 결과 길이 불일치"
        );
        println!(
            "rsa result(8192) : {:?}\nlength : {}",
            result_raw,
            result_raw.len()
        );

        let result2 = rsa_encrypt_without_key(PLAIN_TEXT.as_bytes(), RSA_BIT::B_2048);

        assert!(result2.is_ok());

        let result2_raw = result2.unwrap();

        assert!(result2_raw.private_key().len() > 0, "개인키 반환 실패");
        assert!(
            result2_raw.private_exponent().len() > 0,
            "개인키 지수 반환 실패"
        );
        assert!(
            result2_raw.private_modulus().len() > 0,
            "개인키 계수 반환 실패"
        );
        assert!(result2_raw.public_key().len() > 0, "공개키 반환 실패");
        assert!(
            result2_raw.public_exponent().len() > 0,
            "공개키 지수 반환 실패"
        );
        assert!(
            result2_raw.public_modulus().len() > 0,
            "공개키 계수 반환 실패"
        );
        assert!(result2_raw.result().len() > 0, "암호화 결과 반환 실패");
        assert_eq!(
            result2_raw.result().len(),
            RSA_BIT::B_2048.bytes() as usize,
            "암호화 결과 길이 불일치"
        );

        // result_str 비교
        assert!(result2_raw.result_str().is_some());

        let raw_result: Vec<String> = result2_raw
            .result()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let raw_result = raw_result.join("");

        assert_eq!(raw_result, result2_raw.result_str().unwrap());

        println!("rsa result str ===> {}", result2_raw.result_str().unwrap());

        let decrypt2 = rsa_decrypt(result2_raw.result(), result2_raw.private_key());

        assert!(!decrypt2.is_err());

        let decrypt2_raw = decrypt2.unwrap();
        let decrypt2_result = String::from_utf8(decrypt2_raw.to_vec()).unwrap();

        assert_eq!(decrypt2_result, PLAIN_TEXT, "복호화 실패");

        println!("원문: {:?}\n복호화 결과: {:?}", PLAIN_TEXT, decrypt2_result);
    }
}
