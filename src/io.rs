//! I/O 관련 함수 모음

use std::ops::Not;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Datelike, Local};

use crate::error::InvalidArgumentError;

/// Directory 생성시 날짜 규칙
///
/// - `YYYYMMDD` Directory 생성시 **yyyyMMdd** 형태의 날짜 정보를 이용
/// - `YYYYMM` Directory 생성시 **yyyyMM** 형태의 날짜 정보를 이용
/// - `YYYY` Directory 생성시 **yyyy** 형태의 날짜 정보를 이용
///
/// # Link
///
/// [generate_path]
#[derive(PartialEq)]
pub enum DirectoryDateType {
    /// yyyyMMdd 형태
    YYYYMMDD,

    /// yyyyMM 형태
    YYYYMM,

    /// yyyy 형태
    YYYY,
}

impl DirectoryDateType {
    /// 주어진 날짜 정보와 구분자를 이용하여 directory 문자열을 반환
    ///
    /// # Arguments
    ///
    /// - `date` [`DateTime<Local>`]
    /// - `separator` 날짜 정보 사이에 입력될 문자열 (e.g. **-**, **_**)
    ///
    /// # Return
    ///
    /// - 생성된 경로 문자열
    ///
    /// # Example
    ///
    /// ```rust
    /// use cliff3_util::io::DirectoryDateType;
    /// use chrono::DateTime;
    ///
    /// let now = chrono::Local::now();
    /// let result = DirectoryDateType::YYYYMMDD.generate_path_string(&now, Some("--"));
    ///
    /// // result => 2024--06--26
    /// ```
    pub fn generate_path_string(&self, date: &DateTime<Local>, separator: Option<&str>) -> String {
        let mut path: Vec<String> = vec![];

        path.push(date.year().to_string());
        self.insert_separator(&mut path, separator);

        if *self != DirectoryDateType::YYYY {
            path.push(format!("{:0>2}", date.month()));
            self.insert_separator(&mut path, separator);
        }

        if *self == DirectoryDateType::YYYYMMDD {
            path.push(format!("{:0>2}", date.day().to_string()));
        }

        return path.join("");
    }

    /// 구분자 추가
    ///
    /// **separator**가 `None`일 경우 생략
    ///
    /// # Arguments
    ///
    /// - `path` 경로 정보를 가지는 `Vec<String>`
    /// - `separator` 날짜 정보 사이에 입력될 문자열 (e.g. **-**, **_**)
    #[inline]
    fn insert_separator(&self, path: &mut Vec<String>, separator: Option<&str>) {
        if separator.is_none() {
            return;
        }

        path.push(separator.unwrap().to_owned());
    }
}

/// 지정된 경로 하위에 [DirectoryDateType] 형태에 따라 하위 directory 생성
///
/// # Arguments
///
/// - `parent_path` - 생성하고자 하는 경로의 부모 directory
/// - `date_type` - [DirectoryDateType]
/// - `separator` - 날짜 정보 사이에 입력될 문자열 (e.g. **-**, **_**)
///
/// # Return
///
/// - 생성 결과 `Result<Box<Path>, InvalidArgumentError>`
///
/// # Errors
///
/// - [InvalidArgumentError] 부모 경로가 존재하지 않을 경우 혹은 [std::fs::create_dir_all] 실패
///
/// # Link
///
/// - [DirectoryDateType]
/// - [InvalidArgumentError]
/// - [std::fs::create_dir_all]
///
/// # Example
///
/// ```rust
/// use std::path::Path;
/// use chrono::DateTime;
/// use cliff3_util::io::{generate_path, DirectoryDateType};
///
/// let now = chrono::Local::now();
/// let compare_dir_name = DirectoryDateType::YYYYMMDD.generate_path_string(&now, Some("_"));
/// let current_path = Path::new(env!("CARGO_MANIFEST_DIR"));
/// let result = generate_path(current_path, DirectoryDateType::YYYYMMDD, Some("_"));
///
/// assert!(result.is_ok());
///
/// let created_dir = result.unwrap();
///
/// assert!(created_dir.exists());
///
/// let dir_name = created_dir.file_name().unwrap();
///
/// assert_eq!(compare_dir_name, dir_name.to_str().unwrap());
///
/// let deleted_dir = std::fs::remove_dir(created_dir);
///
/// assert!(deleted_dir.is_ok());
/// ```
pub fn generate_path(
    parent_path: &Path,
    date_type: DirectoryDateType,
    separator: Option<&str>,
) -> Result<Box<Path>, InvalidArgumentError> {
    // check exist parent path
    if parent_path.exists().not() {
        let path_str = parent_path.as_os_str();
        let message = format!("[{:?}] 경로가 존재하지 않습니다.", path_str);

        return Err(InvalidArgumentError::new(message.as_str()));
    }

    let now = Local::now();
    let dir_string = date_type.generate_path_string(&now, separator);
    let result = PathBuf::from(parent_path).join(dir_string);

    if !&result.exists() {
        let created_result = std::fs::create_dir_all(&result);

        if created_result.is_err() {
            let err = created_result.err();
            // TODO(joonho): 2024-06-24 create_dir_all에서 반환되는 에러 확인
            return Err(InvalidArgumentError::new(
                format!("{:?}", err.unwrap()).as_str(),
            ));
        }
    }

    return Ok(result.into_boxed_path());
}

#[cfg(test)]
mod tests {
    use super::{generate_path, DirectoryDateType};
    use std::path::Path;

    #[test]
    fn generate_path_test() {
        let now = chrono::Local::now();
        let compare_dir_name = DirectoryDateType::YYYYMMDD.generate_path_string(&now, Some("_"));
        let current_path = Path::new(env!("CARGO_MANIFEST_DIR"));
        let result = generate_path(current_path, DirectoryDateType::YYYYMMDD, Some("_"));

        // yyyy_mm_dd
        assert!(result.is_ok());

        let created_dir = result.unwrap();

        assert!(created_dir.exists());

        let dir_name = created_dir.file_name().unwrap();
        assert_eq!(dir_name.to_str().unwrap(), compare_dir_name);

        // 생성된 테스트 경로 삭제
        let deleted_dir = std::fs::remove_dir(created_dir);

        assert!(deleted_dir.is_ok());
    }
}
