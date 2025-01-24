//! 날짜 관련 함수 모음

use crate::error::InvalidArgumentError;
use chrono::{DateTime, Datelike, Days, Months, NaiveDateTime, Offset, TimeZone, Utc, Weekday};
use chrono_tz::Tz;

/// 지정된 날짜 및 시간 문자열을 UTC 날짜로 변경
///
/// 문자열 형태로 전달되는 날짜 및 시간 정보를 **UTC** 시간대로 변환하여 반환.
///
/// # Arguments
///
/// - `datetime` - 날짜 및 시간 문자열 (e.g. '2024-11-27 13:23:47')
/// - `pattern` - 날짜 및 시간 패턴 (e.g. '%Y-%m-%d %H:%M:%S')
/// - `timezone` - [Tz]에서 정의된 timezone 정보 (e.g. [Tz::Asia__Seoul])
///
/// # Return
///
/// - 변환 결과 `Result<DateTime<Utc>, InvalidArgumentError>`
///
/// # Link
///
/// - [NaiveDateTime::parse_from_str]
/// - [Tz::offset_from_utc_datetime]
/// - [chrono_tz::TzOffset::fix]
/// - [Utc::from_utc_datetime]
///
/// # Errors
///
/// - [InvalidArgumentError] - 잘못된 날짜 및 시간 형식 혹은 패턴
///
/// # Example
///
/// ```rust
/// use chrono_tz::Tz;
/// use chrono::{DateTime, Datelike, Timelike};
/// use cliff3_util::date::local_datetime_to_utc;
///
/// // KST 2024-11-22 10:29:48
/// // UTC 2024-11-22 01:29:48
/// let datetime = "20241122102948";
/// let pattern = "%Y%m%d%H%M%S";
/// let timezone = Tz::Asia__Seoul;
/// let result = local_datetime_to_utc(datetime, pattern, &timezone);
///
/// assert!(result.is_ok());
///
/// let result = result.unwrap();
///
/// assert_eq!(2024, result.year());
/// assert_eq!(11, result.month());
/// assert_eq!(22, result.day());
/// assert_eq!(1, result.hour());
/// assert_eq!(29, result.minute());
/// assert_eq!(48, result.second());
/// ```
pub fn local_datetime_to_utc(
    datetime: &str,
    pattern: &str,
    timezone: &Tz,
) -> Result<DateTime<Utc>, InvalidArgumentError> {
    let naive_datetime = NaiveDateTime::parse_from_str(datetime, pattern);

    if naive_datetime.is_err() {
        let err = naive_datetime.as_ref().unwrap_err();

        println!("parse_from_str error => {:#?}", err);

        return Err(InvalidArgumentError::new(format!("{err:#?}").as_ref()));
    }

    Ok({
        let offset = timezone.offset_from_utc_datetime(naive_datetime.as_ref().unwrap());
        let fixed = offset.fix();

        Utc.from_utc_datetime(
            &fixed
                .from_local_datetime(naive_datetime.as_ref().unwrap())
                .unwrap()
                .naive_utc(),
        )
    })
}

/// 지정된 UTC 기준 날짜 및 시간 문자열을 지정된 timezone의 시간대([NaiveDateTime])의 시간으로 변경
///
/// 문자열 형태로 전달되는 UTC 기준 날짜 및 시간 정보를 인자로 전달되는 [Tz]를 이용하여 해당 지역 시간으로 변환하여 반환.
///
/// # Arguments
///
/// - `datetime` - UTC 기준 날짜 및 시간 문자열 (e.g. '2024-09-11 23:47:58')
/// - `pattern` - 날짜 및 시간 패턴 (e.g. '%Y-%m-%d %H:%M:%S')
/// - `timezone` - [Tz]에서 정의된 변경하려는 지역의 시간대 정보 (e.g. [Tz::Asia__Seoul])
///
/// # Return
///
/// - 변환 결과 `Result<NaiveDateTime, InvalidArgumentError>`
///
/// # Link
///
/// - [NaiveDateTime::parse_from_str]
/// - [Tz::offset_from_local_datetime]
/// - [chrono_tz::TzOffset::fix]
///
/// # Errors
///
/// - [InvalidArgumentError] - 잘못된 날짜 및 시간 형식 혹은 패턴
///
/// # Example
///
/// ```rust
/// // UTC 2024-09-11 23:47:58
/// // KST 2024-09-12 08:47:58
/// use chrono_tz::Tz;
/// use chrono::{DateTime, Datelike, Timelike};
/// use cliff3_util::date::utc_datetime_to_local;
///
/// let datetime = "20240911234758";
/// let pattern = "%Y%m%d%H%M%S";
/// let timezone = Tz::Asia__Seoul;
/// let result = utc_datetime_to_local(datetime, pattern, &timezone);
///
/// assert!(result.is_ok());
///
/// let result = result.unwrap();
///
/// assert_eq!(2024, result.year());
/// assert_eq!(9, result.month());
/// assert_eq!(12, result.day());
/// assert_eq!(8, result.hour());
/// assert_eq!(47, result.minute());
/// assert_eq!(58, result.second());
/// ```
pub fn utc_datetime_to_local(
    datetime: &str,
    pattern: &str,
    timezone: &Tz,
) -> Result<NaiveDateTime, InvalidArgumentError> {
    let utc_datetime = NaiveDateTime::parse_from_str(datetime, pattern);

    if utc_datetime.is_err() {
        let err = utc_datetime.as_ref().unwrap_err();

        println!("parse_from_str error => {:#?}", err);

        return Err(InvalidArgumentError::new(format!("{err:#?}").as_ref()));
    }

    Ok({
        let utc_datetime = utc_datetime.unwrap();
        let offset = timezone.offset_from_local_datetime(&utc_datetime).unwrap();
        let fixed = offset.fix();

        fixed.from_utc_datetime(&utc_datetime).naive_local()
    })
}

/// 지정한 날짜의 해당 월 마지막 날짜 반환
///
/// # Arguments
///
/// - `datetime` - 마지막 날짜를 구하고자 하는 [DateTime]
///
/// # Return
///
/// - 해당 월의 마지막 날짜
///
/// # Link
///
/// - [DateTime::checked_add_months]
/// - [DateTime::with_day]
/// - [DateTime::checked_sub_days]
///
/// # Example
///
/// ```rust
/// use chrono::{DateTime, TimeZone, Utc};
/// use cliff3_util::date::get_latest_day;
///
/// // leap month 2024
/// // normal     2025
///
/// let utc_leap_datetime: DateTime<Utc> = Utc.with_ymd_and_hms(2024, 2, 11, 13, 27, 0).unwrap();
///  let latest_day = get_latest_day(&utc_leap_datetime);
///
///  assert_eq!(29, latest_day);
///
///  let utc_datetime = Utc.with_ymd_and_hms(2025, 2, 11, 13, 27, 0).unwrap();
///  let latest_day = get_latest_day(&utc_datetime);
///
///  assert_eq!(28, latest_day);
/// ```
pub fn get_latest_day<T: TimeZone + Sized>(datetime: &DateTime<T>) -> u32 {
    let mut dummy = DateTime::from_timestamp(datetime.timestamp(), 0).unwrap();

    dummy = dummy.checked_add_months(Months::new(1)).unwrap();
    dummy = dummy.with_day(1).unwrap();
    dummy = dummy.checked_sub_days(Days::new(1)).unwrap();

    dummy.day()
}

/// 해당 일자가 포함된 주의 월요일/일요일 날짜 반환
///
/// # Arguments
///
/// - `datetime` - 찾고자 하는 주에 포함된 날짜
///
/// # Return
///
/// - (월요일, 일요일) tuple
///
/// # Link
///
/// - [DateTime::weekday]
/// - [DateTime::checked_sub_days]
/// - [DateTime::checked_add_days]
/// - [Weekday]
/// - [Weekday::days_since]
///
/// # Example
///
/// ```rust
/// use chrono::{Utc, Datelike, TimeZone, NaiveDate, NaiveTime, NaiveDateTime};
/// use cliff3_util::date::get_week_start_end;
/// // 1978-06-22
/// // 일요일 : 06-25
/// // 월요일 : 06-19
/// let datetime = NaiveDateTime::new(NaiveDate::from_ymd_opt(1978, 6, 22).unwrap(), NaiveTime::from_hms_opt(0, 0, 0).unwrap());
/// let (monday, sunday) = get_week_start_end(&datetime);
///
/// assert_eq!(1978, monday.year());
/// assert_eq!(6, monday.month());
/// assert_eq!(19, monday.day());
///
/// assert_eq!(6, sunday.month());
/// assert_eq!(25, sunday.day());
/// ```
pub fn get_week_start_end(datetime: &NaiveDateTime) -> (NaiveDateTime, NaiveDateTime) {
    let current_day_of_week = datetime.weekday();
    let days_since = current_day_of_week.days_since(Weekday::Mon);
    let mut monday = datetime.clone();

    monday = monday
        .checked_sub_days(Days::new(days_since as u64))
        .unwrap();

    let mut sunday = monday.clone();

    sunday = sunday.checked_add_days(Days::new(6)).unwrap();

    (monday, sunday)
}

#[cfg(test)]
mod tests {
    use super::{get_latest_day, get_week_start_end, local_datetime_to_utc, utc_datetime_to_local};
    use chrono::{
        DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Timelike, Utc,
    };
    use chrono_tz::Tz;

    #[test]
    fn local_datetime_to_utc_test() {
        // KST 2024-11-22 09:54:45
        // UTC 2024-11-22 00:54:45
        let str_datetime = "20241122095445"; // 2024-11-22 09:54:45
        let pattern = "%Y%m%d%H%M%S";
        let timezone = Tz::Asia__Seoul;

        let result = local_datetime_to_utc(str_datetime, pattern, &timezone);

        assert!(
            result.is_ok(),
            "{}",
            format!("변환 실패 : {:#?}", result.as_ref().unwrap_err())
        );

        let result = result.unwrap();

        println!("utc result => {:#?}", result);

        assert_eq!(2024, result.year());
        assert_eq!(11, result.month());
        assert_eq!(22, result.day());
        assert_eq!(0, result.hour());
        assert_eq!(54, result.minute());
        assert_eq!(45, result.second());
    }

    #[test]
    fn utc_datetime_to_local_test() {
        // UTC 2024-11-22 22:54:45
        // KST 2024-11-23 07:54:45
        let utc_datetime = "20241122225445";
        let patter = "%Y%m%d%H%M%S";
        let timezone = Tz::Asia__Seoul;
        let result = utc_datetime_to_local(utc_datetime, patter, &timezone);

        assert!(
            result.is_ok(),
            "{}",
            format!("변환 실패 : {:#?}", result.as_ref().unwrap_err())
        );

        let result = result.unwrap();

        println!("local result => {:#?}", result);

        assert_eq!(2024, result.year());
        assert_eq!(11, result.month());
        assert_eq!(23, result.day());
        assert_eq!(7, result.hour());
        assert_eq!(54, result.minute());
        assert_eq!(45, result.second());
    }

    #[test]
    fn get_latest_day_test() {
        // leap month 2024
        // normal     2025
        let utc_leap_datetime: DateTime<Utc> =
            Utc.with_ymd_and_hms(2024, 2, 11, 13, 27, 0).unwrap();
        let latest_day = get_latest_day(&utc_leap_datetime);

        assert_eq!(29, latest_day);

        let utc_datetime = Utc.with_ymd_and_hms(2025, 2, 11, 13, 27, 0).unwrap();
        let latest_day = get_latest_day(&utc_datetime);

        assert_eq!(28, latest_day);
    }

    #[test]
    fn get_week_start_end_test() {
        // 1978-06-22
        // 일요일 : 06-25
        // 월요일 : 06-19
        let datetime = NaiveDateTime::new(
            NaiveDate::from_ymd_opt(1978, 6, 22).unwrap(),
            NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
        );
        let (monday, sunday) = get_week_start_end(&datetime);

        assert_eq!(1978, monday.year());
        assert_eq!(6, monday.month());
        assert_eq!(19, monday.day());

        assert_eq!(6, sunday.month());
        assert_eq!(25, sunday.day());
    }
}
