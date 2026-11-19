//! JavaScript `Date` semantics for date-valued config such as `before`.

const DAY_MS: i64 = 86_400_000;

/// `Date.parse` for the ISO forms npm accepts: a date alone is UTC midnight,
/// a date-time without an offset is local time. Milliseconds since the epoch.
pub fn parse_js_date(input: &str) -> Option<i64> {
    let s = input.trim();
    let (date, time) = match s.find(['T', 't', ' ']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mut parts = date.split('-');
    let year_str = parts.next()?;
    if year_str.len() != 4 {
        return None;
    }
    let year: i64 = year_str.parse().ok()?;
    let month: u32 = parts.next().map_or(Some(1), two_digits)?;
    let day: u32 = parts.next().map_or(Some(1), two_digits)?;
    if parts.next().is_some()
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
    {
        return None;
    }
    let midnight = days_from_civil(year, month, day) * DAY_MS;
    let Some(time) = time else {
        return Some(midnight);
    };

    let (clock, offset_min) = if let Some(clock) = time.strip_suffix(['Z', 'z']) {
        (clock, Some(0))
    } else if let Some(i) = time.rfind(['+', '-']) {
        let (sign, off) = (if &time[i..=i] == "-" { -1 } else { 1 }, &time[i + 1..]);
        let (h, m) = match off.split_once(':') {
            Some((h, m)) => (h, m),
            None if off.len() == 4 => off.split_at(2),
            None => (off, "00"),
        };
        let minutes = i64::from(two_digits(h)?) * 60 + i64::from(two_digits(m)?);
        (&time[..i], Some(sign * minutes))
    } else {
        (time, None)
    };
    let mut fields = clock.split(':');
    let hour = i64::from(two_digits(fields.next()?)?);
    let minute = i64::from(two_digits(fields.next()?)?);
    let (second, millis) = match fields.next() {
        None => (0, 0),
        Some(sec) => {
            let (whole, frac) = sec.split_once('.').unwrap_or((sec, ""));
            let frac_ms = if frac.is_empty() {
                0
            } else {
                if !frac.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                format!("{frac:0<3}")[..3].parse::<i64>().ok()?
            };
            (i64::from(two_digits(whole)?), frac_ms)
        }
    };
    if fields.next().is_some() || hour > 24 || minute > 59 || second > 59 {
        return None;
    }
    let wall = midnight + hour * 3_600_000 + minute * 60_000 + second * 1000 + millis;
    Some(match offset_min {
        Some(off) => wall - off * 60_000,
        None => {
            let guess = wall - local_offset_minutes(wall) * 60_000;
            wall - local_offset_minutes(guess) * 60_000
        }
    })
}

/// `new Date(ms).toLocaleString()` in the host's default locale and time zone.
/// Formats the locales whose patterns are known; others use en-US's.
pub fn to_locale_string(ms: i64) -> String {
    let local = ms + local_offset_minutes(ms) * 60_000;
    let (year, month, day) = civil_from_days(local.div_euclid(DAY_MS));
    let secs = local.rem_euclid(DAY_MS) / 1000;
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    let locale = default_locale().to_ascii_lowercase();
    let lang = locale.split('-').next().unwrap_or_default();
    let traditional = ["-tw", "-hk", "-mo", "-hant"]
        .iter()
        .any(|tag| locale.contains(tag));
    match lang {
        "zh" if !traditional => format!("{year}/{month}/{day} {h:02}:{m:02}:{s:02}"),
        "ja" => format!("{year}/{month}/{day} {h}:{m:02}:{s:02}"),
        "de" => format!("{day}.{month}.{year}, {h:02}:{m:02}:{s:02}"),
        "en" if locale == "en-gb" => {
            format!("{day:02}/{month:02}/{year}, {h:02}:{m:02}:{s:02}")
        }
        _ => {
            let (h12, meridiem) = match h {
                0 => (12, "AM"),
                1..=11 => (h, "AM"),
                12 => (12, "PM"),
                _ => (h - 12, "PM"),
            };
            format!("{month}/{day}/{year}, {h12}:{m:02}:{s:02} {meridiem}")
        }
    }
}

fn two_digits(s: &str) -> Option<u32> {
    (s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(month) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(windows)]
mod host {
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        millis: u16,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn SystemTimeToTzSpecificLocalTime(
            zone: *const std::ffi::c_void,
            universal: *const SystemTime,
            local: *mut SystemTime,
        ) -> i32;
        fn GetUserDefaultLocaleName(name: *mut u16, len: i32) -> i32;
    }

    pub fn local_offset_minutes(ms: i64) -> i64 {
        let days = ms.div_euclid(super::DAY_MS);
        let (year, month, day) = super::civil_from_days(days);
        let secs = ms.rem_euclid(super::DAY_MS) / 1000;
        let Ok(year) = u16::try_from(year) else {
            return 0;
        };
        let universal = SystemTime {
            year,
            month: month as u16,
            day_of_week: (days + 4).rem_euclid(7) as u16,
            day: day as u16,
            hour: (secs / 3600) as u16,
            minute: (secs / 60 % 60) as u16,
            second: (secs % 60) as u16,
            millis: 0,
        };
        let mut local = SystemTime::default();
        // SAFETY: both pointers reference live, correctly laid out SYSTEMTIMEs.
        if unsafe { SystemTimeToTzSpecificLocalTime(std::ptr::null(), &universal, &mut local) }
            == 0
        {
            return 0;
        }
        let local_ms = super::days_from_civil(
            i64::from(local.year),
            u32::from(local.month),
            u32::from(local.day),
        ) * super::DAY_MS
            + i64::from(local.hour) * 3_600_000
            + i64::from(local.minute) * 60_000
            + i64::from(local.second) * 1000;
        (local_ms - (ms - ms.rem_euclid(1000))) / 60_000
    }

    pub fn default_locale() -> String {
        let mut buf = [0u16; 85];
        // SAFETY: the buffer holds LOCALE_NAME_MAX_LENGTH (85) UTF-16 units.
        let len = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), buf.len() as i32) };
        if len <= 1 {
            return "en-US".into();
        }
        String::from_utf16_lossy(&buf[..len as usize - 1])
    }
}

#[cfg(unix)]
mod host {
    pub fn local_offset_minutes(ms: i64) -> i64 {
        let secs = ms.div_euclid(1000) as libc::time_t;
        // SAFETY: localtime_r writes only into the provided tm.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
            return 0;
        }
        tm.tm_gmtoff as i64 / 60
    }

    pub fn default_locale() -> String {
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|k| std::env::var(k).ok())
            .find(|v| !v.is_empty())
            .filter(|v| v != "C" && v != "POSIX")
            .map(|v| v.split('.').next().unwrap_or_default().replace('_', "-"))
            .unwrap_or_else(|| "en-US".into())
    }
}

use host::{default_locale, local_offset_minutes};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_utc_forms() {
        assert_eq!(parse_js_date("1970-01-02"), Some(DAY_MS));
        assert_eq!(parse_js_date("2020-06-01"), Some(1_590_969_600_000));
        assert_eq!(
            parse_js_date("2021-06-01T00:00:00.000Z"),
            Some(1_622_505_600_000)
        );
        assert_eq!(
            parse_js_date("2021-06-01T08:00:00+08:00"),
            Some(1_622_505_600_000)
        );
        assert_eq!(parse_js_date("2021-02-30"), None);
        assert_eq!(parse_js_date("yesterday"), None);
    }

    #[test]
    fn civil_round_trip() {
        for days in [-719_468, -1, 0, 18_000, 20_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
