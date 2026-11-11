pub fn civil_from_epoch(epoch: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (epoch / 86_400) as i64;
    let secs = epoch % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (
        y,
        m,
        d,
        (secs / 3_600) as u32,
        (secs % 3_600 / 60) as u32,
        (secs % 60) as u32,
    )
}

const REPORT_TZ_OFFSET_SECS: u64 = 8 * 3_600;

pub fn fmt_tw(epoch: u64) -> String {
    let (y, m, d, hh, mm, _) = civil_from_epoch(epoch + REPORT_TZ_OFFSET_SECS);
    format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m, d, hh, mm)
}

pub fn fmt_tw_compact(epoch: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_epoch(epoch + REPORT_TZ_OFFSET_SECS);
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", y, m, d, hh, mm, ss)
}

pub fn fmt_tw_sec(epoch: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_epoch(epoch + REPORT_TZ_OFFSET_SECS);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_values_are_utc() {
        assert_eq!(civil_from_epoch(1_791_982_917), (2026, 10, 14, 13, 1, 57));
        assert_eq!(civil_from_epoch(951_782_400), (2000, 2, 29, 0, 0, 0));
    }

    #[test]
    fn report_time_is_utc_plus_8() {
        assert_eq!(fmt_tw(0), "1970-01-01 08:00");
        assert_eq!(fmt_tw(1_000_000_000), "2001-09-09 09:46");
        assert_eq!(fmt_tw(1_791_982_917), "2026-10-14 21:01");
        assert_eq!(fmt_tw_sec(1_791_982_917), "2026-10-14 21:01:57");
    }

    #[test]
    fn report_time_crosses_day_month_year_and_leap_day() {
        assert_eq!(fmt_tw_sec(1_791_982_917 + 3 * 3_600), "2026-10-15 00:01:57");
        assert_eq!(fmt_tw_sec(1_793_462_400), "2026-11-01 00:00:00");
        assert_eq!(fmt_tw_sec(1_767_196_800), "2026-01-01 00:00:00");
        assert_eq!(fmt_tw_sec(951_782_400 - 8 * 3_600), "2000-02-29 00:00:00");
    }
}
