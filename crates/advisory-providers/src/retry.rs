use std::time::SystemTime;

pub(crate) const MAX_RETRY_DELAY_SECONDS: u64 = 24 * 60 * 60;

pub(crate) fn retry_after_seconds(value: &str, now: SystemTime) -> Option<u64> {
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.min(MAX_RETRY_DELAY_SECONDS));
    }

    httpdate::parse_http_date(value).ok().map(|deadline| {
        deadline
            .duration_since(now)
            .unwrap_or_default()
            .as_secs()
            .min(MAX_RETRY_DELAY_SECONDS)
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_RETRY_DELAY_SECONDS, retry_after_seconds};
    use std::time::{Duration, SystemTime};

    #[test]
    fn numeric_retry_after_is_capped_at_one_day() {
        assert_eq!(
            retry_after_seconds("86401", SystemTime::UNIX_EPOCH),
            Some(MAX_RETRY_DELAY_SECONDS)
        );
        assert_eq!(retry_after_seconds("30", SystemTime::UNIX_EPOCH), Some(30));
    }

    #[test]
    fn http_date_retry_after_is_capped_and_past_dates_are_immediate() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100_000);
        let later = httpdate::fmt_http_date(now + Duration::from_secs(3 * 24 * 60 * 60));
        let earlier = httpdate::fmt_http_date(now - Duration::from_secs(60));

        assert_eq!(
            retry_after_seconds(&later, now),
            Some(MAX_RETRY_DELAY_SECONDS)
        );
        assert_eq!(retry_after_seconds(&earlier, now), Some(0));
        assert_eq!(retry_after_seconds("untrusted", now), None);
    }
}
