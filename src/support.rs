const OLDEST_BUILD: u64 = 957;

pub fn is_older_than_supported(release: &str) -> bool {
    let (base, rest) = match release.split_once('-') {
        Some((b, r)) => (b, Some(r)),
        None => (release, None),
    };
    let nums: Vec<u64> = base
        .split('.')
        .map(|p| p.parse::<u64>())
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    if nums.len() < 2 {
        return false;
    }
    let cur = (nums[0], nums[1], nums.get(2).copied().unwrap_or(0));
    let want = (3, 10, 0);
    if cur < want {
        return true;
    }
    if cur > want {
        return false;
    }
    let build: Option<u64> = rest.and_then(|r| {
        let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    });
    build.is_some_and(|b| b < OLDEST_BUILD)
}

pub fn refusal_text(release: &str, version: &str) -> String {
    format!(
        "RootKit 掃描報告\n\n\
         結論：這台機器的核心（{}）比支援範圍舊，沒有驗證過，掃描器不執行。\n\n\
         支援範圍：CentOS 7.6 至 7.9（核心 3.10.0-957 起）。\n\
         為什麼停下來：比這更舊的核心，掃描器依賴的行為沒有在實驗室驗證過，貿然執行可能產生誤報或漏報，所以寧可不做。\n\
         掃描器版本 {}。沒有執行掃描。\n",
        release, version
    )
}

pub fn must_refuse_non_root(is_replay: bool, is_root: bool) -> bool {
    !is_replay && !is_root
}

pub fn non_root_refusal_text() -> String {
    "請以root權限執行\n".to_string()
}

pub fn report_file_base(hostname: &str, epoch: u64) -> String {
    let host: String = hostname
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let host = if host.is_empty() {
        "host".to_string()
    } else {
        host
    };
    format!("report-{}-{}", host, crate::timeutil::fmt_tw_compact(epoch))
}

pub fn save_report_in(
    dir: &std::path::Path,
    base: &str,
    text: &str,
) -> std::io::Result<std::path::PathBuf> {
    save_bytes_in(dir, base, "txt", text.as_bytes())
}

pub fn save_bytes_in(
    dir: &std::path::Path,
    base: &str,
    ext: &str,
    bytes: &[u8],
) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    for n in 1..=99u32 {
        let name = if n == 1 {
            format!("{}.{}", base, ext)
        } else {
            format!("{}-{}.{}", base, n, ext)
        };
        let path = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(bytes)?;
                f.flush()?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "同名的報告檔太多",
    ))
}

pub fn report_dir(exe: Option<&std::path::Path>) -> std::path::PathBuf {
    match exe.and_then(|p| p.parent()) {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    }
}

pub const DONE_TEXT: &str = "掃描完成。\n";

pub const SAVE_FAILED_TEXT: &str =
    "掃描完成，但報告存不下來。請確認 rootkit-scan 所在的資料夾可以寫入，再執行一次。\n";

pub const SAVE_FAILED_WIPED_TEXT: &str =
    "掃描完成，但報告存不下來，而且 rootkit-scan 已經把自己刪掉了。請確認原來的資料夾可以寫入，重新複製 rootkit-scan 過去再執行一次。\n";

pub fn should_wipe_self(pubkey: Option<&str>, is_replay: bool) -> bool {
    pubkey.is_some() && !is_replay
}

pub fn remove_own_exe(exe: Option<&std::path::Path>) -> std::io::Result<()> {
    match exe {
        Some(p) => std::fs::remove_file(p),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "找不到自己的執行檔",
        )),
    }
}

pub fn scrub(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn scrub_vec(v: &mut Vec<u8>) {
    let cap = v.capacity();
    v.resize(cap, 0);
    scrub(v);
}

pub fn scrub_string(s: String) {
    let mut v = s.into_bytes();
    scrub_vec(&mut v);
}

extern "C" {
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
}

const PR_SET_DUMPABLE: i32 = 4;
#[cfg(test)]
const PR_GET_DUMPABLE: i32 = 3;

pub fn disable_core_dumps() {
    unsafe {
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

pub const WIPE_FAILED_TEXT: &str = "提醒：沒能刪掉 rootkit-scan 本身，檔案還留在硬碟上。\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centos_7_0_to_7_5_are_older_than_supported() {
        for r in [
            "3.10.0-123.el7.x86_64",
            "3.10.0-229.el7.x86_64",
            "3.10.0-327.el7.x86_64",
            "3.10.0-514.el7.x86_64",
            "3.10.0-693.el7.x86_64",
            "3.10.0-862.el7.x86_64",
            "3.10.0-956.el7.x86_64",
            "2.6.32-754.el6.x86_64",
        ] {
            assert!(is_older_than_supported(r), "{} 應該太舊", r);
        }
    }

    #[test]
    fn centos_7_6_to_7_9_and_their_updates_are_supported() {
        for r in [
            "3.10.0-957.el7.x86_64",
            "3.10.0-957.1.3.el7.x86_64",
            "3.10.0-1062.el7.x86_64",
            "3.10.0-1127.el7.x86_64",
            "3.10.0-1160.el7.x86_64",
            "3.10.0-1160.118.1.el7.x86_64",
        ] {
            assert!(!is_older_than_supported(r), "{} 在支援範圍內", r);
        }
    }

    #[test]
    fn unknown_or_newer_kernel_series_are_not_stopped() {
        for r in [
            "5.14.0-362.el9.x86_64",
            "4.18.0-80.el8.x86_64",
            "7.0.0-34-generic",
            "garbage",
            "",
        ] {
            assert!(!is_older_than_supported(r), "{:?}", r);
        }
    }

    #[test]
    fn refusal_says_why_and_the_supported_range() {
        let t = refusal_text("3.10.0-862.el7.x86_64", "0.1.0");
        assert!(t.contains("3.10.0-862.el7.x86_64"));
        assert!(t.contains("比支援範圍舊"));
        assert!(t.contains("CentOS 7.6 至 7.9"));
        assert!(t.contains("沒有執行掃描"));
    }

    #[test]
    fn live_scan_requires_root_but_replay_does_not() {
        assert!(
            must_refuse_non_root(false, false),
            "現場掃描、非 root：拒絕"
        );
        assert!(!must_refuse_non_root(false, true), "現場掃描、root：照常");
        assert!(!must_refuse_non_root(true, false), "重播、非 root：照常");
        assert!(!must_refuse_non_root(true, true), "重播、root：照常");
    }

    #[test]
    fn non_root_text_is_exactly_one_line() {
        assert_eq!(non_root_refusal_text(), "請以root權限執行\n");
    }

    #[test]
    fn report_file_name_is_safe_and_uses_utc_plus_8() {
        assert_eq!(
            report_file_base("victim-host", 1_772_352_000),
            "report-victim-host-20260301-160000"
        );
        assert_eq!(
            report_file_base("a b/c\n..", 1_772_352_000),
            "report-a_b_c_..-20260301-160000"
        );
        assert_eq!(
            report_file_base("", 1_772_352_000),
            "report-host-20260301-160000"
        );
        assert!(!report_file_base("../../etc/passwd", 0).contains('/'));
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rk-save-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn saved_report_is_private_new_and_never_overwrites_or_follows_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("a");
        let first = save_report_in(&dir, "report-x", "第一份\n").unwrap();
        assert_eq!(first, dir.join("report-x.txt"));
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "第一份\n");
        let mode = std::fs::metadata(&first).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "只有擁有者讀寫");
        let second = save_report_in(&dir, "report-x", "第二份\n").unwrap();
        assert_eq!(second, dir.join("report-x-2.txt"));
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "第一份\n");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "別人的檔案").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("report-y.txt")).unwrap();
        let third = save_report_in(&dir, "report-y", "報告\n").unwrap();
        assert_eq!(third, dir.join("report-y-2.txt"));
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "別人的檔案");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_into_a_missing_folder_is_an_error() {
        let dir = scratch("b");
        let gone = dir.join("nope");
        assert!(save_report_in(&gone, "report-z", "x").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn screen_text_after_a_scan_is_one_short_line_with_no_findings_or_paths() {
        assert_eq!(DONE_TEXT, "掃描完成。\n");
        for t in [
            DONE_TEXT,
            SAVE_FAILED_TEXT,
            SAVE_FAILED_WIPED_TEXT,
            WIPE_FAILED_TEXT,
        ] {
            assert_eq!(t.lines().count(), 1, "只有一行：{}", t);
            for secret in [
                "結論", "發現", "report-", "/root", ".txt", "errno", "os error",
            ] {
                assert!(!t.contains(secret), "螢幕文字不能含「{}」：{}", secret, t);
            }
        }
    }

    #[test]
    fn only_a_keyed_live_scan_deletes_the_scanner() {
        assert!(should_wipe_self(Some("rkscan-pub-v1:00"), false));
        assert!(!should_wipe_self(None, false));
        assert!(!should_wipe_self(Some("rkscan-pub-v1:00"), true));
        assert!(!should_wipe_self(None, true));
    }

    #[test]
    fn disable_core_dumps_marks_this_process_non_dumpable() {
        disable_core_dumps();
        let flag = unsafe { prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(flag, 0, "呼叫之後，本行程的「可傾印」旗標應該是 0");
    }

    #[test]
    fn scrub_zeroes_every_byte_it_is_given() {
        let mut buf = *b"RootKit \xe6\x8e\x83\xe6\x8f\x8f report";
        scrub(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
        scrub(&mut []);
    }

    #[test]
    fn scrub_vec_also_clears_the_unused_tail_of_the_allocation() {
        let mut v: Vec<u8> = Vec::with_capacity(64);
        v.extend_from_slice(b"secret report text");
        let cap = v.capacity();
        assert!(cap >= 64);
        scrub_vec(&mut v);
        assert_eq!(v.len(), cap);
        assert!(v.iter().all(|&b| b == 0));
    }

    #[test]
    fn removing_own_exe_deletes_the_file_and_reports_failure_without_panicking() {
        let dir = scratch("wipe");
        let exe = dir.join("fake-scanner");
        std::fs::write(&exe, b"x").unwrap();
        assert!(remove_own_exe(Some(&exe)).is_ok());
        assert!(!exe.exists());
        assert!(remove_own_exe(Some(&exe)).is_err());
        assert!(remove_own_exe(None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn report_goes_next_to_the_scanner_wherever_it_was_started_from() {
        use std::path::{Path, PathBuf};
        assert_eq!(
            report_dir(Some(Path::new("/root/kit/rootkit-scan"))),
            PathBuf::from("/root/kit")
        );
        assert_eq!(
            report_dir(Some(Path::new("/rootkit-scan"))),
            PathBuf::from("/")
        );
        assert_eq!(report_dir(None), PathBuf::from("."));
        assert_eq!(
            report_dir(Some(Path::new("rootkit-scan"))),
            PathBuf::from(".")
        );
    }
}
