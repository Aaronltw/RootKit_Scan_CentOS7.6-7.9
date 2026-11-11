use crate::model::{LoadLine, LogCopy, Meta, ModLists, ModSample, NameCheck, ProcSample, Unlisted};
use crate::timeutil::civil_from_epoch;
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn geteuid() -> u32;
    fn sysconf(name: i32) -> i64;
    fn mktime(tm: *mut Tm) -> i64;
}

pub fn is_root() -> bool {
    unsafe { geteuid() == 0 }
}

#[repr(C)]
struct Tm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
    tm_gmtoff: i64,
    tm_zone: *const u8,
}

const SC_CLK_TCK: i32 = 2;
const EPERM: i32 = 1;
const EAGAIN: i32 = 11;
const EPIPE: i32 = 32;
const O_NONBLOCK: i32 = 0o4000;
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const EPOCH_PROBE_LINES: u64 = 2000;
const MAX_LINE_BYTES: u64 = 1024 * 1024;
const MAX_CANDIDATES: usize = 64;

fn read_trim(path: &str) -> String {
    fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default()
}

pub fn collect_meta() -> Meta {
    let tck = unsafe { sysconf(SC_CLK_TCK) };
    let uptime = read_trim("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let btime = read_trim("/proc/stat")
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    Meta {
        btime,
        hostname: read_trim("/proc/sys/kernel/hostname"),
        kernel: read_trim("/proc/sys/kernel/osrelease"),
        os: read_trim("/etc/centos-release"),
        epoch: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        clk_tck: if tck > 0 { tck as u64 } else { 100 },
        is_root: is_root(),
        pid_max: read_trim("/proc/sys/kernel/pid_max")
            .parse()
            .unwrap_or(32768),
        uptime_s: uptime,
        elapsed_ms: 0,
        scanner_sha256: None,
    }
}

fn listed_ids() -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return set;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        set.insert(pid);
        if let Ok(tasks) = fs::read_dir(format!("/proc/{}/task", pid)) {
            for t in tasks.flatten() {
                if let Some(tid) = t.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) {
                    set.insert(tid);
                }
            }
        }
    }
    set
}

fn alive_ids(pid_max: u32) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    for id in 1..=pid_max {
        let r = unsafe { kill(id as i32, 0) };
        if r == 0 || io::Error::last_os_error().raw_os_error() == Some(EPERM) {
            set.insert(id);
        }
    }
    set
}

fn parse_stat(stat: &str) -> Option<(u64, Option<u32>, String)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = stat[open + 1..close].to_string();
    let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let ppid = rest.get(1).and_then(|v| v.parse().ok());
    let start = rest.get(19).and_then(|v| v.parse().ok())?;
    Some((start, ppid, comm))
}

fn cgroup_ids() -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    let mut stack = vec![std::path::PathBuf::from("/sys/fs/cgroup/systemd")];
    while let Some(dir) = stack.pop() {
        if let Ok(text) = fs::read(dir.join("tasks")) {
            for tok in String::from_utf8_lossy(&text).split_whitespace() {
                if let Ok(id) = tok.parse::<u32>() {
                    set.insert(id);
                }
            }
        }
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(e.path());
                }
            }
        }
    }
    set
}

pub fn parse_sched_ids(text: &str) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    let mut in_tasks = false;
    let mut after_rule = false;
    for line in text.lines() {
        if line.starts_with("runnable tasks:") {
            in_tasks = true;
            after_rule = false;
            continue;
        }
        if !in_tasks {
            continue;
        }
        if line.starts_with("---") {
            after_rule = true;
            continue;
        }
        if !after_rule {
            continue;
        }
        if line.trim().is_empty() || line.starts_with("cpu#") {
            in_tasks = false;
            continue;
        }
        let b = line.as_bytes();
        if b.len() < 18 || b[16] != b' ' {
            continue;
        }
        let digits: String = b[17..]
            .iter()
            .skip_while(|c| **c == b' ')
            .take_while(|c| c.is_ascii_digit())
            .map(|c| *c as char)
            .collect();
        if let Ok(pid) = digits.parse::<u32>() {
            if pid > 0 {
                set.insert(pid);
            }
        }
    }
    set
}

pub fn parse_timer_ids(text: &str) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    for line in text.lines() {
        let t = line.trim();
        let mut ch = t.chars();
        if ch.next() != Some('#') || !ch.next().is_some_and(|c| c.is_ascii_digit()) {
            continue;
        }
        let Some(slash) = t.rfind('/') else { continue };
        if let Ok(pid) = t[slash + 1..].parse::<u32>() {
            if pid > 0 && slash > 0 {
                set.insert(pid);
            }
        }
    }
    set
}

struct SchedView {
    read: bool,
    ids: BTreeSet<u32>,
    timer: BTreeSet<u32>,
}

fn read_sched_view() -> SchedView {
    let sd = fs::read("/proc/sched_debug").ok();
    let tl = fs::read("/proc/timer_list").ok();
    SchedView {
        read: sd.is_some(),
        ids: sd
            .map(|b| parse_sched_ids(&String::from_utf8_lossy(&b)))
            .unwrap_or_default(),
        timer: tl
            .map(|b| parse_timer_ids(&String::from_utf8_lossy(&b)))
            .unwrap_or_default(),
    }
}

pub(crate) fn describe(
    pid: u32,
    via_kill: bool,
    via_cgroup: bool,
    via_sched: bool,
    via_timer: bool,
) -> Unlisted {
    let stat = fs::read(format!("/proc/{}/stat", pid))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let (starttime, ppid, comm) = parse_stat(&stat).unwrap_or((0, None, String::new()));
    let exe = fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    let cmdline = fs::read(format!("/proc/{}/cmdline", pid))
        .map(|b| {
            String::from_utf8_lossy(&b)
                .replace('\0', " ")
                .trim()
                .to_string()
        })
        .unwrap_or_default();
    Unlisted {
        pid,
        via_kill,
        via_cgroup,
        via_sched,
        via_timer,
        starttime,
        ppid,
        comm,
        exe,
        cmdline,
    }
}

pub(crate) fn pid_alive(pid: u32) -> bool {
    let r = unsafe { kill(pid as i32, 0) };
    r == 0 || io::Error::last_os_error().raw_os_error() == Some(EPERM)
}

pub fn collect_proc_sample(start: Instant, pid_max: u32) -> ProcSample {
    let t_ms = start.elapsed().as_millis() as u64;
    let listed = listed_ids();
    let alive = alive_ids(pid_max);
    let cgroup = cgroup_ids();
    let sched = read_sched_view();
    let trusted = sched.read && sched.ids.contains(&std::process::id());
    let mut candidates: BTreeSet<u32> = alive.union(&cgroup).copied().collect();
    if trusted {
        candidates.extend(sched.ids.iter().copied());
    }
    let unlisted = candidates
        .difference(&listed)
        .map(|&pid| {
            describe(
                pid,
                alive.contains(&pid),
                cgroup.contains(&pid),
                trusted && sched.ids.contains(&pid),
                trusted && sched.timer.contains(&pid),
            )
        })
        .collect();
    ProcSample {
        t_ms,
        n_listed: listed.len(),
        n_alive: alive.len(),
        n_cgroup: cgroup.len(),
        sched_read: sched.read,
        sched_trusted: trusted,
        n_sched: sched.ids.len(),
        n_timer: sched.timer.len(),
        unlisted,
    }
}

fn dir_names(path: &str) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(path)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn sys_module_nlink() -> i64 {
    fs::metadata("/sys/module")
        .map(|m| m.nlink() as i64)
        .unwrap_or(-1)
}

pub fn collect_mod_sample(start: Instant, known_dirs: &mut HashSet<String>) -> ModSample {
    let t_ms = start.elapsed().as_millis() as u64;
    let nl_before = sys_module_nlink();
    let first = dir_names("/sys/module");
    let nl_mid = sys_module_nlink();
    let second = dir_names("/sys/module");
    let nl_after = sys_module_nlink();
    let mut n_sub = 0;
    let mut vanished = 0;
    for name in &first {
        if known_dirs.contains(name) {
            n_sub += 1;
            continue;
        }
        match fs::metadata(format!("/sys/module/{}", name)) {
            Ok(m) if m.is_dir() => {
                known_dirs.insert(name.clone());
                n_sub += 1;
            }
            Ok(_) => {}
            Err(_) => vanished += 1,
        }
    }
    ModSample {
        t_ms,
        nl_before,
        nl_mid,
        nl_after,
        n_list1: first.len(),
        n_list2: second.len(),
        n_sub,
        vanished,
    }
}

fn proc_module_names() -> Vec<String> {
    let mut v: Vec<String> = read_trim("/proc/modules")
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(String::from))
        .collect();
    v.sort();
    v
}

pub fn snapshot_lists() -> (Vec<String>, Vec<String>) {
    (proc_module_names(), dir_names("/sys/module"))
}

pub fn fill_lists(lists: &mut ModLists, before: bool) {
    let (p, s) = snapshot_lists();
    if before {
        lists.proc_before = p;
        lists.sys_before = s;
    } else {
        lists.proc_after = p;
        lists.sys_after = s;
    }
}

const PHRASES: [&str; 2] = [
    ": loading out-of-tree module taints kernel",
    ": module verification failed",
];

pub fn extract_load_name(line: &str) -> Option<String> {
    for ph in PHRASES {
        if let Some(pos) = line.find(ph) {
            let head = &line[..pos];
            let name: String = head
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if !name.is_empty() && name.len() <= 56 {
                return Some(name);
            }
        }
    }
    None
}

pub fn collect_kmsg() -> LogCopy {
    let mut copy = LogCopy {
        source: "kmsg".into(),
        ..Default::default()
    };
    let Ok(mut f) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open("/dev/kmsg")
    else {
        return copy;
    };
    copy.readable = true;
    let mut prev: Option<u64> = None;
    let mut buf = vec![0u8; 8192];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let rec = String::from_utf8_lossy(&buf[..n]).into_owned();
                let Some((head, rest)) = rec.split_once(';') else {
                    continue;
                };
                let seq: Option<u64> = head.split(',').nth(1).and_then(|v| v.parse().ok());
                copy.records += 1;
                if let Some(q) = seq {
                    if copy.first_seq.is_none() {
                        copy.first_seq = Some(q);
                    }
                    if let Some(p) = prev {
                        if q != p + 1 {
                            copy.seq_gaps += 1;
                        }
                    }
                    prev = Some(q);
                }
                let text = rest.lines().next().unwrap_or("");
                if let Some(name) = extract_load_name(text) {
                    copy.load_lines.push(LoadLine {
                        name,
                        text: text.chars().take(300).collect(),
                        epoch: None,
                        seq,
                    });
                }
            }
            Err(e) if e.raw_os_error() == Some(EAGAIN) => break,
            Err(e) if e.raw_os_error() == Some(EPIPE) => continue,
            Err(_) => break,
        }
    }
    copy
}

fn month_index(m: &str) -> Option<i32> {
    [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|x| *x == m)
    .map(|i| i as i32)
}

fn syslog_epoch(line: &str, now: u64) -> Option<u64> {
    let mut it = line.split_whitespace();
    let mon = month_index(it.next()?)?;
    let day: i32 = it.next()?.parse().ok()?;
    let hms = it.next()?;
    let mut p = hms.split(':');
    let (h, m, sec): (i32, i32, i32) = (
        p.next()?.parse().ok()?,
        p.next()?.parse().ok()?,
        p.next()?.parse().ok()?,
    );
    let year_now = civil_from_epoch(now).0 as i32;
    for year in [year_now, year_now - 1] {
        let mut tm = Tm {
            tm_sec: sec,
            tm_min: m,
            tm_hour: h,
            tm_mday: day,
            tm_mon: mon,
            tm_year: year - 1900,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: -1,
            tm_gmtoff: 0,
            tm_zone: std::ptr::null(),
        };
        let t = unsafe { mktime(&mut tm) };
        if t > 0 && (t as u64) <= now + 86_400 {
            return Some(t as u64);
        }
    }
    None
}

pub fn collect_messages(now: u64) -> LogCopy {
    read_messages_dir("/var/log", now, MAX_LOG_BYTES)
}

fn read_messages_dir(dir: &str, now: u64, max_bytes: u64) -> LogCopy {
    let mut copy = LogCopy {
        source: "messages".into(),
        ..Default::default()
    };
    for name in dir_names(dir) {
        if !name.starts_with("messages") {
            continue;
        }
        if [".gz", ".xz", ".bz2", ".zst"]
            .iter()
            .any(|e| name.ends_with(e))
        {
            copy.skipped += 1;
            continue;
        }
        let path = format!("{}/{}", dir, name);
        match fs::metadata(&path) {
            Ok(m) if m.is_file() && m.len() <= max_bytes => {}
            Ok(m) if m.is_file() => {
                copy.unread += 1;
                continue;
            }
            _ => {
                copy.skipped += 1;
                continue;
            }
        }
        let Ok(file) = fs::File::open(&path) else {
            copy.skipped += 1;
            continue;
        };
        copy.readable = true;
        copy.files += 1;
        if !read_syslog_stream(file, now, &mut copy) {
            copy.unread += 1;
        }
    }
    copy
}

fn read_syslog_stream(file: fs::File, now: u64, copy: &mut LogCopy) -> bool {
    let mut rd = BufReader::with_capacity(1 << 20, file);
    let mut buf = Vec::new();
    let mut lineno = 0u64;
    loop {
        buf.clear();
        match (&mut rd).take(MAX_LINE_BYTES).read_until(b'\n', &mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
        lineno += 1;
        let text = String::from_utf8_lossy(&buf);
        let line = text.trim_end_matches(['\n', '\r']);
        copy.records += 1;
        if line.contains("kernel:") && line.contains("Linux version") {
            copy.boot_banner = true;
        }
        let name = extract_load_name(line);
        if lineno <= EPOCH_PROBE_LINES || name.is_some() {
            let epoch = syslog_epoch(line, now);
            if let Some(e) = epoch {
                copy.min_epoch = Some(copy.min_epoch.map_or(e, |m| m.min(e)));
            }
            if let Some(name) = name {
                copy.load_lines.push(LoadLine {
                    name,
                    text: line.chars().take(300).collect(),
                    epoch,
                    seq: None,
                });
            }
        }
    }
}

pub fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let m = needle.len();
    if m == 0 || hay.len() < m {
        return out;
    }
    let mut skip = [m; 256];
    for (i, b) in needle[..m - 1].iter().enumerate() {
        skip[*b as usize] = m - 1 - i;
    }
    let mut i = 0;
    while i + m <= hay.len() {
        if &hay[i..i + m] == needle {
            out.push(i);
        }
        i += skip[hay[i + m - 1] as usize];
    }
    out
}

fn name_before(buf: &[u8], phrase_pos: usize) -> Option<String> {
    let mut start = phrase_pos;
    while start > 0 {
        let c = buf[start - 1];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
            start -= 1;
        } else {
            break;
        }
    }
    let name = std::str::from_utf8(&buf[start..phrase_pos]).ok()?;
    if name.is_empty() || name.len() > 56 {
        None
    } else {
        Some(name.to_string())
    }
}

pub fn scan_stream<R: Read>(mut src: R, names: &mut Vec<String>) -> (bool, u64) {
    const CHUNK: usize = 8 * 1024 * 1024;
    const OVERLAP: usize = 128;
    let banner = b"Linux version ";
    let mut carry: Vec<u8> = Vec::new();
    let mut total = 0u64;
    let mut has_banner = false;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        total += n as u64;
        let mut hay = std::mem::take(&mut carry);
        let carry_len = hay.len();
        hay.extend_from_slice(&buf[..n]);
        if find_all(&hay, banner)
            .iter()
            .any(|p| p + banner.len() > carry_len)
        {
            has_banner = true;
        }
        for ph in PHRASES {
            for pos in find_all(&hay, ph.as_bytes()) {
                if pos + ph.len() <= carry_len {
                    continue;
                }
                if let Some(name) = name_before(&hay, pos) {
                    if !names.contains(&name) && names.len() < MAX_CANDIDATES {
                        names.push(name);
                    }
                }
            }
        }
        let keep = hay.len().min(OVERLAP);
        carry = hay[hay.len() - keep..].to_vec();
    }
    (has_banner, total)
}

pub fn collect_journal() -> LogCopy {
    let mut copy = LogCopy {
        source: "journal".into(),
        ..Default::default()
    };
    let mut names: Vec<String> = Vec::new();
    let mut stack: Vec<std::path::PathBuf> =
        vec!["/run/log/journal".into(), "/var/log/journal".into()];
    let mut bytes = 0u64;
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let path = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".journal") || name.ends_with(".journal~") {
                    match fs::File::open(&path) {
                        Ok(f) => {
                            let (banner, n) = scan_stream(f, &mut names);
                            copy.readable = true;
                            copy.files += 1;
                            copy.boot_banner |= banner;
                            bytes += n;
                        }
                        Err(_) => copy.skipped += 1,
                    }
                }
            }
        }
    }
    copy.records = bytes / 1024;
    copy.load_lines = names
        .into_iter()
        .map(|name| LoadLine {
            text: format!("{}: （systemd 日誌裡的載入訊息）", name),
            name,
            epoch: None,
            seq: None,
        })
        .collect();
    copy
}

pub fn candidate_names(logs: &[LogCopy]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for lg in logs {
        for ll in &lg.load_lines {
            seen.insert(ll.name.clone());
        }
    }
    seen.into_iter().take(MAX_CANDIDATES).collect()
}

pub fn check_name(name: &str) -> NameCheck {
    let base = format!("/sys/module/{}", name);
    let stat_ok = fs::metadata(&base).is_ok();
    NameCheck {
        name: name.into(),
        stat_ok,
        initstate: read_trim(&format!("{}/initstate", base)),
        taint: read_trim(&format!("{}/taint", base)),
        text_addr: read_trim(&format!("{}/sections/.text", base)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stat_handles_parens_and_spaces_in_name() {
        let line = "7652 (ktest (wk) fx) D 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 20 0 1 0 7364 0 0 18446744073709551615";
        let (start, ppid, comm) = parse_stat(line).unwrap();
        assert_eq!(start, 7364);
        assert_eq!(ppid, Some(2));
        assert_eq!(comm, "ktest (wk) fx");
    }

    const SCHED_SAMPLE: &str = "\
Sched Debug Version: v0.10, 3.10.0-1160.119.1.el7.x86_64 #1
cpu#0, 2399.998 MHz
  .nr_running                    : 1
  .load                          : 1024

cfs_rq[0]:/
  .exec_clock                    : 0.000000

runnable tasks:
            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep
----------------------------------------------------------------------------------------------------------
     kworker/0:0     3     14162.427254        20   120         0.000000         0.215269         0.000000 0 /
    kworker/0:0H     4     20419.599305        10   100         0.000000         0.135280         0.000000 0 /
R           bash 55555     12.000000       100   120     12.000000       1.000000      2.000000 0 /
 systemd-journal   442     12.000000       100   120     12.000000       1.000000      2.000000 0 /
            1234 77777     12.000000       100   120     12.000000       1.000000      2.000000 0 /
          python 4194303     12.000000       100   120     12.000000       1.000000      2.000000 0 /

cpu#1, 2399.998 MHz
  .nr_running                    : 7
runnable tasks:
            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep
----------------------------------------------------------------------------------------------------------
      watchdog/1    12        -2.994828        19     0         0.000000        59.262552         0.000000 0 /
";

    #[test]
    fn sched_ids_come_from_fixed_columns_not_from_the_first_number() {
        let ids = parse_sched_ids(SCHED_SAMPLE);
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            vec![3, 4, 12, 442, 55555, 77777, 4_194_303],
            "名字是 1234 的工作，編號是 77777；其他區段的數字（.nr_running 等）不能算進來"
        );
        assert!(parse_sched_ids("").is_empty());
        assert!(
            parse_sched_ids("Sched Debug Version: v0.10\ncpu#0\n  .nr_running : 3\n").is_empty()
        );
    }

    const TIMER_SAMPLE: &str = "\
Timer List Version: v0.8
active timers:
 #0: <ffff8e68bfc15f80>, tick_sched_timer, S:01, hrtimer_start, swapper/0/0
 # expires at 66537000000-66537000000 nsecs [in 1657656 to 1657656 nsecs]
 #1: <ffff8e68adacf8d8>, hrtimer_wakeup, S:01, schedule_hrtimeout_range_clock, tuned/866
 # expires at 66822890797-66823890795 nsecs [in 287548453 to 288548451 nsecs]
 #2: <ffff8e68bfc16160>, watchdog_timer_fn, S:01, hrtimer_start, watchdog/0/11
 #3: <ffff8e68330d78d8>, hrtimer_wakeup, S:01, schedule_hrtimeout_range_clock, tstprc/8721
 #4: <ffff8e68330d7aaa>, it_real_fn, S:01, hrtimer_start, kworker/u2:1/9
 #5: <ffff8e68330d7bbb>, nameless, S:01, hrtimer_start
";

    #[test]
    fn timer_ids_are_the_trailing_name_slash_number_of_timer_lines_only() {
        let ids = parse_timer_ids(TIMER_SAMPLE);
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            vec![9, 11, 866, 8721],
            "swapper/0/0 的 0 不算；「# expires …」那一列不算；沒有名字／編號的不算"
        );
        assert!(parse_timer_ids("").is_empty());
    }

    #[test]
    fn extract_load_name_from_kernel_lines() {
        assert_eq!(
            extract_load_name("testmod: loading out-of-tree module taints kernel.").as_deref(),
            Some("testmod")
        );
        assert_eq!(
            extract_load_name(
                "Oct 14 08:33:06 centos7-web kernel: test-mod_x: module verification failed: signature and/or required key missing - tainting kernel"
            )
            .as_deref(),
            Some("test-mod_x")
        );
        assert_eq!(
            extract_load_name("systemd[1]: Started Session 3 of user root."),
            None
        );
        assert_eq!(extract_load_name(": module verification failed"), None);
    }

    #[test]
    fn find_all_handles_edges() {
        assert_eq!(find_all(b"abcabcab", b"abc"), vec![0, 3]);
        assert_eq!(find_all(b"aaaa", b"aa"), vec![0, 1, 2]);
        assert!(find_all(b"ab", b"abc").is_empty());
        assert!(find_all(b"abc", b"").is_empty());
        assert_eq!(find_all(b"xxabcxx", b"abc"), vec![2]);
    }

    #[test]
    fn scan_stream_finds_names_banner_and_ignores_duplicates() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 50]);
        data.extend_from_slice(b"MESSAGE=Linux version 3.10.0-1160.el7.x86_64 (mockbuild)\0");
        data.extend_from_slice(b"\x01MESSAGE=testmod: loading out-of-tree module taints kernel.\0");
        data.extend_from_slice(
            b"MESSAGE=testmod: module verification failed: signature and/or required key missing\0",
        );
        data.extend_from_slice(b"MESSAGE=other_mod: module verification failed: x\0");
        let mut names = Vec::new();
        let (banner, n) = scan_stream(std::io::Cursor::new(data.clone()), &mut names);
        assert!(banner);
        assert_eq!(n as usize, data.len());
        assert_eq!(names, vec!["testmod".to_string(), "other_mod".to_string()]);
    }

    #[test]
    fn scan_stream_without_banner_or_phrases() {
        let mut names = Vec::new();
        let (banner, _) = scan_stream(
            std::io::Cursor::new(b"nothing to see here".to_vec()),
            &mut names,
        );
        assert!(!banner && names.is_empty());
    }

    #[test]
    fn syslog_epoch_rejects_non_timestamps() {
        assert_eq!(syslog_epoch("not a log line", 1_791_982_917), None);
        assert_eq!(syslog_epoch("Foo 14 13:01:58 h x", 1_791_982_917), None);
    }

    #[test]
    fn parse_stat_rejects_short_lines() {
        assert!(parse_stat("1 (a) S 0").is_none());
        assert!(parse_stat("garbage").is_none());
    }

    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("rkscan-{}-{}", tag, std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
        fn put(&self, name: &str, bytes: &[u8]) {
            fs::write(self.0.join(name), bytes).unwrap();
        }
        fn path(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn messages_stream_reads_lines_crlf_invalid_utf8_and_a_missing_final_newline() {
        let d = TmpDir::new("msgs");
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"Jan  2 03:04:05 h kernel: Linux version 3.10.0-957.1.3.el7\r\n");
        body.extend_from_slice(b"Jan  2 03:04:06 h kernel: \xff\xfe bad bytes line\n");
        body.extend_from_slice(
            b"Jan  2 03:04:07 h kernel: testmod: loading out-of-tree module taints kernel.\n",
        );
        body.extend_from_slice(b"Jan  2 03:04:08 h last line without newline");
        d.put("messages", &body);
        d.put("messages-20260101.gz", b"not read");
        d.put("other.log", b"not a messages file");
        let c = read_messages_dir(&d.path(), now(), 1 << 20);
        assert!(c.readable && c.boot_banner);
        assert_eq!((c.files, c.records, c.skipped, c.unread), (1, 4, 1, 0));
        assert_eq!(c.load_lines.len(), 1);
        assert_eq!(c.load_lines[0].name, "testmod");
        assert!(c.load_lines[0].epoch.is_some());
        assert!(c.min_epoch.is_some());
    }

    #[test]
    fn messages_over_the_size_limit_are_counted_as_unread_not_silently_dropped() {
        let d = TmpDir::new("big");
        d.put(
            "messages",
            b"Jan  2 03:04:05 h kernel: Linux version 3.10.0\n",
        );
        d.put("messages-20260101", &vec![b'x'; 5000]);
        let c = read_messages_dir(&d.path(), now(), 1000);
        assert_eq!((c.files, c.unread, c.skipped), (1, 1, 0));
        assert!(c.readable, "小的那個還是讀了");
    }

    #[test]
    fn a_huge_line_without_newline_is_split_instead_of_eating_memory() {
        let d = TmpDir::new("long");
        d.put("messages", &vec![b'a'; 3 * 1024 * 1024 + 10]);
        let c = read_messages_dir(&d.path(), now(), u64::MAX);
        assert_eq!(
            c.records, 4,
            "每 1 MiB 拆成一行：3 個整塊加最後的 10 位元組"
        );
        assert_eq!(c.unread, 0);
    }

    #[test]
    fn only_the_first_lines_of_a_file_are_parsed_for_the_earliest_time() {
        let d = TmpDir::new("probe");
        let mut body = String::new();
        for _ in 0..EPOCH_PROBE_LINES {
            body.push_str("not a timestamp line\n");
        }
        body.push_str("Jan  2 03:04:05 h kernel: ordinary line far from the start\n");
        body.push_str("Jan  2 03:04:06 h kernel: testmod: module verification failed\n");
        d.put("messages", body.as_bytes());
        let c = read_messages_dir(&d.path(), now(), u64::MAX);
        assert_eq!(c.load_lines.len(), 1);
        assert!(
            c.load_lines[0].epoch.is_some(),
            "載入訊息那一行一定解析時間"
        );
        assert_eq!(
            c.min_epoch, c.load_lines[0].epoch,
            "遠處普通行的時間戳沒被解析"
        );
    }
}
