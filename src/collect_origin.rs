use crate::model::{
    AuditLogin, FileInfo, OriginData, OriginFacts, ProcEvidence, RawFile, RawFileFact, RawLookup,
    SessionFile, ID_UNSET, RAW_CONTENT_MAX,
};
use crate::mounts::{self, MountEntry};
use crate::rawfs::{Inode, RawFs};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::MetadataExt;

const MAX_ENV_BYTES: u64 = 1 << 20;
const MAX_AUDIT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_LINE_BYTES: u64 = 1024 * 1024;
const MAX_EXE_BYTES: u64 = 512 * 1024 * 1024;
const AUDIT_DIR: &str = "/var/log/audit";
const SESSION_DIR: &str = "/run/systemd/sessions";
pub const UNIT_DIRS: [&str; 4] = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
];

fn read_u32(path: &str) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub fn systemd_cgroup_path(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let mut it = l.splitn(3, ':');
        it.next()?;
        (it.next()? == "name=systemd").then(|| it.next().unwrap_or("").to_string())
    })
}

pub fn ssh_env(block: &[u8]) -> (Option<String>, Option<String>) {
    let mut conn = None;
    let mut tty = None;
    for item in block.split(|&b| b == 0) {
        if let Some(v) = item.strip_prefix(b"SSH_CONNECTION=") {
            conn = Some(String::from_utf8_lossy(v).into_owned());
        } else if let Some(v) = item.strip_prefix(b"SSH_TTY=") {
            tty = Some(String::from_utf8_lossy(v).into_owned());
        }
    }
    (conn, tty)
}

pub fn parse_session_file(text: &str) -> SessionFile {
    let mut f = SessionFile::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.to_string();
        match k {
            "USER" => f.user = Some(v),
            "SERVICE" => f.service = Some(v),
            "TYPE" => f.kind = Some(v),
            "REMOTE_HOST" => f.remote_host = Some(v),
            "TTY" => f.tty = Some(v),
            "STATE" => f.state = Some(v),
            "REALTIME" => f.realtime_us = v.parse().ok(),
            _ => {}
        }
    }
    f
}

fn find_unit_files(unit: &str) -> Vec<String> {
    UNIT_DIRS
        .iter()
        .map(|d| format!("{}/{}", d, unit))
        .filter(|p| fs::symlink_metadata(p).is_ok())
        .collect()
}

pub fn errno_name(code: Option<i32>) -> String {
    match code {
        Some(1) => "EPERM".into(),
        Some(2) => "ENOENT".into(),
        Some(3) => "ESRCH".into(),
        Some(5) => "EIO".into(),
        Some(13) => "EACCES".into(),
        Some(20) => "ENOTDIR".into(),
        Some(40) => "ELOOP".into(),
        Some(n) => format!("errno {}", n),
        None => "未知錯誤".into(),
    }
}

pub struct StatusIds {
    pub uid: Option<(u32, u32)>,
    pub gid: Option<(u32, u32)>,
    pub tracer_pid: Option<u32>,
}

pub fn parse_status(text: &str) -> StatusIds {
    let pair = |rest: &str| -> Option<(u32, u32)> {
        let mut it = rest.split_whitespace();
        let real = it.next()?.parse().ok()?;
        let eff = it.next()?.parse().ok()?;
        Some((real, eff))
    };
    let (mut uid, mut gid, mut tracer) = (None, None, None);
    for line in text.lines() {
        if let Some(r) = line.strip_prefix("Uid:") {
            uid = pair(r);
        } else if let Some(r) = line.strip_prefix("Gid:") {
            gid = pair(r);
        } else if let Some(r) = line.strip_prefix("TracerPid:") {
            tracer = r.trim().parse().ok();
        }
    }
    StatusIds {
        uid,
        gid,
        tracer_pid: tracer,
    }
}

pub fn hash_reader<R: Read>(mut src: R, limit: u64) -> Result<(u64, String), String> {
    let mut h = crate::sha256::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(format!("讀取失敗：{}", errno_name(e.raw_os_error()))),
        };
        total += n as u64;
        if total > limit {
            return Err(format!(
                "超過 {} MiB 的上限，沒有算指紋",
                limit / 1024 / 1024
            ));
        }
        h.update(&buf[..n]);
    }
    Ok((total, h.finalize_hex()))
}

pub fn collect_proc_evidence(pid: u32) -> ProcEvidence {
    let base = format!("/proc/{}", pid);
    let ids = fs::read_to_string(format!("{}/status", base)).map(|t| parse_status(&t));
    let mut ev = ProcEvidence {
        pid,
        uid: ids.as_ref().ok().and_then(|i| i.uid),
        gid: ids.as_ref().ok().and_then(|i| i.gid),
        tracer_pid: ids.as_ref().ok().and_then(|i| i.tracer_pid),
        ..Default::default()
    };
    let file = match fs::File::open(format!("{}/exe", base)) {
        Ok(f) => f,
        Err(e) => {
            ev.exe_open_error = Some(errno_name(e.raw_os_error()));
            return ev;
        }
    };
    ev.exe_info = Some(match file.metadata() {
        Ok(m) => FileInfo::Ok {
            size: m.size(),
            mtime: m.mtime(),
            ctime: m.ctime(),
            nlink: m.nlink(),
        },
        Err(e) => FileInfo::Err(errno_name(e.raw_os_error())),
    });
    match hash_reader(BufReader::new(file), MAX_EXE_BYTES) {
        Ok((n, hex)) => {
            ev.exe_bytes = Some(n);
            ev.exe_sha256 = Some(hex);
        }
        Err(msg) => ev.exe_read_error = Some(msg),
    }
    ev
}

pub fn scanner_sha256() -> Option<String> {
    let f = fs::File::open("/proc/self/exe").ok()?;
    hash_reader(BufReader::new(f), MAX_EXE_BYTES)
        .ok()
        .map(|(_, h)| h)
}

pub fn collect_origin(pid: u32) -> OriginFacts {
    let base = format!("/proc/{}", pid);
    let loginuid = read_u32(&format!("{}/loginuid", base));
    let sessionid = read_u32(&format!("{}/sessionid", base));
    let cgroup = fs::read_to_string(format!("{}/cgroup", base))
        .ok()
        .and_then(|t| systemd_cgroup_path(&t));
    let mut env = Vec::new();
    if let Ok(f) = fs::File::open(format!("{}/environ", base)) {
        let _ = f.take(MAX_ENV_BYTES).read_to_end(&mut env);
    }
    let (ssh_connection, ssh_tty) = ssh_env(&env);
    let session_file = match sessionid {
        Some(n) if n != ID_UNSET => fs::read_to_string(format!("{}/{}", SESSION_DIR, n))
            .ok()
            .map(|t| parse_session_file(&t)),
        _ => None,
    };
    let mut facts = OriginFacts {
        pid,
        loginuid,
        sessionid,
        cgroup,
        ssh_connection,
        ssh_tty,
        session_file,
        ..Default::default()
    };
    if let Some(unit) = facts.service_unit().map(str::to_string) {
        facts.unit_checked = true;
        facts.unit_files = find_unit_files(&unit);
    }
    facts
}

fn audit_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!(" {}=", key);
    let at = line.find(&pat)? + pat.len();
    let rest = &line[at..];
    let end = rest.find(' ').unwrap_or(rest.len());
    Some(rest[..end].trim_end_matches('\''))
}

fn audit_text(v: &str) -> String {
    if let Some(q) = v.strip_prefix('"') {
        return q.trim_end_matches('"').to_string();
    }
    let b = v.as_bytes();
    if b.len() >= 2 && b.len() % 2 == 0 && b.iter().all(u8::is_ascii_hexdigit) {
        let bytes: Vec<u8> = (0..b.len() / 2)
            .map(|i| u8::from_str_radix(&v[2 * i..2 * i + 2], 16).unwrap_or(b'?'))
            .collect();
        if let Ok(s) = String::from_utf8(bytes) {
            if s.chars().all(|c| !c.is_control()) {
                return s;
            }
        }
    }
    v.to_string()
}

pub fn audit_epoch(line: &str) -> Option<u64> {
    let at = line.find("audit(")? + "audit(".len();
    let digits: String = line[at..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

pub fn parse_audit_login(line: &str) -> Option<AuditLogin> {
    if !line.starts_with("type=USER_LOGIN ") {
        return None;
    }
    if audit_value(line, "res")? != "success" {
        return None;
    }
    Some(AuditLogin {
        ses: audit_value(line, "ses")?.parse().ok()?,
        epoch: audit_epoch(line)?,
        uid: audit_value(line, "uid").and_then(|v| v.parse().ok()),
        exe: audit_value(line, "exe").map(audit_text).unwrap_or_default(),
        hostname: audit_value(line, "hostname")
            .map(str::to_string)
            .unwrap_or_default(),
        addr: audit_value(line, "addr")
            .map(str::to_string)
            .unwrap_or_default(),
        terminal: audit_value(line, "terminal")
            .map(str::to_string)
            .unwrap_or_default(),
    })
}

fn read_audit_stream(
    file: fs::File,
    wanted: &BTreeSet<u32>,
    btime: u64,
    data: &mut OriginData,
) -> bool {
    let mut rd = BufReader::with_capacity(1 << 20, file);
    let mut buf = Vec::new();
    let mut first = true;
    loop {
        buf.clear();
        match (&mut rd).take(MAX_LINE_BYTES).read_until(b'\n', &mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
        let text = String::from_utf8_lossy(&buf);
        let line = text.trim_end_matches(['\n', '\r']);
        if first {
            first = false;
            if let Some(e) = audit_epoch(line) {
                data.audit_min_epoch = Some(data.audit_min_epoch.map_or(e, |m| m.min(e)));
            }
        }
        if !line.starts_with("type=USER_LOGIN ") {
            continue;
        }
        if let Some(l) = parse_audit_login(line) {
            if wanted.contains(&l.ses) && l.epoch >= btime {
                data.audit_logins.push(l);
            }
        }
    }
}

fn collect_audit(wanted: &BTreeSet<u32>, btime: u64, data: &mut OriginData) {
    data.audit_ran = true;
    let Ok(rd) = fs::read_dir(AUDIT_DIR) else {
        return;
    };
    let mut names: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("audit.log"))
        .collect();
    names.sort();
    for name in names {
        if [".gz", ".xz", ".bz2", ".zst"]
            .iter()
            .any(|e| name.ends_with(e))
        {
            data.audit_unread += 1;
            continue;
        }
        let path = format!("{}/{}", AUDIT_DIR, name);
        match fs::metadata(&path) {
            Ok(m) if m.is_file() && m.len() <= MAX_AUDIT_BYTES => {}
            _ => {
                data.audit_unread += 1;
                continue;
            }
        }
        let Ok(file) = fs::File::open(&path) else {
            data.audit_unread += 1;
            continue;
        };
        data.audit_files += 1;
        if !read_audit_stream(file, wanted, btime, data) {
            data.audit_unread += 1;
        }
    }
}

pub fn raw_describe(fs: &dyn RawFs, path: &str, want_content: bool) -> RawLookup {
    match fs.lookup(path, false) {
        Ok(Some(inode)) => RawLookup::Found(describe_inode(
            fs,
            &inode,
            want_content,
            MAX_EXE_BYTES,
            Some(path),
        )),
        Ok(None) => RawLookup::NotFound,
        Err(e) => RawLookup::Unavailable(e.text()),
    }
}

pub fn describe_inode(
    fs: &dyn RawFs,
    inode: &Inode,
    want_content: bool,
    sha_limit: u64,
    follow_path: Option<&str>,
) -> RawFile {
    let kind = if inode.is_regular() {
        'f'
    } else if inode.is_dir() {
        'd'
    } else if inode.is_symlink() {
        'l'
    } else {
        'o'
    };
    let mut f = RawFile {
        ino: inode.ino,
        kind,
        size: inode.size,
        links: inode.links,
        mode: inode.mode as u32 & 0o7777,
        mtime: inode.mtime,
        ctime: inode.ctime,
        crtime: inode.crtime,
        ..Default::default()
    };
    let mut source = None;
    if kind == 'f' {
        source = Some(inode.clone());
    } else if kind == 'l' {
        if let Ok(t) = fs.read_link(inode) {
            f.link_target = Some(String::from_utf8_lossy(&t).to_string());
        }
        if let (true, Some(path)) = (want_content, follow_path) {
            if let Ok(Some(t)) = fs.lookup(path, true) {
                if t.is_regular() {
                    source = Some(t);
                }
            }
        }
    }
    if let Some(src) = source {
        if kind == 'f' && src.size <= sha_limit {
            let mut h = crate::sha256::Sha256::new();
            if fs.read_to(&src, sha_limit, &mut |c| h.update(c)).is_ok() {
                f.sha256 = Some(h.finalize_hex());
            }
        }
        if want_content {
            if let Ok(bytes) = fs.read_data(&src, RAW_CONTENT_MAX as u64 + 1) {
                f.content_truncated = bytes.len() > RAW_CONTENT_MAX;
                let keep = &bytes[..bytes.len().min(RAW_CONTENT_MAX)];
                f.content = Some(String::from_utf8_lossy(keep).to_string());
            }
        }
    }
    f
}

pub fn collect_raw_files(targets: &[(String, bool)]) -> Vec<RawFileFact> {
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .map(|t| mounts::parse_mountinfo(&t))
        .unwrap_or_default();
    let mut opened: OpenedDevs = BTreeMap::new();
    targets
        .iter()
        .map(|(path, want_content)| {
            let vfs_error = fs::symlink_metadata(path)
                .err()
                .map(|e| errno_name(e.raw_os_error()));
            let vfs_missing = vfs_error.is_some();
            let (vfs_content, vfs_content_truncated) = if *want_content && vfs_error.is_none() {
                read_text_capped(path)
            } else {
                (None, false)
            };
            RawFileFact {
                path: path.clone(),
                vfs_error,
                vfs_content,
                vfs_content_truncated,
                raw: raw_lookup_path(&mounts, &mut opened, path, *want_content, vfs_missing),
            }
        })
        .collect()
}

fn read_text_capped(path: &str) -> (Option<String>, bool) {
    let Ok(f) = fs::File::open(path) else {
        return (None, false);
    };
    let mut buf = Vec::new();
    if f.take(RAW_CONTENT_MAX as u64 + 1)
        .read_to_end(&mut buf)
        .is_err()
    {
        return (None, false);
    }
    let truncated = buf.len() > RAW_CONTENT_MAX;
    buf.truncate(RAW_CONTENT_MAX);
    (Some(String::from_utf8_lossy(&buf).to_string()), truncated)
}

pub type OpenedDevs = BTreeMap<(u32, u32), Result<Box<dyn RawFs>, String>>;

pub fn rawfs_for<'a>(
    mounts: &[MountEntry],
    opened: &'a mut OpenedDevs,
    path: &str,
) -> Result<(&'a dyn RawFs, String), String> {
    let Some(m) = mounts::mount_for(mounts, path) else {
        return Err("讀不到掛載資訊（/proc/self/mountinfo）".to_string());
    };
    if !mounts::raw_fs_supported(&m.fstype) {
        return Err(format!(
            "這個路徑放在 {} 檔案系統，{}",
            m.fstype,
            mounts::RAW_FS_ONLY
        ));
    }
    let entry = opened
        .entry((m.major, m.minor))
        .or_insert_with(|| mounts::open_raw_fs(m));
    match entry {
        Ok(fs) => Ok((&**fs, mounts::path_in_fs(m, path))),
        Err(why) => Err(why.clone()),
    }
}

fn raw_lookup_path(
    mounts: &[MountEntry],
    opened: &mut OpenedDevs,
    path: &str,
    want_content: bool,
    vfs_missing: bool,
) -> RawLookup {
    match rawfs_for(mounts, opened, path) {
        Ok((fs, in_fs)) => {
            let found = raw_describe(fs, &in_fs, want_content);
            if vfs_missing && fs.lags_behind_memory() && matches!(found, RawLookup::Found(_)) {
                let cold = crate::collect_disk::xfs_cold_secs() as i64;
                let parent = std::path::Path::new(path).parent();
                if let Some(s) = parent.and_then(crate::collect_disk::dir_stamp) {
                    if crate::collect_disk::now_secs() - s.0 < cold {
                        return RawLookup::Unavailable(format!(
                            "XFS 的磁碟資料會落後：這個路徑的上一層資料夾最近 {} 秒內被修改過，磁碟上的名單可能還沒更新",
                            cold
                        ));
                    }
                }
            }
            found
        }
        Err(why) => RawLookup::Unavailable(why),
    }
}

fn raw_targets(pids: &[u32], items: &[OriginFacts]) -> Vec<(String, bool)> {
    let mut want: BTreeMap<String, bool> = BTreeMap::new();
    for pid in pids {
        if let Ok(p) = fs::read_link(format!("/proc/{}/exe", pid)) {
            let s = p.to_string_lossy().to_string();
            let s = s.strip_suffix(" (deleted)").unwrap_or(&s).to_string();
            want.entry(s).or_insert(false);
        }
    }
    for f in items {
        if let Some(unit) = f.service_unit() {
            for d in UNIT_DIRS {
                want.insert(format!("{}/{}", d, unit), true);
            }
        }
    }
    want.into_iter().collect()
}

pub fn collect_origin_data(pids: &[u32], btime: u64) -> OriginData {
    let mut data = OriginData {
        ran: true,
        items: pids.iter().map(|&p| collect_origin(p)).collect(),
        evidence: pids.iter().map(|&p| collect_proc_evidence(p)).collect(),
        ..Default::default()
    };
    data.raw_files = collect_raw_files(&raw_targets(pids, &data.items));
    let wanted: BTreeSet<u32> = data
        .items
        .iter()
        .filter(|f| f.has_login_identity())
        .filter_map(|f| f.sessionid)
        .filter(|&n| n != ID_UNSET)
        .collect();
    if !wanted.is_empty() {
        collect_audit(&wanted, btime, &mut data);
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_layer_of_cgroup_file() {
        let text = "11:perf_event:/\n1:name=systemd:/user.slice/user-0.slice/session-3.scope\n";
        assert_eq!(
            systemd_cgroup_path(text).as_deref(),
            Some("/user.slice/user-0.slice/session-3.scope")
        );
        assert_eq!(systemd_cgroup_path("11:perf_event:/\n"), None);
        assert_eq!(
            systemd_cgroup_path("1:name=systemd:/\n").as_deref(),
            Some("/")
        );
    }

    #[test]
    fn only_two_ssh_names_survive() {
        let env = b"PATH=/usr/bin\0SECRET_TOKEN=abc\0SSH_CONNECTION=10.0.0.9 51776 10.0.0.1 22\0SSH_TTY=/dev/pts/0\0";
        let (c, t) = ssh_env(env);
        assert_eq!(c.as_deref(), Some("10.0.0.9 51776 10.0.0.1 22"));
        assert_eq!(t.as_deref(), Some("/dev/pts/0"));
        assert_eq!(ssh_env(b"PATH=/usr/bin\0"), (None, None));
    }

    #[test]
    fn session_file_fields() {
        let f = parse_session_file(
            "# comment\nUSER=root\nSERVICE=sshd\nTYPE=tty\nREMOTE_HOST=10.0.0.9\nSTATE=closing\nREALTIME=1793086267544472\nOTHER=x\n",
        );
        assert_eq!(f.user.as_deref(), Some("root"));
        assert_eq!(f.service.as_deref(), Some("sshd"));
        assert_eq!(f.remote_host.as_deref(), Some("10.0.0.9"));
        assert_eq!(f.state.as_deref(), Some("closing"));
        assert_eq!(f.realtime_us, Some(1_793_086_267_544_472));
        assert_eq!(f.tty, None);
    }

    #[test]
    fn audit_login_line_from_sshd() {
        let line = "type=USER_LOGIN msg=audit(1793086267.602:73): pid=4321 uid=0 auid=0 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=login id=0 exe=\"/usr/sbin/sshd\" hostname=203.0.113.7 addr=203.0.113.7 terminal=/dev/pts/0 res=success'";
        let l = parse_audit_login(line).unwrap();
        assert_eq!(l.ses, 2);
        assert_eq!(l.epoch, 1_793_086_267);
        assert_eq!(l.uid, Some(0));
        assert_eq!(l.exe, "/usr/sbin/sshd");
        assert_eq!(l.addr, "203.0.113.7");
        assert_eq!(l.terminal, "/dev/pts/0");
    }

    #[test]
    fn audit_login_failures_and_other_types_are_ignored() {
        let failed = "type=USER_LOGIN msg=audit(1793086267.602:73): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=? addr=1.2.3.4 terminal=ssh res=failed'";
        assert!(parse_audit_login(failed).is_none());
        assert!(parse_audit_login("type=USER_START msg=audit(1.0:1): ses=2 res=success").is_none());
        assert!(parse_audit_login("garbage").is_none());
    }

    #[test]
    fn audit_hex_exe_is_decoded_but_plain_names_are_not() {
        assert_eq!(audit_text("2F7573722F7362696E2F73736864"), "/usr/sbin/sshd");
        assert_eq!(audit_text("\"/usr/sbin/sshd\""), "/usr/sbin/sshd");
        assert_eq!(audit_text("(null)"), "(null)");
        assert_eq!(audit_text("abcd"), "abcd", "解出來是控制字元就不還原");
    }

    #[test]
    fn status_fields() {
        let t = "Name:\tx\nUid:\t1000\t0\t0\t0\nGid:\t5\t6\t7\t8\nTracerPid:\t4242\n";
        let ids = parse_status(t);
        assert_eq!(ids.uid, Some((1000, 0)));
        assert_eq!(ids.gid, Some((5, 6)));
        assert_eq!(ids.tracer_pid, Some(4242));
        let none = parse_status("Name:\tx\n");
        assert!(none.uid.is_none() && none.gid.is_none() && none.tracer_pid.is_none());
    }

    #[test]
    fn raw_describe_reads_unit_file_content_time_and_fingerprint() {
        let fs = crate::rawfs_fixture::open_small();
        let RawLookup::Found(f) = raw_describe(&fs, "/etc/systemd/system/svc.service", true) else {
            panic!("應該找得到");
        };
        assert_eq!(f.kind, 'f');
        assert_eq!(f.crtime, Some(1_773_022_830));
        let text = f.content.clone().unwrap();
        assert!(text.contains("ExecStart=/usr/bin/tool --serve"), "{}", text);
        assert!(!f.content_truncated);
        assert_eq!(f.size as usize, text.len());
        assert_eq!(
            f.sha256.as_deref(),
            Some(crate::sha256::hex_of(text.as_bytes()).as_str())
        );
    }

    #[test]
    fn raw_describe_executable_has_fingerprint_but_no_content() {
        let fs = crate::rawfs_fixture::open_small();
        let RawLookup::Found(f) = raw_describe(&fs, "/usr/bin/tool", false) else {
            panic!("應該找得到");
        };
        assert_eq!(f.size, crate::rawfs_fixture::TOOL_SIZE);
        assert!(f.content.is_none(), "執行檔內容不留");
        let body: Vec<u8> = (0..f.size as usize)
            .map(crate::rawfs_fixture::tool_byte)
            .collect();
        assert_eq!(
            f.sha256.as_deref(),
            Some(crate::sha256::hex_of(&body).as_str())
        );
    }

    #[test]
    fn raw_describe_symlink_reports_target_and_follows_it_for_content() {
        let fs = crate::rawfs_fixture::open_small();
        let p = "/etc/systemd/system/multi-user.target.wants/svc.service";
        let RawLookup::Found(f) = raw_describe(&fs, p, true) else {
            panic!("應該找得到");
        };
        assert_eq!(f.kind, 'l');
        assert_eq!(
            f.link_target.as_deref(),
            Some("/etc/systemd/system/svc.service")
        );
        assert!(f.content.unwrap().contains("[Service]"));
        assert!(f.sha256.is_none(), "連結本身沒有內容指紋");
    }

    #[test]
    fn raw_describe_missing_path_and_directory() {
        let fs = crate::rawfs_fixture::open_small();
        assert_eq!(
            raw_describe(&fs, "/etc/systemd/system/nope.service", true),
            RawLookup::NotFound
        );
        let RawLookup::Found(d) = raw_describe(&fs, "/etc/systemd/system", false) else {
            panic!("目錄應該找得到");
        };
        assert_eq!(d.kind, 'd');
        assert!(d.sha256.is_none() && d.content.is_none());
    }

    #[test]
    fn raw_describe_truncates_long_content() {
        let fs = crate::rawfs_fixture::open_small();
        let RawLookup::Found(f) = raw_describe(&fs, "/usr/bin/tool", true) else {
            panic!("應該找得到");
        };
        assert!(f.content_truncated);
        assert!(!f.content.unwrap().is_empty());
    }

    #[test]
    fn hash_reader_counts_bytes_and_respects_the_limit() {
        let data = vec![b'a'; 1_000_000];
        let (n, h) = hash_reader(&data[..], 10_000_000).unwrap();
        assert_eq!(n, 1_000_000);
        assert_eq!(
            h,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        let err = hash_reader(&data[..], 500_000).unwrap_err();
        assert!(err.contains("上限"), "{}", err);
    }

    #[test]
    fn errno_names() {
        assert_eq!(errno_name(Some(2)), "ENOENT");
        assert_eq!(errno_name(Some(13)), "EACCES");
        assert_eq!(errno_name(Some(999)), "errno 999");
        assert_eq!(errno_name(None), "未知錯誤");
    }

    #[test]
    fn evidence_of_our_own_process_reads_its_exe() {
        let ev = collect_proc_evidence(std::process::id());
        assert!(ev.exe_open_error.is_none(), "{:?}", ev.exe_open_error);
        assert!(
            matches!(ev.exe_info, Some(FileInfo::Ok { .. })),
            "{:?}",
            ev.exe_info
        );
        assert_eq!(ev.exe_sha256.as_deref().map(str::len), Some(64));
        assert!(ev.exe_bytes.unwrap_or(0) > 0);
        assert!(ev.uid.is_some() && ev.tracer_pid.is_some());
        if let Some(FileInfo::Ok { size, .. }) = ev.exe_info {
            assert_eq!(Some(size), ev.exe_bytes, "問到的大小與讀到的位元組數一致");
        }
    }

    #[test]
    fn audit_stream_keeps_only_wanted_sessions_after_boot() {
        let dir = std::env::temp_dir().join(format!("rk-origin-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        let log = "type=USER_LOGIN msg=audit(1000.000:1): pid=1 uid=0 auid=0 ses=2 msg='op=login id=0 exe=\"/usr/sbin/sshd\" hostname=? addr=1.1.1.1 terminal=ssh res=success'\n\
type=USER_LOGIN msg=audit(2000.000:2): pid=1 uid=0 auid=0 ses=2 msg='op=login id=0 exe=\"/usr/sbin/sshd\" hostname=? addr=2.2.2.2 terminal=ssh res=success'\n\
type=USER_LOGIN msg=audit(2001.000:3): pid=1 uid=0 auid=0 ses=9 msg='op=login id=0 exe=\"/usr/sbin/sshd\" hostname=? addr=3.3.3.3 terminal=ssh res=success'\n";
        fs::write(&path, log).unwrap();
        let mut data = OriginData::default();
        let wanted: BTreeSet<u32> = [2].into_iter().collect();
        let done = read_audit_stream(fs::File::open(&path).unwrap(), &wanted, 1500, &mut data);
        fs::remove_dir_all(&dir).unwrap();
        assert!(done);
        assert_eq!(data.audit_min_epoch, Some(1000));
        assert_eq!(
            data.audit_logins.len(),
            1,
            "開機前的同編號事件與別的編號都不收"
        );
        assert_eq!(data.audit_logins[0].addr, "2.2.2.2");
    }
}
