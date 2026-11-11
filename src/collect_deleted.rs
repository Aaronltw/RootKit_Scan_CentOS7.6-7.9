use crate::collect::describe;
use crate::collect_origin::{hash_reader, OpenedDevs};
use crate::model::{DeletedProc, DeletedScan, PathNow, ProcSocket, Proto};
use crate::mounts::{self, MountEntry};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;

pub const MAX_ITEMS: usize = 200;
const MAX_SOCKETS: usize = 50;
const MAX_EXE_BYTES: u64 = 512 * 1024 * 1024;
const STD_DIRS: [&str; 6] = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];
const DELETED_SUFFIX: &str = " (deleted)";

fn visible_pids() -> Vec<u32> {
    let mut v: Vec<u32> = fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
}

pub fn parse_addr(text: &str, v6: bool) -> Option<(String, u16)> {
    let (ip, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if !v6 {
        if ip.len() != 8 {
            return None;
        }
        let w = u32::from_str_radix(ip, 16).ok()?;
        return Some((Ipv4Addr::from(w.to_le_bytes()).to_string(), port));
    }
    if ip.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let w = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let a = Ipv6Addr::from(bytes);
    Some((
        a.to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| a.to_string()),
        port,
    ))
}

#[derive(Default)]
struct Tables {
    by_inode: BTreeMap<u64, ProcSocket>,
    listening_ports: BTreeSet<u16>,
}

fn parse_table(text: &str, proto: Proto, v6: bool, t: &mut Tables) {
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Some((lip, lport)), Some((rip, rport))) = (parse_addr(f[1], v6), parse_addr(f[2], v6))
        else {
            continue;
        };
        let Ok(inode) = f[9].parse::<u64>() else {
            continue;
        };
        if proto == Proto::Tcp && f[3] == "0A" {
            t.listening_ports.insert(lport);
        }
        t.by_inode.insert(
            inode,
            ProcSocket {
                proto,
                v6,
                local_ip: lip,
                local_port: lport,
                remote_ip: rip,
                remote_port: rport,
                state: f[3].to_string(),
                local_port_listening: false,
            },
        );
    }
}

fn read_tables() -> Tables {
    let mut t = Tables::default();
    for (path, proto, v6) in [
        ("/proc/net/tcp", Proto::Tcp, false),
        ("/proc/net/tcp6", Proto::Tcp, true),
        ("/proc/net/udp", Proto::Udp, false),
        ("/proc/net/udp6", Proto::Udp, true),
    ] {
        if let Ok(text) = fs::read_to_string(path) {
            parse_table(&text, proto, v6, &mut t);
        }
    }
    t
}

fn sockets_of(pid: u32, tables: &Tables) -> (Vec<ProcSocket>, bool) {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut capped = false;
    let Ok(rd) = fs::read_dir(format!("/proc/{}/fd", pid)) else {
        return (out, false);
    };
    for e in rd.flatten() {
        let Ok(target) = fs::read_link(e.path()) else {
            continue;
        };
        let target = target.to_string_lossy().to_string();
        let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|x| x.strip_suffix(']'))
            .and_then(|x| x.parse::<u64>().ok())
        else {
            continue;
        };
        if !seen.insert(inode) {
            continue;
        }
        if let Some(row) = tables.by_inode.get(&inode) {
            if out.len() >= MAX_SOCKETS {
                capped = true;
                break;
            }
            let mut s = row.clone();
            s.local_port_listening = tables.listening_ports.contains(&s.local_port);
            out.push(s);
        }
    }
    out.sort_by(|a, b| {
        (
            a.proto,
            &a.local_ip,
            a.local_port,
            &a.remote_ip,
            a.remote_port,
        )
            .cmp(&(
                b.proto,
                &b.local_ip,
                b.local_port,
                &b.remote_ip,
                b.remote_port,
            ))
    });
    (out, capped)
}

fn path_now(path: &str) -> PathNow {
    match fs::metadata(path) {
        Ok(m) if m.is_file() => PathNow::File {
            ino: m.ino(),
            dev: m.dev(),
            ctime: m.ctime(),
            mtime: m.mtime(),
        },
        Ok(_) => PathNow::Other,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => PathNow::Missing,
        Err(_) => PathNow::Unknown,
    }
}

fn find_in_std_dirs(name: &str) -> Option<(String, PathNow)> {
    if name.is_empty() || name.contains('/') {
        return None;
    }
    for d in STD_DIRS {
        let p = format!("{}/{}", d, name);
        if let n @ PathNow::File { .. } = path_now(&p) {
            return Some((p, n));
        }
    }
    None
}

pub fn resolve_now(argv0: &str, comm: &str, link_path: &str) -> (String, PathNow) {
    if argv0.starts_with('/') {
        let n = path_now(argv0);
        if n != PathNow::Missing {
            return (argv0.to_string(), n);
        }
        if let Some((first, _)) = argv0.split_once(char::is_whitespace) {
            if first.starts_with('/') {
                let n2 = path_now(first);
                if n2 != PathNow::Missing {
                    return (first.to_string(), n2);
                }
            }
        }
        return (argv0.to_string(), PathNow::Missing);
    }
    let first = argv0
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(':');
    for name in [first, comm] {
        if let Some(found) = find_in_std_dirs(name) {
            return found;
        }
    }
    if link_path.starts_with('/') {
        let n = path_now(link_path);
        if matches!(n, PathNow::File { .. }) {
            return (link_path.to_string(), n);
        }
    }
    let shown = if !first.is_empty() { first } else { comm };
    (shown.to_string(), PathNow::Missing)
}

pub fn split_dev(dev: u64) -> (u32, u32) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major as u32, minor as u32)
}

fn crtime_of(
    mounts: &[MountEntry],
    opened: &mut OpenedDevs,
    dev: u64,
    ino: u64,
    size: u64,
) -> (Option<i64>, Option<String>) {
    let (maj, min) = split_dev(dev);
    let Some(m) = mounts
        .iter()
        .rev()
        .find(|m| m.major == maj && m.minor == min)
    else {
        return (
            None,
            Some("找不到這個檔案放在哪個磁碟（掛載資訊裡沒有）".to_string()),
        );
    };
    if !mounts::raw_fs_supported(&m.fstype) {
        return (
            None,
            Some(format!(
                "這個檔案放在 {} 檔案系統，{}，讀不到建立時間",
                m.fstype,
                mounts::RAW_FS_ONLY
            )),
        );
    }
    let entry = opened
        .entry((m.major, m.minor))
        .or_insert_with(|| mounts::open_raw_fs(m));
    match entry {
        Err(why) => (None, Some(why.clone())),
        Ok(fs) => match fs.inode(ino) {
            Err(e) => (None, Some(format!("讀不到磁碟上的紀錄：{}", e.text()))),
            Ok(inode) => {
                if !inode.is_regular() || inode.size != size {
                    (
                        None,
                        Some("磁碟上這個編號的紀錄和系統說的對不上，不採用".to_string()),
                    )
                } else if let Some(c) = inode.crtime {
                    (Some(c), None)
                } else {
                    (
                        None,
                        Some(if m.fstype == "xfs" {
                            "這個 XFS 是舊格式（V4），磁碟上沒有記建立時間".to_string()
                        } else {
                            "這個磁碟的 inode 太小，沒有建立時間欄位".to_string()
                        }),
                    )
                }
            }
        },
    }
}

fn read_uid(pid: u32) -> Option<u32> {
    let s = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

fn read_argv0(pid: u32) -> (String, String) {
    let raw = fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
    let first = raw.split(|&b| b == 0).next().unwrap_or(&[]);
    let full: String = String::from_utf8_lossy(&raw)
        .replace('\0', " ")
        .trim()
        .to_string();
    (
        String::from_utf8_lossy(first).trim().to_string(),
        full.chars().take(400).collect(),
    )
}

pub fn collect_deleted_scan() -> DeletedScan {
    let mut scan = DeletedScan {
        ran: true,
        ..Default::default()
    };
    let my_pid = std::process::id();
    let my_ns = fs::read_link("/proc/self/ns/mnt").ok();
    let tables = read_tables();
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .map(|t| mounts::parse_mountinfo(&t))
        .unwrap_or_default();
    let mut opened: OpenedDevs = BTreeMap::new();
    let mut hashed: BTreeMap<(u64, u64), (Option<String>, Option<String>)> = BTreeMap::new();
    let mut crtimes: BTreeMap<(u64, u64), (Option<i64>, Option<String>)> = BTreeMap::new();
    for pid in visible_pids() {
        let Ok(link) = fs::read_link(format!("/proc/{}/exe", pid)) else {
            continue;
        };
        scan.checked += 1;
        if pid == my_pid {
            continue;
        }
        let exe_link = link.to_string_lossy().to_string();
        if !exe_link.ends_with(DELETED_SUFFIX) {
            continue;
        }
        let same_ns =
            my_ns.is_some() && fs::read_link(format!("/proc/{}/ns/mnt", pid)).ok() == my_ns;
        if !same_ns {
            scan.other_ns += 1;
            continue;
        }
        if scan.items.len() >= MAX_ITEMS {
            scan.omitted += 1;
            continue;
        }
        let info = describe(pid, false, false, false, false);
        let (argv0, cmdline) = read_argv0(pid);
        let link_path = exe_link
            .strip_suffix(DELETED_SUFFIX)
            .unwrap_or(&exe_link)
            .to_string();
        let rooted_here = fs::read_link(format!("/proc/{}/root", pid))
            .map(|r| r.to_string_lossy() == "/")
            .unwrap_or(false);
        let (argv0_path, argv0_now, link_now) = if rooted_here {
            let (p, n) = resolve_now(&argv0, &info.comm, &link_path);
            (p, n, path_now(&link_path))
        } else {
            (argv0.clone(), PathNow::Unknown, PathNow::Unknown)
        };
        let mut d = DeletedProc {
            pid,
            ppid: info.ppid.unwrap_or(0),
            uid: read_uid(pid),
            comm: info.comm,
            argv0,
            cmdline,
            exe_link,
            starttime: info.starttime,
            argv0_path,
            argv0_now,
            link_now,
            same_ns,
            ..Default::default()
        };
        if let Ok(m) = fs::metadata(format!("/proc/{}/exe", pid)) {
            d.fstat_ok = true;
            d.ino = m.ino();
            d.dev = m.dev();
            d.nlink = m.nlink();
            d.size = m.size();
            d.mtime = m.mtime();
            d.ctime = m.ctime();
            let key = (d.dev, d.ino);
            let (sha, note) = hashed.entry(key).or_insert_with(|| {
                match fs::File::open(format!("/proc/{}/exe", pid)) {
                    Err(e) => (None, Some(format!("打不開程式檔：{}", e))),
                    Ok(f) => match hash_reader(BufReader::new(f), MAX_EXE_BYTES) {
                        Ok((_, hex)) => (Some(hex), None),
                        Err(why) => (None, Some(why)),
                    },
                }
            });
            d.sha256 = sha.clone();
            d.sha_note = note.clone();
            let (cr, why) = crtimes
                .entry(key)
                .or_insert_with(|| crtime_of(&mounts, &mut opened, d.dev, d.ino, d.size));
            d.crtime = *cr;
            d.crtime_note = why.clone();
        }
        let (socks, capped) = sockets_of(pid, &tables);
        d.sockets = socks;
        d.sockets_capped = capped;
        scan.items.push(d);
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_address_is_little_endian_hex() {
        assert_eq!(
            parse_addr("0109090A:8C6A", false),
            Some(("10.9.9.1".to_string(), 35946))
        );
        assert_eq!(
            parse_addr("3209090A:480B", false),
            Some(("10.9.9.50".to_string(), 18443))
        );
        assert_eq!(
            parse_addr("0100007F:0050", false),
            Some(("127.0.0.1".to_string(), 80))
        );
        assert_eq!(parse_addr("zz:50", false), None);
        assert_eq!(parse_addr("0100007F", false), None);
    }

    #[test]
    fn ipv6_address_is_four_little_endian_words_and_mapped_v4_is_shown_as_v4() {
        assert_eq!(
            parse_addr("00000000000000000000000001000000:0050", true),
            Some(("::1".to_string(), 80))
        );
        assert_eq!(
            parse_addr("0000000000000000FFFF00000109090A:01BB", true),
            Some(("10.9.9.1".to_string(), 443))
        );
        assert_eq!(
            parse_addr("B80D0120000000000000000001000000:0050", true),
            Some(("2001:db8::1".to_string(), 80))
        );
        assert_eq!(parse_addr("00:50", true), None);
    }

    #[test]
    fn table_rows_become_sockets_and_listening_ports_are_collected() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 ffff 100 0 0 10 0\n\
   1: 0109090A:8C6A 3209090A:480B 02 00000000:00000001 00:00000000 00000000     0        0 26004 1 ffff 100 0 0 10 0\n";
        let mut t = Tables::default();
        parse_table(text, Proto::Tcp, false, &mut t);
        assert!(t.listening_ports.contains(&22));
        assert!(!t.listening_ports.contains(&35946));
        let s = &t.by_inode[&26004];
        assert_eq!(
            (
                s.local_port,
                s.remote_ip.as_str(),
                s.remote_port,
                s.state.as_str()
            ),
            (35946, "10.9.9.50", 18443, "02")
        );
        let mut t2 = Tables::default();
        parse_table("header\nshort line\n", Proto::Tcp, false, &mut t2);
        assert!(t2.by_inode.is_empty());
    }

    #[test]
    fn device_number_split_matches_makedev() {
        for (ma, mi) in [(253u32, 1u32), (8, 1), (259, 3), (8, 300)] {
            assert_eq!(split_dev(mounts::makedev(ma, mi)), (ma, mi));
        }
    }

    #[test]
    fn absolute_start_path_is_authoritative() {
        let (p, n) = resolve_now(
            "/nonexistent-dir-xyz/sshd",
            "sshd",
            "/nonexistent-dir-xyz/sshd",
        );
        assert_eq!(p, "/nonexistent-dir-xyz/sshd");
        assert_eq!(n, PathNow::Missing);
        let (_, n) = resolve_now("/bin/sh", "sh", "/bin/sh");
        assert!(matches!(n, PathNow::File { .. }), "{:?}", n);
        assert_eq!(resolve_now("/tmp", "tmp", "/tmp").1, PathNow::Other);
    }

    #[test]
    fn bare_names_are_looked_up_in_standard_dirs_and_process_titles_are_tolerated() {
        let (p, n) = resolve_now("sh", "sh", "/x/sh;1234");
        assert!(matches!(n, PathNow::File { .. }), "{} {:?}", p, n);
        let (_, n) = resolve_now("sh: master process /usr/sbin/sh", "zzz", "/x/y");
        assert!(matches!(n, PathNow::File { .. }), "{:?}", n);
        let (_, n) = resolve_now("", "sh", "/x/y");
        assert!(matches!(n, PathNow::File { .. }), "{:?}", n);
        assert_eq!(
            resolve_now("no-such-prog-xyz", "no-such-prog-xyz", "/x/y").1,
            PathNow::Missing
        );
    }

    #[test]
    fn our_own_process_is_never_listed_and_a_live_scan_runs() {
        let scan = collect_deleted_scan();
        assert!(scan.ran);
        assert!(scan.checked > 0, "至少會檢查到別的行程");
        let me = std::process::id();
        assert!(scan.items.iter().all(|d| d.pid != me));
    }
}
