use crate::collect_origin::{rawfs_for, OpenedDevs};
use crate::model::{ContentMismatch, ContentScan};
use crate::mounts::{self, MountEntry};
use crate::rawfs::{Inode, RawFs};
use crate::sha256::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_ROOTS: [&str; 6] = [
    "/etc",
    "/root",
    "/var/spool/cron",
    "/usr/lib/systemd/system",
    "/usr/local/bin",
    "/usr/local/sbin",
];
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXE_BYTES: u64 = 64 * 1024 * 1024;
pub const GUARD_SECS: i64 = 120;
pub const RECHECK_ROUNDS: u32 = 3;
const RECHECK_GAP_MS: u64 = 100;
const MAX_FILES_PER_ROOT: usize = 50_000;
const MAX_DEPTH: u32 = 16;

struct Cand {
    path: String,
    cap: u64,
    vfs: (u64, String),
    raw: (u64, String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum VfsRead {
    Hash(u64, String),
    TooBig,
    Unreadable,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Same,
    Recent,
    Big,
    Unreadable,
    Skip,
    Differ {
        vfs: (u64, String),
        raw: (u64, String),
    },
}

pub fn vfs_read(path: &str, cap: u64) -> VfsRead {
    let Ok(f) = fs::File::open(path) else {
        return VfsRead::Unreadable;
    };
    let mut h = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    let mut r = f;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if total > cap {
                    return VfsRead::TooBig;
                }
                h.update(&buf[..n]);
            }
            Err(_) => return VfsRead::Unreadable,
        }
    }
    VfsRead::Hash(total, h.finalize_hex())
}

fn raw_hash(fs: &dyn RawFs, inode: &Inode, cap: u64) -> Option<(u64, String)> {
    let mut h = Sha256::new();
    let n = fs.read_to(inode, cap, &mut |c| h.update(c)).ok()?;
    Some((n, h.finalize_hex()))
}

fn live_recent(path: &str, now: i64) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).is_ok_and(|m| now - m.mtime().max(m.ctime()) < GUARD_SECS)
}

fn same_inode_as_live(fs: &dyn RawFs, in_fs: &str, path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(Some(raw)), Ok(live)) = (fs.lookup(in_fs, true), fs::metadata(path)) else {
        return true;
    };
    raw.ino == live.ino()
}

pub fn compare_one(
    fs: &dyn RawFs,
    in_fs: &str,
    cap: u64,
    now: i64,
    vfs: &dyn Fn(u64) -> VfsRead,
) -> Outcome {
    let Ok(Some(inode)) = fs.lookup(in_fs, true) else {
        return Outcome::Skip;
    };
    if !inode.is_regular() {
        return Outcome::Skip;
    }
    if inode.size > cap {
        return Outcome::Big;
    }
    if now - inode.mtime.max(inode.ctime) < GUARD_SECS {
        return Outcome::Recent;
    }
    let v = match vfs(cap) {
        VfsRead::Hash(n, h) => (n, h),
        VfsRead::TooBig => return Outcome::Big,
        VfsRead::Unreadable => return Outcome::Unreadable,
    };
    let Some(r) = raw_hash(fs, &inode, cap) else {
        return Outcome::Skip;
    };
    if v == r {
        Outcome::Same
    } else {
        Outcome::Differ { vfs: v, raw: r }
    }
}

pub fn first_diff(a: &[u8], b: &[u8]) -> Option<u64> {
    let n = a.len().min(b.len());
    for i in 0..n {
        if a[i] != b[i] {
            return Some(i as u64);
        }
    }
    if a.len() == b.len() {
        None
    } else {
        Some(n as u64)
    }
}

fn list_regular(
    fs: &dyn RawFs,
    dir: &Inode,
    visible: &str,
    mount_points: &HashSet<String>,
    depth: u32,
    out: &mut Vec<String>,
    unreadable_names: &mut usize,
) {
    if depth > MAX_DEPTH || out.len() >= MAX_FILES_PER_ROOT {
        return;
    }
    let Ok(entries) = fs.read_dir(dir) else {
        return;
    };
    for e in entries {
        if e.name == b"." || e.name == b".." {
            continue;
        }
        let Ok(name) = String::from_utf8(e.name.clone()) else {
            *unreadable_names += 1;
            continue;
        };
        let child = if visible == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", visible, name)
        };
        let ftype = if e.file_type == 0 {
            match fs.inode(e.ino) {
                Ok(i) if i.is_dir() => 2,
                Ok(i) if i.is_regular() => 1,
                _ => 0,
            }
        } else {
            e.file_type
        };
        match ftype {
            1 => out.push(child),
            2 if !mount_points.contains(&child) => {
                if let Ok(sub) = fs.inode(e.ino) {
                    list_regular(
                        fs,
                        &sub,
                        &child,
                        mount_points,
                        depth + 1,
                        out,
                        unreadable_names,
                    );
                }
            }
            _ => {}
        }
    }
}

fn running_exe_paths() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return set;
    };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(p) = fs::read_link(format!("/proc/{}/exe", pid)) {
            let s = p.to_string_lossy().to_string();
            if !s.ends_with(" (deleted)") {
                set.insert(s);
            }
        }
    }
    set
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn collect_content_scan(extra_roots: &[String]) -> ContentScan {
    let mut scan = ContentScan {
        ran: true,
        ..Default::default()
    };
    let mounts: Vec<MountEntry> = fs::read_to_string("/proc/self/mountinfo")
        .map(|t| mounts::parse_mountinfo(&t))
        .unwrap_or_default();
    let mount_points: HashSet<String> = mounts.iter().map(|m| m.mount_point.clone()).collect();
    let mut opened: OpenedDevs = BTreeMap::new();

    let mut roots: Vec<String> = DEFAULT_ROOTS.iter().map(|s| s.to_string()).collect();
    if let Ok(rd) = fs::read_dir("/home") {
        let mut homes: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(|n| format!("/home/{}/.ssh", n)))
            .collect();
        homes.sort();
        roots.extend(homes);
    }
    roots.extend(extra_roots.iter().cloned());
    let mut seen = HashSet::new();
    roots.retain(|r| seen.insert(r.clone()));

    let mut targets: BTreeMap<String, u64> = BTreeMap::new();
    let mut skipped_names = 0usize;
    for root in &roots {
        if fs::symlink_metadata(root).is_err() {
            continue;
        }
        scan.roots.push(root.clone());
        match rawfs_for(&mounts, &mut opened, root) {
            Err(why) => scan.unavailable.push(format!("{}：{}", root, why)),
            Ok((efs, in_fs)) => {
                let Ok(Some(dir)) = efs.lookup(&in_fs, true) else {
                    continue;
                };
                if !dir.is_dir() {
                    continue;
                }
                let mut files = Vec::new();
                list_regular(
                    efs,
                    &dir,
                    root,
                    &mount_points,
                    0,
                    &mut files,
                    &mut skipped_names,
                );
                for f in files {
                    targets.entry(f).or_insert(MAX_FILE_BYTES);
                }
            }
        }
    }
    for exe in running_exe_paths() {
        targets.insert(exe, MAX_EXE_BYTES);
    }
    scan.skipped_unreadable += skipped_names;

    let now = now_secs();
    let mut cands: Vec<Cand> = Vec::new();
    for (path, cap) in &targets {
        let Ok((efs, in_fs)) = rawfs_for(&mounts, &mut opened, path) else {
            continue;
        };
        let p = path.clone();
        if live_recent(path, now)
            || (efs.lags_behind_memory() && !same_inode_as_live(efs, &in_fs, path))
        {
            scan.skipped_recent += 1;
            continue;
        }
        match compare_one(efs, &in_fs, *cap, now, &|c| vfs_read(&p, c)) {
            Outcome::Same => scan.checked += 1,
            Outcome::Recent => scan.skipped_recent += 1,
            Outcome::Big => scan.skipped_big += 1,
            Outcome::Unreadable => scan.skipped_unreadable += 1,
            Outcome::Skip => {}
            Outcome::Differ { vfs, raw } => {
                scan.checked += 1;
                cands.push(Cand {
                    path: path.clone(),
                    cap: *cap,
                    vfs,
                    raw,
                });
            }
        }
    }
    scan.candidates = cands.len();

    for _ in 0..RECHECK_ROUNDS {
        if cands.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(RECHECK_GAP_MS));
        let now = now_secs();
        cands.retain(|c| {
            let Ok((efs, in_fs)) = rawfs_for(&mounts, &mut opened, &c.path) else {
                return false;
            };
            let p = c.path.clone();
            !live_recent(&c.path, now)
                && (!efs.lags_behind_memory() || same_inode_as_live(efs, &in_fs, &c.path))
                && matches!(
                    compare_one(efs, &in_fs, c.cap, now, &|cap| vfs_read(&p, cap)),
                    Outcome::Differ { vfs, raw } if vfs == c.vfs && raw == c.raw
                )
        });
    }
    scan.vanished = scan.candidates - cands.len();

    for c in cands {
        let Cand {
            path,
            cap,
            vfs,
            raw,
        } = c;
        let mut item = ContentMismatch {
            path: path.clone(),
            vfs_size: vfs.0,
            vfs_sha256: vfs.1,
            raw_size: raw.0,
            raw_sha256: raw.1,
            first_diff: None,
        };
        if cap <= MAX_FILE_BYTES && vfs.0 <= MAX_FILE_BYTES && raw.0 <= MAX_FILE_BYTES {
            if let (Ok(a), Ok((efs, in_fs))) =
                (fs::read(&path), rawfs_for(&mounts, &mut opened, &path))
            {
                if let Ok(Some(inode)) = efs.lookup(&in_fs, true) {
                    if let Ok(b) = efs.read_data(&inode, cap) {
                        item.first_diff = first_diff(&a, &b);
                    }
                }
            }
        }
        scan.items.push(item);
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rawfs_fixture::{open_small, tool_byte, TOOL_SIZE};

    fn honest(bytes: Vec<u8>) -> impl Fn(u64) -> VfsRead {
        move |_| VfsRead::Hash(bytes.len() as u64, crate::sha256::hex_of(&bytes))
    }

    fn tool() -> Vec<u8> {
        (0..TOOL_SIZE as usize).map(tool_byte).collect()
    }

    const LATER: i64 = 1_800_000_000;

    #[test]
    fn identical_content_on_both_sides_is_the_same() {
        let fs = open_small();
        let out = compare_one(&fs, "/usr/bin/tool", MAX_FILE_BYTES, LATER, &honest(tool()));
        assert_eq!(out, Outcome::Same);
    }

    #[test]
    fn content_that_differs_is_reported_with_both_sizes_and_fingerprints() {
        let fs = open_small();
        let mut cut = tool();
        cut.truncate(cut.len() - 57);
        let out = compare_one(
            &fs,
            "/usr/bin/tool",
            MAX_FILE_BYTES,
            LATER,
            &honest(cut.clone()),
        );
        match out {
            Outcome::Differ { vfs, raw } => {
                assert_eq!(vfs.0, TOOL_SIZE - 57);
                assert_eq!(raw.0, TOOL_SIZE);
                assert_eq!(vfs.1, crate::sha256::hex_of(&cut));
                assert_eq!(raw.1, crate::sha256::hex_of(&tool()));
            }
            other => panic!("應該不一致：{:?}", other),
        }
        let mut flip = tool();
        flip[1234] ^= 0xFF;
        assert!(matches!(
            compare_one(&fs, "/usr/bin/tool", MAX_FILE_BYTES, LATER, &honest(flip)),
            Outcome::Differ { .. }
        ));
    }

    #[test]
    fn recently_modified_big_unreadable_and_missing_files_are_skipped_not_reported() {
        let fs = open_small();
        let inode = fs.lookup("/usr/bin/tool", true).unwrap().unwrap();
        let just_after = inode.mtime.max(inode.ctime) + 10;
        assert_eq!(
            compare_one(
                &fs,
                "/usr/bin/tool",
                MAX_FILE_BYTES,
                just_after,
                &honest(tool())
            ),
            Outcome::Recent
        );
        assert_eq!(
            compare_one(&fs, "/usr/bin/tool", 100, LATER, &honest(tool())),
            Outcome::Big
        );
        assert_eq!(
            compare_one(&fs, "/usr/bin/tool", MAX_FILE_BYTES, LATER, &|_| {
                VfsRead::Unreadable
            }),
            Outcome::Unreadable
        );
        assert_eq!(
            compare_one(&fs, "/usr/bin/nope", MAX_FILE_BYTES, LATER, &honest(vec![])),
            Outcome::Skip
        );
        assert_eq!(
            compare_one(&fs, "/usr/bin", MAX_FILE_BYTES, LATER, &honest(vec![])),
            Outcome::Skip
        );
    }

    #[test]
    fn first_difference_position() {
        assert_eq!(first_diff(b"abcdef", b"abcdef"), None);
        assert_eq!(first_diff(b"abcdef", b"abXdef"), Some(2));
        assert_eq!(
            first_diff(b"abc", b"abcdef"),
            Some(3),
            "一邊是另一邊的前綴：從較短那段的尾端開始不同"
        );
        assert_eq!(first_diff(b"", b"x"), Some(0));
    }

    #[test]
    fn regular_files_are_collected_through_symlinks_and_mount_points_are_not_entered() {
        let fs = open_small();
        let etc = fs.lookup("/etc", true).unwrap().unwrap();
        let mut out = Vec::new();
        let mut bad = 0;
        list_regular(&fs, &etc, "/etc", &HashSet::new(), 0, &mut out, &mut bad);
        assert_eq!(out, vec!["/etc/systemd/system/svc.service"]);
        let mut out2 = Vec::new();
        let mp: HashSet<String> = ["/etc/systemd".to_string()].into_iter().collect();
        list_regular(&fs, &etc, "/etc", &mp, 0, &mut out2, &mut bad);
        assert!(out2.is_empty());
        assert_eq!(bad, 0);
    }

    #[test]
    fn a_live_scan_of_a_directory_that_is_not_ext4_reports_why() {
        let scan = collect_content_scan(&[]);
        assert!(scan.ran);
        assert!(scan.items.is_empty(), "{:?}", scan.items);
    }
}
