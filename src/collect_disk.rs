use crate::collect_origin::{describe_inode, errno_name};
use crate::model::{
    DirCover, DiskDevice, DiskScan, DiskStatus, DiskWalk, HiddenFile, ProcCover, COVER_NAMES_MAX,
    HIDDEN_CHILDREN_MAX, HIDDEN_FILES_MAX, UNSETTLED_DIRS_MAX,
};
use crate::mounts::{self, MountEntry};
use crate::rawfs::RawFs;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const WALK_MAX_SECS: u64 = 180;
pub const RECHECK_ROUNDS: u32 = 3;
const RECHECK_GAP_MS: u64 = 100;
pub const XFS_COLD_EXTRA_SECS: u64 = 30;
const XFS_DEFAULT_SYNCD_SECS: u64 = 30;
const XFS_COLD_MAX_SECS: u64 = 600;

pub fn xfs_cold_secs() -> u64 {
    let base = fs::read_to_string("/proc/sys/fs/xfs/xfssyncd_centisecs")
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .map(|c| c.div_ceil(100))
        .unwrap_or(XFS_DEFAULT_SYNCD_SECS);
    (base * 2 + XFS_COLD_EXTRA_SECS).min(XFS_COLD_MAX_SECS)
}

pub fn dir_stamp(path: &Path) -> Option<(i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).ok()?;
    Some(
        if (m.mtime(), m.mtime_nsec()) >= (m.ctime(), m.ctime_nsec()) {
            (m.mtime(), m.mtime_nsec())
        } else {
            (m.ctime(), m.ctime_nsec())
        },
    )
}

const HIDDEN_SHA_LIMIT: u64 = 64 * 1024 * 1024;
const PSEUDO_FS: [&str; 26] = [
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "cgroup",
    "cgroup2",
    "pstore",
    "securityfs",
    "selinuxfs",
    "debugfs",
    "hugetlbfs",
    "mqueue",
    "configfs",
    "fusectl",
    "binfmt_misc",
    "autofs",
    "rpc_pipefs",
    "nfsd",
    "tracefs",
    "bpf",
    "overlay",
    "ramfs",
    "fuse.gvfsd-fuse",
    "efivarfs",
    "squashfs",
];

type DirNames = (HashSet<Vec<u8>>, HashSet<Vec<u8>>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub dir_ino: u64,
    pub dir_visible: PathBuf,
    pub name: Vec<u8>,
    pub ino: u64,
}

fn fill_type(fs: &dyn RawFs, raw: &mut [(Vec<u8>, u64, u8)]) {
    for (_, ino, ftype) in raw.iter_mut() {
        if *ftype != 0 {
            continue;
        }
        if let Ok(i) = fs.inode(*ino) {
            *ftype = match i.mode & 0xF000 {
                0x8000 => 1,
                0x4000 => 2,
                0x2000 => 3,
                0x6000 => 4,
                0x1000 => 5,
                0xC000 => 6,
                0xA000 => 7,
                _ => 0,
            };
        }
    }
}

pub struct WalkOut {
    pub stats: DiskWalk,
    pub candidates: Vec<Candidate>,
    pub covers: Vec<DirCover>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverInfo {
    pub fstype: String,
    pub source: String,
}

pub fn names_that_can_hold_content(raw: &[(Vec<u8>, u64, u8)]) -> Vec<String> {
    let mut v: Vec<String> = raw
        .iter()
        .filter(|(_, _, ftype)| !matches!(*ftype, 3..=6))
        .map(|(n, _, _)| String::from_utf8_lossy(n).to_string())
        .collect();
    v.sort();
    v
}

pub fn proc_covers(mounts: &[MountEntry]) -> Vec<ProcCover> {
    let mut out = Vec::new();
    for m in mounts {
        let Some(rest) = m.mount_point.strip_prefix("/proc/") else {
            continue;
        };
        let first = rest.split('/').next().unwrap_or("");
        if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(pid) = first.parse::<u32>() {
            out.push(ProcCover {
                mount_point: m.mount_point.clone(),
                pid,
                fstype: m.fstype.clone(),
                source: m.source.clone(),
                alive: false,
            });
        }
    }
    out
}

fn join(dir: &Path, name: &[u8]) -> PathBuf {
    dir.join(OsStr::from_bytes(name))
}

fn raw_names(fs: &dyn RawFs, dir_ino: u64) -> Option<Vec<(Vec<u8>, u64, u8)>> {
    let inode = fs.inode(dir_ino).ok()?;
    let entries = fs.read_dir(&inode).ok()?;
    Some(
        entries
            .into_iter()
            .filter(|e| e.name != b"." && e.name != b"..")
            .map(|e| (e.name, e.ino, e.file_type))
            .collect(),
    )
}

pub fn walk_device(
    fs: &dyn RawFs,
    mount_point: &Path,
    skip: &dyn Fn(&Path) -> Option<CoverInfo>,
    lister: &dyn Fn(&Path) -> Option<Vec<Vec<u8>>>,
    deadline: Instant,
) -> WalkOut {
    let mut stats = DiskWalk::default();
    let mut candidates = Vec::new();
    let mut covers = Vec::new();
    let mut stack: Vec<(u64, PathBuf)> = vec![(fs.root_ino(), mount_point.to_path_buf())];
    while let Some((ino, visible)) = stack.pop() {
        if Instant::now() > deadline {
            stats.truncated = true;
            break;
        }
        if visible != mount_point {
            if let Some(info) = skip(&visible) {
                stats.skipped_mounts += 1;
                if let Some(mut raw) = raw_names(fs, ino) {
                    fill_type(fs, &mut raw);
                    let names = names_that_can_hold_content(&raw);
                    if !names.is_empty() {
                        covers.push(DirCover {
                            path: visible.to_string_lossy().to_string(),
                            fstype: info.fstype,
                            source: info.source,
                            total: names.len(),
                            names: names.into_iter().take(COVER_NAMES_MAX).collect(),
                        });
                    }
                }
                continue;
            }
        }
        let Some(raw) = raw_names(fs, ino) else {
            stats.dir_errors += 1;
            continue;
        };
        stats.dirs += 1;
        stats.entries += raw.len() as u64;
        let listed: Option<HashSet<Vec<u8>>> = lister(&visible).map(|v| v.into_iter().collect());
        if listed.is_none() {
            stats.dir_errors += 1;
        }
        let raw_set: HashSet<&[u8]> = raw.iter().map(|(n, _, _)| n.as_slice()).collect();
        if let Some(l) = &listed {
            stats.fs_only += l.iter().filter(|n| !raw_set.contains(n.as_slice())).count() as u64;
        }
        for (name, child, ftype) in &raw {
            let hidden = listed.as_ref().is_some_and(|l| !l.contains(name));
            if hidden {
                candidates.push(Candidate {
                    dir_ino: ino,
                    dir_visible: visible.clone(),
                    name: name.clone(),
                    ino: *child,
                });
                continue;
            }
            let is_dir = match ftype {
                2 => true,
                0 => fs.inode(*child).map(|i| i.is_dir()).unwrap_or(false),
                _ => false,
            };
            if is_dir {
                stack.push((*child, join(&visible, name)));
            }
        }
    }
    WalkOut {
        stats,
        candidates,
        covers,
    }
}

pub fn recheck(
    fs: &dyn RawFs,
    cands: Vec<Candidate>,
    lister: &dyn Fn(&Path) -> Option<Vec<Vec<u8>>>,
    rounds: u32,
    gap: Duration,
) -> (Vec<Candidate>, usize) {
    let first = cands.len();
    let mut keep = cands;
    for _ in 0..rounds {
        if keep.is_empty() {
            break;
        }
        std::thread::sleep(gap);
        let mut cache: BTreeMap<(u64, PathBuf), Option<DirNames>> = BTreeMap::new();
        keep.retain(|c| {
            let key = (c.dir_ino, c.dir_visible.clone());
            let both = cache.entry(key).or_insert_with(|| {
                let raw: HashSet<Vec<u8>> = raw_names(fs, c.dir_ino)?
                    .into_iter()
                    .map(|(n, _, _)| n)
                    .collect();
                let listed: HashSet<Vec<u8>> = lister(&c.dir_visible)?.into_iter().collect();
                Some((raw, listed))
            });
            match both {
                Some((raw, listed)) => raw.contains(&c.name) && !listed.contains(&c.name),
                None => false,
            }
        });
    }
    let vanished = first - keep.len();
    (keep, vanished)
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct LagRecheck {
    pub stable: Vec<Candidate>,
    pub vanished: usize,
    pub unsettled: Vec<Candidate>,
}

#[allow(clippy::too_many_arguments)]
pub fn recheck_lagging(
    fs: &dyn RawFs,
    cands: Vec<Candidate>,
    lister: &dyn Fn(&Path) -> Option<Vec<Vec<u8>>>,
    rounds: u32,
    gap: Duration,
    stamp: &dyn Fn(&Path) -> Option<(i64, i64)>,
    now: &dyn Fn() -> i64,
    cold_secs: u64,
) -> LagRecheck {
    enum Dir {
        Untrusted,
        Unreadable,
        Names(HashSet<Vec<u8>>, HashSet<Vec<u8>>),
    }
    let first = cands.len();
    let mut keep = cands;
    let mut unsettled: Vec<Candidate> = Vec::new();
    for _ in 0..rounds {
        if keep.is_empty() {
            break;
        }
        std::thread::sleep(gap);
        fs.forget_cached();
        let mut cache: BTreeMap<(u64, PathBuf), Dir> = BTreeMap::new();
        let mut next = Vec::new();
        for c in keep {
            let key = (c.dir_ino, c.dir_visible.clone());
            let dir = cache.entry(key).or_insert_with(|| {
                let Some(s0) = stamp(&c.dir_visible) else {
                    return Dir::Untrusted;
                };
                if now() - s0.0 < cold_secs as i64 {
                    return Dir::Untrusted;
                }
                let flushed = fs
                    .inode(c.dir_ino)
                    .map(|i| i.mtime.max(i.ctime) == s0.0)
                    .unwrap_or(false);
                if !flushed {
                    return Dir::Untrusted;
                }
                let raw: Option<HashSet<Vec<u8>>> =
                    raw_names(fs, c.dir_ino).map(|v| v.into_iter().map(|(n, _, _)| n).collect());
                let listed: Option<HashSet<Vec<u8>>> =
                    lister(&c.dir_visible).map(|v| v.into_iter().collect());
                if stamp(&c.dir_visible) != Some(s0) {
                    return Dir::Untrusted;
                }
                match (raw, listed) {
                    (Some(r), Some(l)) => Dir::Names(r, l),
                    _ => Dir::Unreadable,
                }
            });
            match dir {
                Dir::Untrusted => unsettled.push(c),
                Dir::Unreadable => {}
                Dir::Names(raw, listed) => {
                    if raw.contains(&c.name) && !listed.contains(&c.name) {
                        next.push(c);
                    }
                }
            }
        }
        keep = next;
    }
    let vanished = first - keep.len() - unsettled.len();
    LagRecheck {
        stable: keep,
        vanished,
        unsettled,
    }
}

pub fn describe_hidden(fs: &dyn RawFs, cands: &[Candidate]) -> Vec<HiddenFile> {
    let mut out = Vec::new();
    for c in cands {
        let Ok(inode) = fs.inode(c.ino) else { continue };
        let raw = describe_inode(fs, &inode, false, HIDDEN_SHA_LIMIT, None);
        let path = join(&c.dir_visible, &c.name);
        let mut h = HiddenFile {
            path: path.to_string_lossy().to_string(),
            dir: c.dir_visible.to_string_lossy().to_string(),
            name: String::from_utf8_lossy(&c.name).to_string(),
            lstat_error: fs::symlink_metadata(&path)
                .err()
                .map(|e| errno_name(e.raw_os_error())),
            raw,
            ..Default::default()
        };
        if inode.is_dir() {
            if let Ok(entries) = fs.read_dir(&inode) {
                let mut names: Vec<String> = entries
                    .iter()
                    .filter(|e| e.name != b"." && e.name != b"..")
                    .map(|e| String::from_utf8_lossy(&e.name).to_string())
                    .collect();
                names.sort();
                h.children_total = names.len();
                names.truncate(HIDDEN_CHILDREN_MAX);
                h.children = names;
            }
        }
        out.push(h);
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub fn fs_lister(path: &Path) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for e in fs::read_dir(path).ok()? {
        out.push(e.ok()?.file_name().as_bytes().to_vec());
    }
    Some(out)
}

#[derive(Debug, PartialEq, Eq)]
pub struct DevicePlan {
    pub major: u32,
    pub minor: u32,
    pub root_mount: Option<MountEntry>,
    pub fstype: String,
    pub source: String,
    pub other_mount_points: HashMap<PathBuf, CoverInfo>,
}

pub fn plan_devices(mounts: &[MountEntry]) -> Vec<DevicePlan> {
    let mut by_dev: BTreeMap<(u32, u32), Vec<&MountEntry>> = BTreeMap::new();
    for m in mounts {
        if m.major == 0 || PSEUDO_FS.contains(&m.fstype.as_str()) {
            continue;
        }
        by_dev.entry((m.major, m.minor)).or_default().push(m);
    }
    by_dev
        .into_iter()
        .map(|((major, minor), ms)| {
            let root_mount = ms
                .iter()
                .filter(|m| m.root == "/")
                .min_by_key(|m| m.mount_point.len())
                .map(|m| (*m).clone());
            let first = ms[0];
            let (fstype, source) = root_mount
                .as_ref()
                .map(|m| (m.fstype.clone(), m.source.clone()))
                .unwrap_or_else(|| (first.fstype.clone(), first.source.clone()));
            let other_mount_points = mounts
                .iter()
                .filter(|m| (m.major, m.minor) != (major, minor))
                .map(|m| {
                    (
                        PathBuf::from(&m.mount_point),
                        CoverInfo {
                            fstype: m.fstype.clone(),
                            source: m.source.clone(),
                        },
                    )
                })
                .collect();
            DevicePlan {
                major,
                minor,
                root_mount,
                fstype,
                source,
                other_mount_points,
            }
        })
        .collect()
}

fn unavailable(plan: &DevicePlan, mount_point: &str, why: String) -> DiskDevice {
    DiskDevice {
        mount_point: mount_point.to_string(),
        source: plan.source.clone(),
        fstype: plan.fstype.clone(),
        status: DiskStatus::Unavailable(why),
    }
}

pub fn collect_disk_scan() -> DiskScan {
    let mut scan = DiskScan {
        ran: true,
        rounds: RECHECK_ROUNDS,
        ..Default::default()
    };
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        scan.devices.push(DiskDevice {
            mount_point: String::new(),
            source: String::new(),
            fstype: String::new(),
            status: DiskStatus::Unavailable("讀不到掛載資訊（/proc/self/mountinfo）".into()),
        });
        return scan;
    };
    let deadline = Instant::now() + Duration::from_secs(WALK_MAX_SECS);
    let mut all_hidden: Vec<HiddenFile> = Vec::new();
    let parsed = mounts::parse_mountinfo(&text);
    scan.proc_covers = proc_covers(&parsed);
    for c in scan.proc_covers.iter_mut() {
        c.alive = crate::collect::pid_alive(c.pid);
    }
    for plan in plan_devices(&parsed) {
        let Some(root) = plan.root_mount.clone() else {
            scan.devices.push(unavailable(
                &plan,
                "",
                "這個裝置只以子資料夾的方式掛載，沒有掛在根上，沒有對照".into(),
            ));
            continue;
        };
        if !mounts::raw_fs_supported(&root.fstype) {
            scan.devices.push(unavailable(
                &plan,
                &root.mount_point,
                format!("{} 檔案系統，{}", root.fstype, mounts::RAW_FS_ONLY),
            ));
            continue;
        }
        let ext = match mounts::open_raw_fs(&root) {
            Ok(e) => e,
            Err(why) => {
                scan.devices
                    .push(unavailable(&plan, &root.mount_point, why));
                continue;
            }
        };
        let mp = PathBuf::from(&root.mount_point);
        let skip = |p: &Path| plan.other_mount_points.get(p).cloned();
        let out = walk_device(ext.as_ref(), &mp, &skip, &fs_lister, deadline);
        scan.candidates += out.candidates.len();
        let mut stats = out.stats;
        let (stable, vanished) = if root.fstype == "xfs" {
            scan.cold_secs = xfs_cold_secs();
            let r = recheck_lagging(
                ext.as_ref(),
                out.candidates,
                &fs_lister,
                RECHECK_ROUNDS,
                Duration::from_millis(RECHECK_GAP_MS),
                &dir_stamp,
                &now_secs,
                xfs_cold_secs(),
            );
            stats.unsettled = r.unsettled.len() as u64;
            for c in r.unsettled.iter() {
                let d = c.dir_visible.to_string_lossy().to_string();
                if scan.unsettled_dirs.len() < UNSETTLED_DIRS_MAX
                    && !scan.unsettled_dirs.contains(&d)
                {
                    scan.unsettled_dirs.push(d);
                }
            }
            (r.stable, r.vanished)
        } else {
            recheck(
                ext.as_ref(),
                out.candidates,
                &fs_lister,
                RECHECK_ROUNDS,
                Duration::from_millis(RECHECK_GAP_MS),
            )
        };
        scan.vanished += vanished;
        scan.dir_covers.extend(out.covers);
        all_hidden.extend(describe_hidden(ext.as_ref(), &stable));
        scan.devices.push(DiskDevice {
            mount_point: root.mount_point.clone(),
            source: root.source.clone(),
            fstype: root.fstype.clone(),
            status: DiskStatus::Walked(stats),
        });
    }
    scan.dir_covers.sort_by(|a, b| a.path.cmp(&b.path));
    all_hidden.sort_by(|a, b| a.path.cmp(&b.path));
    scan.hidden_total = all_hidden.len();
    all_hidden.truncate(HIDDEN_FILES_MAX);
    scan.hidden = all_hidden;
    scan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rawfs::Ext4;
    use crate::rawfs_fixture::{open_small, open_xfs_v4, open_xfs_v5};
    use std::cell::Cell;

    fn lister_hiding<'a>(
        fs: &'a dyn RawFs,
        hide: &'a [(&'a str, &'a str)],
    ) -> impl Fn(&Path) -> Option<Vec<Vec<u8>>> + 'a {
        move |p: &Path| {
            let inode = fs.lookup(&p.to_string_lossy(), true).ok()??;
            let names: Vec<Vec<u8>> = fs
                .read_dir(&inode)
                .ok()?
                .into_iter()
                .map(|e| e.name)
                .filter(|n| n != b"." && n != b"..")
                .filter(|n| {
                    !hide
                        .iter()
                        .any(|(d, h)| Path::new(d) == p && h.as_bytes() == n.as_slice())
                })
                .collect();
            Some(names)
        }
    }

    #[test]
    fn xfs_honest_filesystem_produces_no_candidates_and_walks_every_directory() {
        for (fs, dirs) in [
            (open_xfs_v5().into_dyn(), 18),
            (open_xfs_v4().into_dyn(), 17),
        ] {
            let l = lister_hiding(fs.as_ref(), &[]);
            let out = walk_device(fs.as_ref(), Path::new("/"), &noskip, &l, far());
            assert!(out.candidates.is_empty(), "{:?}", out.candidates);
            assert!(out.stats.dirs >= dirs, "{:?}", out.stats);
            assert_eq!(out.stats.fs_only, 0);
            assert_eq!(out.stats.dir_errors, 0);
            assert!(!out.stats.truncated);
        }
    }

    #[test]
    fn xfs_hidden_names_are_found_and_described_with_creation_time_only_on_v5() {
        for (fs, v5) in [
            (open_xfs_v5().into_dyn(), true),
            (open_xfs_v4().into_dyn(), false),
        ] {
            let hide = [
                ("/d/leaf", "file-leaf-entry-name-7"),
                ("/etc/systemd/system", "svc.service"),
            ];
            let l = lister_hiding(fs.as_ref(), &hide);
            let out = walk_device(fs.as_ref(), Path::new("/"), &noskip, &l, far());
            assert_eq!(out.candidates.len(), 2, "{:?}", out.candidates);
            let (stable, vanished) =
                recheck(fs.as_ref(), out.candidates, &l, 3, Duration::from_millis(1));
            assert_eq!((stable.len(), vanished), (2, 0));
            let hidden = describe_hidden(fs.as_ref(), &stable);
            let svc = hidden
                .iter()
                .find(|h| h.path.ends_with("svc.service"))
                .unwrap();
            assert_eq!(svc.raw.kind, 'f');
            let text = "[Unit]\nDescription=x\n[Service]\nExecStart=/usr/bin/tool --serve\n";
            assert_eq!(
                svc.raw.sha256.as_deref(),
                Some(crate::sha256::hex_of(text.as_bytes()).as_str())
            );
            assert_eq!(svc.raw.crtime.is_some(), v5, "V5 才有建立時間");
            let tool = hidden
                .iter()
                .find(|h| h.path.ends_with("entry-name-7"))
                .unwrap();
            assert_eq!(tool.raw.size, 3000);
        }
    }

    #[test]
    fn xfs_without_entry_types_still_ignores_special_files_under_a_covering_mount() {
        let fs = open_xfs_v4();
        let l = lister_hiding(&fs, &[]);
        let skip = |p: &Path| (p == Path::new("/d/sf")).then(tmpfs);
        let out = walk_device(&fs, Path::new("/"), &skip, &l, far());
        assert_eq!(out.stats.skipped_mounts, 1);
        assert_eq!(out.covers.len(), 1, "{:?}", out.covers);
        let c = &out.covers[0];
        assert_eq!(c.path, "/d/sf");
        for special in ["chr", "fifo"] {
            assert!(
                !c.names.contains(&special.to_string()),
                "{} 是特殊檔案，不算被蓋住的東西：{:?}",
                special,
                c.names
            );
        }
        assert_eq!(c.total, 6, "{:?}", c.names);
    }

    fn clock<'a>(
        stamps: &'a [(&'a str, Vec<(i64, i64)>)],
        calls: &'a std::cell::RefCell<std::collections::HashMap<String, usize>>,
    ) -> impl Fn(&Path) -> Option<(i64, i64)> + 'a {
        move |p: &Path| {
            let key = p.to_string_lossy().to_string();
            let (_, seq) = stamps.iter().find(|(k, _)| *k == key)?;
            let mut c = calls.borrow_mut();
            let n = c.entry(key).or_insert(0);
            let v = seq[(*n).min(seq.len() - 1)];
            *n += 1;
            Some(v)
        }
    }

    type Lister<'a> = Box<dyn Fn(&Path) -> Option<Vec<Vec<u8>>> + 'a>;

    fn hide_one<'a>(
        fs: &'a dyn RawFs,
        dir: &'static str,
        name: &'static str,
    ) -> (Vec<Candidate>, Lister<'a>) {
        let hide: &'static [(&'static str, &'static str)] = Box::leak(Box::new([(dir, name)]));
        let l = lister_hiding(fs, hide);
        let out = walk_device(fs, Path::new("/"), &noskip, &l, far());
        (out.candidates, Box::new(l))
    }

    const COLD: u64 = 60;

    fn disk_stamp_of_leaf(fs: &dyn RawFs) -> i64 {
        let d = fs.lookup("/d/leaf", true).unwrap().unwrap();
        d.mtime.max(d.ctime)
    }

    #[test]
    fn lagging_fs_trusts_a_directory_that_has_been_quiet_long_enough() {
        let fs = open_xfs_v5();
        let (cands, l) = hide_one(&fs, "/d/leaf", "file-leaf-entry-name-7");
        assert_eq!(cands.len(), 1);
        let t = disk_stamp_of_leaf(&fs);
        let calls = Default::default();
        let st = [("/d/leaf", vec![(t, 5)])];
        let r = recheck_lagging(
            &fs,
            cands,
            &l,
            3,
            Duration::from_millis(1),
            &clock(&st, &calls),
            &|| t + 1000,
            COLD,
        );
        assert_eq!((r.stable.len(), r.vanished, r.unsettled.len()), (1, 0, 0));
    }

    #[test]
    fn lagging_fs_does_not_judge_a_directory_modified_within_the_cold_time() {
        let fs = open_xfs_v5();
        let t = disk_stamp_of_leaf(&fs);
        let (cands, l) = hide_one(&fs, "/d/leaf", "file-leaf-entry-name-7");
        let calls = Default::default();
        let st = [("/d/leaf", vec![(t, 0)])];
        let r = recheck_lagging(
            &fs,
            cands,
            &l,
            3,
            Duration::from_millis(1),
            &clock(&st, &calls),
            &|| t + 10,
            COLD,
        );
        assert_eq!((r.stable.len(), r.vanished, r.unsettled.len()), (0, 0, 1));
        let (cands, l) = hide_one(&fs, "/d/leaf", "file-leaf-entry-name-7");
        let r = recheck_lagging(
            &fs,
            cands,
            &l,
            1,
            Duration::from_millis(1),
            &clock(&st, &calls),
            &|| t + COLD as i64,
            COLD,
        );
        assert_eq!(r.stable.len(), 1);
        let (cands, l) = hide_one(&fs, "/d/leaf", "file-leaf-entry-name-7");
        let calls2 = Default::default();
        let r = recheck_lagging(
            &fs,
            cands,
            &l,
            1,
            Duration::from_millis(1),
            &clock(&st, &calls2),
            &|| t + COLD as i64 - 1,
            COLD,
        );
        assert_eq!((r.stable.len(), r.unsettled.len()), (0, 1));
    }

    #[test]
    fn lagging_fs_does_not_judge_when_the_disk_copy_of_the_directory_inode_is_older_than_what_we_see(
    ) {
        let fs = open_xfs_v5();
        let t = disk_stamp_of_leaf(&fs);
        let (cands, l) = hide_one(&fs, "/d/leaf", "file-leaf-entry-name-7");
        let calls = Default::default();
        let st = [("/d/leaf", vec![(t + 500, 0)])];
        let r = recheck_lagging(
            &fs,
            cands,
            &l,
            3,
            Duration::from_millis(1),
            &clock(&st, &calls),
            &|| t + 100_000,
            COLD,
        );
        assert_eq!((r.stable.len(), r.vanished, r.unsettled.len()), (0, 0, 1));
    }

    #[test]
    fn lagging_fs_does_not_judge_when_the_directory_changes_during_the_read() {
        let fs = open_xfs_v5();
        let t = disk_stamp_of_leaf(&fs);
        let (cands, l) = hide_one(&fs, "/d/leaf", "file-leaf-entry-name-7");
        let calls = Default::default();
        let st = [("/d/leaf", vec![(t, 5), (t, 6)])];
        let r = recheck_lagging(
            &fs,
            cands,
            &l,
            3,
            Duration::from_millis(1),
            &clock(&st, &calls),
            &|| t + 1000,
            COLD,
        );
        assert_eq!((r.stable.len(), r.unsettled.len()), (0, 1));
    }

    #[test]
    fn lagging_fs_cannot_judge_without_the_directory_time_and_counts_vanished_separately() {
        let fs = open_xfs_v5();
        let (cands, l) = hide_one(&fs, "/d/leaf", "file-leaf-entry-name-7");
        let calls = Default::default();
        let r = recheck_lagging(
            &fs,
            cands,
            &l,
            3,
            Duration::from_millis(1),
            &clock(&[], &calls),
            &|| 2_000_000_000,
            COLD,
        );
        assert_eq!((r.stable.len(), r.vanished, r.unsettled.len()), (0, 0, 1));
        let t = disk_stamp_of_leaf(&fs);
        let (cands, _) = hide_one(&fs, "/d/leaf", "file-leaf-entry-name-7");
        let honest = lister_hiding(&fs, &[]);
        let st = [("/d/leaf", vec![(t, 5)])];
        let r = recheck_lagging(
            &fs,
            cands,
            &honest,
            3,
            Duration::from_millis(1),
            &clock(&st, &calls),
            &|| t + 1000,
            COLD,
        );
        assert_eq!((r.stable.len(), r.vanished, r.unsettled.len()), (0, 1, 0));
    }

    #[test]
    fn xfs_cold_time_follows_the_kernel_flush_interval_plus_margin_and_is_bounded() {
        let d = xfs_cold_secs();
        assert!(
            (2 * XFS_DEFAULT_SYNCD_SECS..=XFS_COLD_MAX_SECS).contains(&d),
            "{}",
            d
        );
    }

    #[test]
    fn dir_stamp_is_the_later_of_modification_and_status_change() {
        let t = dir_stamp(Path::new("/tmp")).unwrap();
        assert!(t.0 > 1_600_000_000);
        assert!(dir_stamp(Path::new("/nonexistent-dir-for-test")).is_none());
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn noskip(_: &Path) -> Option<CoverInfo> {
        None
    }

    fn tmpfs() -> CoverInfo {
        CoverInfo {
            fstype: "tmpfs".into(),
            source: "tmpfs".into(),
        }
    }

    #[test]
    fn an_honest_filesystem_produces_no_candidates() {
        let fs = open_small();
        let l = lister_hiding(&fs, &[]);
        let out = walk_device(&fs, Path::new("/"), &noskip, &l, far());
        assert!(out.candidates.is_empty(), "{:?}", out.candidates);
        assert!(out.stats.dirs >= 8, "{:?}", out.stats);
        assert_eq!(out.stats.fs_only, 0);
        assert_eq!(out.stats.dir_errors, 0);
        assert!(!out.stats.truncated);
    }

    #[test]
    fn names_hidden_from_directory_listing_are_found_and_survive_recheck() {
        let fs = open_small();
        let hide = [("/etc/systemd/system", "svc.service"), ("/usr/bin", "tool")];
        let l = lister_hiding(&fs, &hide);
        let out = walk_device(&fs, Path::new("/"), &noskip, &l, far());
        let mut names: Vec<String> = out
            .candidates
            .iter()
            .map(|c| join(&c.dir_visible, &c.name).to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["/etc/systemd/system/svc.service", "/usr/bin/tool"]
        );
        let (stable, vanished) = recheck(&fs, out.candidates, &l, 3, Duration::from_millis(1));
        assert_eq!(stable.len(), 2);
        assert_eq!(vanished, 0);
        let hidden = describe_hidden(&fs, &stable);
        assert_eq!(hidden[0].path, "/etc/systemd/system/svc.service");
        assert_eq!(hidden[0].raw.kind, 'f');
        assert_eq!(hidden[0].raw.crtime, Some(1_773_022_830));
        assert!(hidden[0].raw.sha256.is_some());
        assert_eq!(hidden[0].lstat_error.as_deref(), Some("ENOENT"));
        assert_eq!(hidden[1].raw.size, crate::rawfs_fixture::TOOL_SIZE);
    }

    #[test]
    fn a_hidden_directory_is_reported_once_with_a_sample_of_its_contents() {
        let fs = open_small();
        let hide = [("/", "etc")];
        let l = lister_hiding(&fs, &hide);
        let out = walk_device(&fs, Path::new("/"), &noskip, &l, far());
        assert_eq!(
            out.candidates.len(),
            1,
            "不走進被藏的資料夾，裡面的名字不重複算"
        );
        let (stable, _) = recheck(&fs, out.candidates, &l, 2, Duration::from_millis(1));
        let hidden = describe_hidden(&fs, &stable);
        assert_eq!(hidden[0].raw.kind, 'd');
        assert_eq!(hidden[0].children, vec!["systemd"]);
        assert_eq!(hidden[0].children_total, 1);
    }

    #[test]
    fn a_name_that_only_flickers_does_not_survive_recheck() {
        let fs = open_small();
        let calls = Cell::new(0u32);
        let honest = lister_hiding(&fs, &[]);
        let flaky = |p: &Path| {
            let mut v = honest(p)?;
            if p == Path::new("/etc/systemd/system") {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    v.retain(|n| n != b"svc.service");
                }
            }
            Some(v)
        };
        let out = walk_device(&fs, Path::new("/"), &noskip, &flaky, far());
        assert_eq!(out.candidates.len(), 1);
        let (stable, vanished) = recheck(&fs, out.candidates, &flaky, 3, Duration::from_millis(1));
        assert!(stable.is_empty());
        assert_eq!(vanished, 1);
    }

    #[test]
    fn mount_points_of_other_devices_are_skipped_and_unreadable_directories_are_counted() {
        let fs = open_small();
        let honest = lister_hiding(&fs, &[]);
        let skip = |p: &Path| (p == Path::new("/usr")).then(tmpfs);
        let out = walk_device(&fs, Path::new("/"), &skip, &honest, far());
        assert_eq!(out.stats.skipped_mounts, 1);
        let full = walk_device(&fs, Path::new("/"), &noskip, &honest, far());
        assert!(out.stats.dirs < full.stats.dirs);
        let broken = |p: &Path| {
            if p == Path::new("/etc") {
                None
            } else {
                honest(p)
            }
        };
        let out2 = walk_device(&fs, Path::new("/"), &noskip, &broken, far());
        assert_eq!(out2.stats.dir_errors, 1);
        assert!(out2.candidates.is_empty());
    }

    #[test]
    fn names_listed_by_the_filesystem_but_missing_on_disk_are_counted_not_reported() {
        let fs = open_small();
        let honest = lister_hiding(&fs, &[]);
        let extra = |p: &Path| {
            let mut v = honest(p)?;
            if p == Path::new("/usr/bin") {
                v.push(b"brand-new".to_vec());
            }
            Some(v)
        };
        let out = walk_device(&fs, Path::new("/"), &noskip, &extra, far());
        assert!(out.candidates.is_empty());
        assert_eq!(out.stats.fs_only, 1);
    }

    #[test]
    fn walk_stops_at_the_deadline_and_says_so() {
        let fs = open_small();
        let honest = lister_hiding(&fs, &[]);
        let past = Instant::now() - Duration::from_secs(1);
        let out = walk_device(&fs, Path::new("/"), &noskip, &honest, past);
        assert!(out.stats.truncated);
        assert_eq!(out.stats.dirs, 0);
    }

    #[test]
    #[ignore]
    fn bench_walk() {
        let (Ok(img), Ok(tree)) = (
            std::env::var("RK_BENCH_IMG"),
            std::env::var("RK_BENCH_TREE"),
        ) else {
            eprintln!("沒有設定 RK_BENCH_IMG／RK_BENCH_TREE，略過");
            return;
        };
        let fs = Ext4::open(crate::mounts::FileDev::buffered_only(
            std::fs::File::open(img).unwrap(),
        ))
        .unwrap();
        let t = Instant::now();
        let out = walk_device(&fs, Path::new(&tree), &noskip, &fs_lister, far());
        eprintln!(
            "走訪 {} 個資料夾、{} 個名字，耗時 {:.2} 秒；候選 {}；檔案系統有磁碟沒有 {}；讀不了 {}",
            out.stats.dirs,
            out.stats.entries,
            t.elapsed().as_secs_f64(),
            out.candidates.len(),
            out.stats.fs_only,
            out.stats.dir_errors
        );
    }

    #[test]
    fn a_skipped_mount_with_real_content_underneath_is_reported_as_covered() {
        let fs = open_small();
        let honest = lister_hiding(&fs, &[]);
        let skip = |p: &Path| (p == Path::new("/usr")).then(tmpfs);
        let out = walk_device(&fs, Path::new("/"), &skip, &honest, far());
        assert_eq!(out.covers.len(), 1);
        let c = &out.covers[0];
        assert_eq!(c.path, "/usr");
        assert_eq!((c.fstype.as_str(), c.source.as_str()), ("tmpfs", "tmpfs"));
        assert_eq!(c.total, 2);
        assert_eq!(c.names, vec!["bin", "lib"]);
        assert!(out.candidates.is_empty());
        assert!(walk_device(&fs, Path::new("/"), &noskip, &honest, far())
            .covers
            .is_empty());
    }

    #[test]
    fn special_files_under_a_mount_point_are_normal_other_things_are_not() {
        let raw = vec![
            (b"null".to_vec(), 5, 3),
            (b"sda".to_vec(), 6, 4),
            (b"tty0".to_vec(), 7, 3),
            (b"initctl".to_vec(), 8, 5),
            (b"log".to_vec(), 9, 6),
        ];
        assert!(
            names_that_can_hold_content(&raw).is_empty(),
            "只有裝置節點、具名管道、通訊端：正常"
        );
        let mixed = vec![
            (b"null".to_vec(), 5, 3),
            (b"initctl".to_vec(), 6, 5),
            (b".x".to_vec(), 8, 1),
            (b"sub".to_vec(), 9, 2),
            (b"lnk".to_vec(), 10, 7),
        ];
        assert_eq!(
            names_that_can_hold_content(&mixed),
            vec![".x", "lnk", "sub"],
            "混在一起時，只列能存放內容的"
        );
        let unknown = vec![(b"mystery".to_vec(), 11, 0)];
        assert_eq!(names_that_can_hold_content(&unknown), vec!["mystery"]);
    }

    #[test]
    fn mounts_on_top_of_a_process_directory_are_found() {
        let text = "\
22 1 8:1 / / rw - ext4 /dev/sda rw
23 22 0:5 / /proc rw - proc proc rw
24 23 0:30 / /proc/4321 rw - tmpfs tmpfs rw
25 23 0:31 /x /proc/77/fd rw - ext4 /dev/sdb rw
26 23 0:32 / /proc/sys/fs/binfmt_misc rw - binfmt_misc none rw
27 23 0:33 / /proc/sysvipc rw - tmpfs tmpfs rw
28 22 0:34 / /proc4321 rw - tmpfs tmpfs rw
";
        let v = proc_covers(&mounts::parse_mountinfo(text));
        let got: Vec<(u32, &str, &str)> = v
            .iter()
            .map(|c| (c.pid, c.mount_point.as_str(), c.fstype.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![(4321, "/proc/4321", "tmpfs"), (77, "/proc/77/fd", "ext4")],
            "/proc/sys、/proc/sysvipc、/proc4321 都不是行程目錄"
        );
    }

    #[test]
    fn device_plan_picks_real_devices_and_the_root_mount() {
        let text = "\
22 1 8:1 / / rw - ext4 /dev/sda rw
23 22 0:5 / /proc rw - proc proc rw
24 22 8:17 / /usr rw - xfs /dev/sdb1 rw
25 22 8:33 /sub /srv/sub rw - ext4 /dev/sdc1 rw
26 22 8:1 /var/x /var/x rw - ext4 /dev/sda rw
27 22 0:30 / /tmp rw - tmpfs tmpfs rw
28 22 8:49 / /mnt/b rw - ext4 /dev/sdd1 rw
29 22 8:49 / /mnt/a rw - ext4 /dev/sdd1 rw
";
        let plans = plan_devices(&mounts::parse_mountinfo(text));
        let by: BTreeMap<(u32, u32), &DevicePlan> =
            plans.iter().map(|p| ((p.major, p.minor), p)).collect();
        assert_eq!(by.len(), 4, "proc 與 tmpfs 不算裝置");
        assert_eq!(by[&(8, 1)].root_mount.as_ref().unwrap().mount_point, "/");
        assert_eq!(by[&(8, 17)].fstype, "xfs");
        assert!(by[&(8, 33)].root_mount.is_none());
        assert_eq!(
            by[&(8, 49)].root_mount.as_ref().unwrap().mount_point,
            "/mnt/b"
        );
        assert!(by[&(8, 1)]
            .other_mount_points
            .contains_key(Path::new("/usr")));
        assert!(by[&(8, 1)]
            .other_mount_points
            .contains_key(Path::new("/proc")));
        assert!(!by[&(8, 1)]
            .other_mount_points
            .contains_key(Path::new("/var/x")));
        assert_eq!(
            by[&(8, 1)].other_mount_points[Path::new("/usr")].fstype,
            "xfs"
        );
    }
}
