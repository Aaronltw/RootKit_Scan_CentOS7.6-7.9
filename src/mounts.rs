use std::fs;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    pub major: u32,
    pub minor: u32,
    pub root: String,
    pub mount_point: String,
    pub fstype: String,
    pub source: String,
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') as u32 * 64
                + (b[i + 2] - b'0') as u32 * 8
                + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let Some(dash) = f.iter().position(|&x| x == "-") else {
            continue;
        };
        if f.len() < 6 || dash < 6 || f.len() < dash + 3 {
            continue;
        }
        let Some((maj, min)) = f[2].split_once(':') else {
            continue;
        };
        let (Ok(major), Ok(minor)) = (maj.parse::<u32>(), min.parse::<u32>()) else {
            continue;
        };
        out.push(MountEntry {
            major,
            minor,
            root: unescape(f[3]),
            mount_point: unescape(f[4]),
            fstype: f[dash + 1].to_string(),
            source: unescape(f[dash + 2]),
        });
    }
    out
}

pub fn mount_for<'a>(mounts: &'a [MountEntry], path: &str) -> Option<&'a MountEntry> {
    let mut best: Option<&MountEntry> = None;
    for m in mounts {
        let mp = m.mount_point.trim_end_matches('/');
        let hit = mp.is_empty() || path == mp || path.starts_with(&format!("{}/", mp));
        if !hit {
            continue;
        }
        if best.is_none_or(|b| m.mount_point.len() >= b.mount_point.len()) {
            best = Some(m);
        }
    }
    best
}

pub fn path_in_fs(m: &MountEntry, path: &str) -> String {
    let mp = m.mount_point.trim_end_matches('/');
    let rest = path.strip_prefix(mp).unwrap_or(path);
    let root = m.root.trim_end_matches('/');
    let joined = format!("{}{}", root, rest);
    if joined.is_empty() {
        "/".to_string()
    } else {
        joined
    }
}

pub fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (major as u64, minor as u64);
    ((ma & 0xfff) << 8) | (mi & 0xff) | ((mi & !0xff) << 12) | ((ma & !0xfff) << 32)
}

pub fn open_block_device(m: &MountEntry) -> Result<FileDev, String> {
    let want = makedev(m.major, m.minor);
    let mut candidates: Vec<String> = Vec::new();
    if m.source.starts_with("/dev/") {
        candidates.push(m.source.clone());
    }
    candidates.push(format!("/dev/block/{}:{}", m.major, m.minor));
    for dir in ["/dev", "/dev/mapper"] {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                candidates.push(e.path().to_string_lossy().to_string());
            }
        }
    }
    let mut last_err = String::from("找不到對應的區塊裝置檔");
    for c in candidates {
        let Ok(md) = fs::metadata(&c) else { continue };
        if md.rdev() != want {
            continue;
        }
        match fs::File::open(&c) {
            Ok(f) => {
                let direct = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(O_DIRECT)
                    .open(&c)
                    .ok();
                return Ok(FileDev {
                    buffered: f,
                    direct,
                });
            }
            Err(e) => last_err = format!("打不開 {}：{}", c, e),
        }
    }
    Err(last_err)
}

pub fn raw_fs_supported(fstype: &str) -> bool {
    matches!(fstype, "ext4" | "ext3" | "ext2" | "xfs")
}

pub const RAW_FS_ONLY: &str = "原始磁碟解析目前只支援 ext4 與 XFS";

pub fn open_raw_fs(m: &MountEntry) -> Result<Box<dyn crate::rawfs::RawFs>, String> {
    if !raw_fs_supported(&m.fstype) {
        return Err(format!("{} 檔案系統，{}", m.fstype, RAW_FS_ONLY));
    }
    let dev = open_block_device(m)?;
    if m.fstype == "xfs" {
        if dev.direct.is_none() {
            return Err(
                "打不開直接讀取（O_DIRECT）的通道，XFS 可能讀到過期的快取，所以不解析".into(),
            );
        }
        crate::rawfs::xfs::Xfs::open(dev)
            .map(|f| Box::new(f) as Box<dyn crate::rawfs::RawFs>)
            .map_err(|e| e.text())
    } else {
        crate::rawfs::Ext4::open(dev)
            .map(|f| Box::new(f) as Box<dyn crate::rawfs::RawFs>)
            .map_err(|e| e.text())
    }
}

const O_DIRECT: i32 = 0o40000;
const DIRECT_ALIGN: u64 = 4096;

pub struct FileDev {
    pub buffered: fs::File,
    pub direct: Option<fs::File>,
}

impl FileDev {
    #[cfg(test)]
    pub fn buffered_only(f: fs::File) -> Self {
        FileDev {
            buffered: f,
            direct: None,
        }
    }
}

pub fn read_aligned(f: &fs::File, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let start = off & !(DIRECT_ALIGN - 1);
    let end = (off + buf.len() as u64 + DIRECT_ALIGN - 1) & !(DIRECT_ALIGN - 1);
    let len = (end - start) as usize;
    let mut raw = vec![0u8; len + DIRECT_ALIGN as usize];
    let adj = (DIRECT_ALIGN as usize - raw.as_ptr() as usize % DIRECT_ALIGN as usize)
        % DIRECT_ALIGN as usize;
    let aligned = &mut raw[adj..adj + len];
    let mut done = 0usize;
    while done < len {
        let n = f.read_at(&mut aligned[done..], start + done as u64)?;
        if n == 0 {
            break;
        }
        done += n;
    }
    let from = (off - start) as usize;
    if done < from + buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "讀到的資料比需要的少",
        ));
    }
    buf.copy_from_slice(&aligned[from..from + buf.len()]);
    Ok(())
}

impl crate::rawfs::Dev for FileDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.buffered.read_exact_at(buf, off)
    }

    fn read_data_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        if let Some(d) = &self.direct {
            if read_aligned(d, off, buf).is_ok() {
                return Ok(());
            }
        }
        self.buffered.read_exact_at(buf, off)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_parsing_supports_ext_family_and_xfs_only() {
        for t in ["ext4", "ext3", "ext2", "xfs"] {
            assert!(raw_fs_supported(t), "{}", t);
        }
        for t in [
            "btrfs", "nfs", "nfs4", "tmpfs", "overlay", "vfat", "iso9660", "fuseblk", "",
        ] {
            assert!(!raw_fs_supported(t), "{}", t);
        }
        assert!(RAW_FS_ONLY.contains("ext4") && RAW_FS_ONLY.contains("XFS"));
    }

    const SAMPLE: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda rw,data=ordered
23 22 0:5 / /proc rw,nosuid shared:5 - proc proc rw
24 22 8:17 / /usr rw,relatime shared:8 - ext4 /dev/sdb1 rw
25 22 8:33 /data/sub /srv/with\\040space rw - ext4 /dev/sdc1 rw
26 22 8:1 /var/lib/x /var/mnt rw - ext4 /dev/sda rw
27 22 0:30 / /tmp rw - tmpfs tmpfs rw,size=1k
bad line
";

    #[test]
    fn parses_fields_and_skips_bad_lines() {
        let m = parse_mountinfo(SAMPLE);
        assert_eq!(m.len(), 6);
        assert_eq!(m[0].fstype, "ext4");
        assert_eq!(m[0].source, "/dev/sda");
        assert_eq!((m[0].major, m[0].minor), (8, 1));
        assert_eq!(m[3].mount_point, "/srv/with space");
        assert_eq!(m[3].root, "/data/sub");
    }

    #[test]
    fn longest_mount_point_wins() {
        let m = parse_mountinfo(SAMPLE);
        assert_eq!(mount_for(&m, "/etc/passwd").unwrap().source, "/dev/sda");
        assert_eq!(mount_for(&m, "/usr/bin/x").unwrap().source, "/dev/sdb1");
        assert_eq!(mount_for(&m, "/usr").unwrap().source, "/dev/sdb1");
        assert_eq!(mount_for(&m, "/usrx/bin").unwrap().source, "/dev/sda");
        assert_eq!(mount_for(&m, "/tmp/a").unwrap().fstype, "tmpfs");
        assert_eq!(
            mount_for(&m, "/srv/with space/f").unwrap().source,
            "/dev/sdc1"
        );
    }

    #[test]
    fn path_is_translated_into_the_filesystem() {
        let m = parse_mountinfo(SAMPLE);
        let root = mount_for(&m, "/etc/passwd").unwrap();
        assert_eq!(path_in_fs(root, "/etc/passwd"), "/etc/passwd");
        let usr = mount_for(&m, "/usr/bin/x").unwrap();
        assert_eq!(path_in_fs(usr, "/usr/bin/x"), "/bin/x");
        assert_eq!(path_in_fs(usr, "/usr"), "/");
        let bind = mount_for(&m, "/srv/with space/f").unwrap();
        assert_eq!(path_in_fs(bind, "/srv/with space/f"), "/data/sub/f");
        let var = mount_for(&m, "/var/mnt/a/b").unwrap();
        assert_eq!(path_in_fs(var, "/var/mnt/a/b"), "/var/lib/x/a/b");
    }

    #[test]
    fn later_mount_on_the_same_point_wins() {
        let text = "1 0 8:1 / / rw - ext4 /dev/sda rw\n2 1 8:2 / /mnt rw - ext4 /dev/sdb rw\n3 1 8:3 / /mnt rw - ext4 /dev/sdc rw\n";
        let m = parse_mountinfo(text);
        assert_eq!(mount_for(&m, "/mnt/x").unwrap().source, "/dev/sdc");
    }

    #[test]
    fn device_number_encoding_matches_linux() {
        assert_eq!(makedev(8, 1), 0x801);
        assert_eq!(makedev(8, 17), 0x811);
        assert_eq!(makedev(259, 300), (259u64 << 8) | 44 | (1u64 << 20));
    }

    #[test]
    fn aligned_read_handles_unaligned_positions_lengths_and_the_end_of_file() {
        let dir = std::env::temp_dir().join(format!("rk-aligned-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.bin");
        let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        for (off, len) in [
            (0usize, 1usize),
            (1, 4095),
            (4095, 2),
            (4096, 4096),
            (5000, 9000),
            (19_999, 1),
            (0, 20_000),
        ] {
            let mut buf = vec![0u8; len];
            read_aligned(&f, off as u64, &mut buf)
                .unwrap_or_else(|e| panic!("{} {} {}", off, len, e));
            assert_eq!(
                buf,
                data[off..off + len].to_vec(),
                "位置 {} 長度 {}",
                off,
                len
            );
        }
        let mut buf = vec![0u8; 10];
        assert!(
            read_aligned(&f, 25_000, &mut buf).is_err(),
            "超過檔案尾端要回報錯誤"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
