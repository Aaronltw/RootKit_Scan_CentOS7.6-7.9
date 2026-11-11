use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;

pub mod xfs;

pub trait Dev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()>;
    fn read_data_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.read_at(off, buf)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawError {
    NotExt4,
    NotXfs,
    Unsupported(String),
    Io(String),
    Corrupt(String),
}

impl RawError {
    pub fn text(&self) -> String {
        match self {
            RawError::NotExt4 => "不是 ext4".to_string(),
            RawError::NotXfs => "不是 XFS".to_string(),
            RawError::Unsupported(s) => format!("用到不支援的功能：{}", s),
            RawError::Io(s) => format!("讀取失敗：{}", s),
            RawError::Corrupt(s) => format!("資料不合理：{}", s),
        }
    }
}

pub type Res<T> = Result<T, RawError>;

fn io_err(e: io::Error) -> RawError {
    RawError::Io(e.to_string())
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

const EXT4_MAGIC: u16 = 0xEF53;
const EXTENT_MAGIC: u16 = 0xF30A;
const FL_EXTENTS: u32 = 0x0008_0000;
const FL_INLINE_DATA: u32 = 0x1000_0000;
const INCOMPAT_UNSUPPORTED: u32 = 0x1 | 0x8 | 0x10 | 0x1000;
const INCOMPAT_64BIT: u32 = 0x80;
const MAX_DIR_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SYMLINKS: u32 = 16;
const ROOT_INO: u64 = 2;
const CHUNK: u64 = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    pub ino: u64,
    pub mode: u16,
    pub size: u64,
    pub links: u32,
    pub flags: u32,
    pub atime: i64,
    pub ctime: i64,
    pub mtime: i64,
    pub crtime: Option<i64>,
    fork: Vec<u8>,
    aux: u32,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
    pub fn is_regular(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == 0xA000
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u64,
    pub name: Vec<u8>,
    pub file_type: u8,
}

#[derive(Clone, Copy, Debug)]
struct Extent {
    lblk: u64,
    len: u64,
    pblk: u64,
    unwritten: bool,
}

pub struct Ext4<D: Dev> {
    dev: D,
    bs: u64,
    inode_size: u64,
    inodes_per_group: u64,
    inodes_count: u64,
    blocks_count: u64,
    desc_size: u64,
    gdt_off: u64,
    groups: u64,
    cache: RefCell<HashMap<u64, Rc<Vec<u8>>>>,
}

impl<D: Dev> Ext4<D> {
    pub fn open(dev: D) -> Res<Self> {
        let mut sb = vec![0u8; 1024];
        dev.read_at(1024, &mut sb).map_err(io_err)?;
        if le16(&sb, 0x38) != EXT4_MAGIC {
            return Err(RawError::NotExt4);
        }
        let incompat = le32(&sb, 0x60);
        if incompat & INCOMPAT_UNSUPPORTED != 0 {
            return Err(RawError::Unsupported(format!(
                "不相容功能旗標 0x{:x}",
                incompat & INCOMPAT_UNSUPPORTED
            )));
        }
        let log_bs = le32(&sb, 0x18);
        if log_bs > 6 {
            return Err(RawError::Corrupt(format!("區塊大小指數 {}", log_bs)));
        }
        let bs = 1024u64 << log_bs;
        let rev = le32(&sb, 0x4C);
        let inode_size = if rev == 0 {
            128
        } else {
            le16(&sb, 0x58) as u64
        };
        if !(128..=bs).contains(&inode_size) || inode_size % 128 != 0 {
            return Err(RawError::Corrupt(format!("inode 大小 {}", inode_size)));
        }
        let is64 = incompat & INCOMPAT_64BIT != 0;
        let desc_size = if is64 { le16(&sb, 0xFE) as u64 } else { 32 };
        if desc_size < 32 {
            return Err(RawError::Corrupt(format!("群組描述大小 {}", desc_size)));
        }
        let blocks_lo = le32(&sb, 0x04) as u64;
        let blocks_hi = if is64 { le32(&sb, 0x150) as u64 } else { 0 };
        let blocks_count = blocks_lo | (blocks_hi << 32);
        let first_data_block = le32(&sb, 0x14) as u64;
        let blocks_per_group = le32(&sb, 0x20) as u64;
        let inodes_per_group = le32(&sb, 0x28) as u64;
        let inodes_count = le32(&sb, 0x00) as u64;
        if blocks_per_group == 0 || inodes_per_group == 0 || blocks_count <= first_data_block {
            return Err(RawError::Corrupt("超級區塊的群組數字為零".to_string()));
        }
        let groups = (blocks_count - first_data_block).div_ceil(blocks_per_group);
        Ok(Ext4 {
            dev,
            bs,
            inode_size,
            inodes_per_group,
            inodes_count,
            blocks_count,
            desc_size,
            gdt_off: (first_data_block + 1) * bs,
            groups,
            cache: RefCell::new(HashMap::new()),
        })
    }

    #[allow(dead_code)]
    pub fn block_size(&self) -> u64 {
        self.bs
    }

    #[allow(dead_code)]
    pub fn inodes_count(&self) -> u64 {
        self.inodes_count
    }

    fn read_block(&self, blk: u64) -> Res<Vec<u8>> {
        if blk >= self.blocks_count {
            return Err(RawError::Corrupt(format!("區塊 {} 超出範圍", blk)));
        }
        let mut buf = vec![0u8; self.bs as usize];
        self.dev.read_at(blk * self.bs, &mut buf).map_err(io_err)?;
        Ok(buf)
    }

    fn inode_block(&self, blk: u64) -> Res<Rc<Vec<u8>>> {
        if let Some(b) = self.cache.borrow().get(&blk) {
            return Ok(Rc::clone(b));
        }
        let b = Rc::new(self.read_block(blk)?);
        let mut c = self.cache.borrow_mut();
        if c.len() >= 4096 {
            c.clear();
        }
        c.insert(blk, Rc::clone(&b));
        Ok(b)
    }

    fn extents(&self, inode: &Inode) -> Res<Vec<Extent>> {
        if inode.flags & FL_INLINE_DATA != 0 {
            return Err(RawError::Unsupported("內嵌資料".to_string()));
        }
        let mut out = Vec::new();
        if inode.flags & FL_EXTENTS != 0 {
            let mut budget = 4096u32;
            self.walk_extent_node(&inode.fork, 0, &mut out, &mut budget)?;
        } else {
            self.walk_block_map(inode, &mut out)?;
        }
        out.sort_by_key(|e| e.lblk);
        Ok(out)
    }

    fn walk_extent_node(
        &self,
        node: &[u8],
        level: u32,
        out: &mut Vec<Extent>,
        budget: &mut u32,
    ) -> Res<()> {
        if node.len() < 12 || le16(node, 0) != EXTENT_MAGIC {
            return Err(RawError::Corrupt("extent 區塊的魔數不對".to_string()));
        }
        if level > 5 {
            return Err(RawError::Corrupt("extent 樹太深".to_string()));
        }
        let entries = le16(node, 2) as usize;
        let depth = le16(node, 6);
        if 12 + entries * 12 > node.len() {
            return Err(RawError::Corrupt("extent 項目數超出區塊".to_string()));
        }
        for i in 0..entries {
            let e = &node[12 + i * 12..24 + i * 12];
            if depth == 0 {
                let mut len = le16(e, 4) as u64;
                let unwritten = len > 32768;
                if unwritten {
                    len -= 32768;
                }
                out.push(Extent {
                    lblk: le32(e, 0) as u64,
                    len,
                    pblk: le32(e, 8) as u64 | ((le16(e, 6) as u64) << 32),
                    unwritten,
                });
            } else {
                if *budget == 0 {
                    return Err(RawError::Corrupt("extent 節點太多".to_string()));
                }
                *budget -= 1;
                let leaf = le32(e, 4) as u64 | ((le16(e, 8) as u64) << 32);
                let child = self.read_block(leaf)?;
                self.walk_extent_node(&child, level + 1, out, budget)?;
            }
        }
        Ok(())
    }

    fn walk_block_map(&self, inode: &Inode, out: &mut Vec<Extent>) -> Res<()> {
        let nblocks = inode.size.div_ceil(self.bs);
        let mut lblk = 0u64;
        let mut push = |pblk: u64, lblk: &mut u64| {
            out.push(Extent {
                lblk: *lblk,
                len: 1,
                pblk,
                unwritten: pblk == 0,
            });
            *lblk += 1;
        };
        for i in 0..12 {
            if lblk >= nblocks {
                return Ok(());
            }
            push(le32(&inode.fork, i * 4) as u64, &mut lblk);
        }
        for (slot, depth) in [(12usize, 1u32), (13, 2), (14, 3)] {
            if lblk >= nblocks {
                break;
            }
            let root = le32(&inode.fork, slot * 4) as u64;
            self.walk_indirect(root, depth, nblocks, &mut lblk, out)?;
        }
        Ok(())
    }

    fn walk_indirect(
        &self,
        blk: u64,
        depth: u32,
        nblocks: u64,
        lblk: &mut u64,
        out: &mut Vec<Extent>,
    ) -> Res<()> {
        let per = self.bs / 4;
        if blk == 0 {
            *lblk += per.pow(depth);
            return Ok(());
        }
        let data = self.read_block(blk)?;
        for i in 0..per as usize {
            if *lblk >= nblocks {
                return Ok(());
            }
            let child = le32(&data, i * 4) as u64;
            if depth == 1 {
                out.push(Extent {
                    lblk: *lblk,
                    len: 1,
                    pblk: child,
                    unwritten: child == 0,
                });
                *lblk += 1;
            } else {
                self.walk_indirect(child, depth - 1, nblocks, lblk, out)?;
            }
        }
        Ok(())
    }
}

pub trait RawFs {
    fn root_ino(&self) -> u64;
    fn inode(&self, ino: u64) -> Res<Inode>;
    fn read_to(&self, inode: &Inode, max: u64, sink: &mut dyn FnMut(&[u8])) -> Res<u64>;
    fn read_dir(&self, dir: &Inode) -> Res<Vec<DirEntry>>;
    fn read_link(&self, inode: &Inode) -> Res<Vec<u8>>;
    fn forget_cached(&self) {}
    fn lags_behind_memory(&self) -> bool {
        false
    }

    fn read_data(&self, inode: &Inode, max: u64) -> Res<Vec<u8>> {
        let mut out = Vec::new();
        self.read_to(inode, max, &mut |c| out.extend_from_slice(c))?;
        Ok(out)
    }

    fn lookup(&self, path: &str, follow_last: bool) -> Res<Option<Inode>> {
        let mut stack: Vec<Inode> = vec![self.inode(self.root_ino())?];
        let mut todo: Vec<String> = path
            .split('/')
            .rev()
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        let mut links = 0u32;
        while let Some(comp) = todo.pop() {
            if comp == "." {
                continue;
            }
            if comp == ".." {
                if stack.len() > 1 {
                    stack.pop();
                }
                continue;
            }
            let cur = stack
                .last()
                .cloned()
                .ok_or_else(|| RawError::Corrupt("路徑堆疊為空".to_string()))?;
            if !cur.is_dir() {
                return Ok(None);
            }
            let entries = self.read_dir(&cur)?;
            let Some(hit) = entries.iter().find(|e| e.name == comp.as_bytes()) else {
                return Ok(None);
            };
            let node = self.inode(hit.ino)?;
            let is_last = todo.is_empty();
            if node.is_symlink() && (!is_last || follow_last) {
                links += 1;
                if links > MAX_SYMLINKS {
                    return Err(RawError::Corrupt("符號連結太多層".to_string()));
                }
                let target = String::from_utf8_lossy(&self.read_link(&node)?).to_string();
                if target.starts_with('/') {
                    stack.truncate(1);
                }
                for c in target.split('/').rev().filter(|c| !c.is_empty()) {
                    todo.push(c.to_string());
                }
                continue;
            }
            stack.push(node);
        }
        Ok(stack.pop())
    }
}

fn read_extent_data<D: Dev>(
    dev: &D,
    bs: u64,
    extents: &[Extent],
    total: u64,
    direct: bool,
    sink: &mut dyn FnMut(&[u8]),
) -> Res<u64> {
    let mut pos = 0u64;
    let mut buf = vec![0u8; CHUNK as usize];
    let mut first = 0usize;
    while pos < total {
        let n = (total - pos).min(CHUNK);
        let chunk = &mut buf[..n as usize];
        chunk.fill(0);
        while first < extents.len() && (extents[first].lblk + extents[first].len) * bs <= pos {
            first += 1;
        }
        for e in &extents[first..] {
            let e_start = e.lblk * bs;
            if e_start >= pos + n {
                break;
            }
            let e_end = (e.lblk + e.len) * bs;
            let from = pos.max(e_start);
            let to = (pos + n).min(e_end);
            if !e.unwritten && from < to {
                let dst = &mut chunk[(from - pos) as usize..(to - pos) as usize];
                let at = e.pblk * bs + (from - e_start);
                let r = if direct {
                    dev.read_data_at(at, dst)
                } else {
                    dev.read_at(at, dst)
                };
                r.map_err(io_err)?;
            }
        }
        sink(chunk);
        pos += n;
    }
    Ok(total)
}

impl<D: Dev> RawFs for Ext4<D> {
    fn root_ino(&self) -> u64 {
        ROOT_INO
    }

    fn inode(&self, ino: u64) -> Res<Inode> {
        if ino == 0 || ino > self.inodes_count {
            return Err(RawError::Corrupt(format!("inode 編號 {} 超出範圍", ino)));
        }
        let group = (ino - 1) / self.inodes_per_group;
        let idx = (ino - 1) % self.inodes_per_group;
        if group >= self.groups {
            return Err(RawError::Corrupt(format!("inode {} 的群組不存在", ino)));
        }
        let mut gd = vec![0u8; self.desc_size as usize];
        self.dev
            .read_at(self.gdt_off + group * self.desc_size, &mut gd)
            .map_err(io_err)?;
        let mut table = le32(&gd, 0x08) as u64;
        if self.desc_size >= 64 {
            table |= (le32(&gd, 0x28) as u64) << 32;
        }
        let byte_off = idx * self.inode_size;
        let blk = table + byte_off / self.bs;
        let off = (byte_off % self.bs) as usize;
        let data = self.inode_block(blk)?;
        let raw = &data[off..off + self.inode_size as usize];
        Ok(parse_inode(ino, raw))
    }

    fn read_to(&self, inode: &Inode, max: u64, sink: &mut dyn FnMut(&[u8])) -> Res<u64> {
        let total = inode.size.min(max);
        if total == 0 {
            return Ok(0);
        }
        if inode.is_symlink() && inode.size < 60 && inode.flags & FL_EXTENTS == 0 {
            sink(&inode.fork[..total as usize]);
            return Ok(total);
        }
        let extents = self.extents(inode)?;
        read_extent_data(
            &self.dev,
            self.bs,
            &extents,
            total,
            inode.is_regular(),
            sink,
        )
    }

    fn read_link(&self, inode: &Inode) -> Res<Vec<u8>> {
        if !inode.is_symlink() {
            return Err(RawError::Corrupt("不是符號連結".to_string()));
        }
        self.read_data(inode, 4096)
    }

    fn read_dir(&self, dir: &Inode) -> Res<Vec<DirEntry>> {
        if !dir.is_dir() {
            return Err(RawError::Corrupt("不是目錄".to_string()));
        }
        let data = self.read_data(dir, MAX_DIR_BYTES)?;
        let bs = self.bs as usize;
        let mut out = Vec::new();
        for block in data.chunks(bs) {
            let mut o = 0usize;
            while o + 8 <= block.len() {
                let ino = le32(block, o) as u64;
                let mut rec_len = le16(block, o + 4) as usize;
                if bs >= 65536 && (rec_len == 0 || rec_len == 65535) {
                    rec_len = 65536;
                }
                let name_len = block[o + 6] as usize;
                let ftype = block[o + 7];
                if rec_len < 8 || rec_len % 4 != 0 || o + rec_len > block.len() {
                    break;
                }
                if ino != 0 && name_len > 0 && 8 + name_len <= rec_len {
                    out.push(DirEntry {
                        ino,
                        name: block[o + 8..o + 8 + name_len].to_vec(),
                        file_type: ftype,
                    });
                }
                o += rec_len;
            }
        }
        Ok(out)
    }
}

fn ts(lo: u32, extra: Option<u32>) -> i64 {
    (lo as i32 as i64) + ((extra.map_or(0, |e| (e & 3) as i64)) << 32)
}

fn parse_inode(ino: u64, raw: &[u8]) -> Inode {
    let mode = le16(raw, 0x00);
    let size = le32(raw, 0x04) as u64 | ((le32(raw, 0x6C) as u64) << 32);
    let size = if mode & 0xF000 == 0x8000 {
        size
    } else {
        size & 0xFFFF_FFFF
    };
    let extra_isize = if raw.len() > 0x82 {
        le16(raw, 0x80) as usize
    } else {
        0
    };
    let has = |upto: usize| raw.len() >= upto && 128 + extra_isize >= upto;
    let extra = |o: usize| if has(o + 4) { Some(le32(raw, o)) } else { None };
    let fork = raw[0x28..0x28 + 60].to_vec();
    Inode {
        ino,
        mode,
        size,
        links: le16(raw, 0x1A) as u32,
        flags: le32(raw, 0x20),
        atime: ts(le32(raw, 0x08), extra(0x8C)),
        ctime: ts(le32(raw, 0x0C), extra(0x84)),
        mtime: ts(le32(raw, 0x10), extra(0x88)),
        crtime: if has(0x94) {
            Some(ts(le32(raw, 0x90), extra(0x94)))
        } else {
            None
        },
        fork,
        aux: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::rawfs_fixture::MemDev;

    #[test]
    fn garbage_is_not_ext4() {
        let r = Ext4::open(MemDev(vec![0u8; 8192]));
        assert!(matches!(r, Err(RawError::NotExt4)));
    }

    #[test]
    fn too_short_device_is_an_io_error() {
        let r = Ext4::open(MemDev(vec![0u8; 100]));
        assert!(matches!(r, Err(RawError::Io(_))));
    }

    #[test]
    fn timestamp_extension_bits_extend_past_2038() {
        assert_eq!(ts(0x7FFF_FFFF, Some(0)), 2_147_483_647);
        assert_eq!(ts(0x8000_0000, Some(1)), -2_147_483_648 + (1i64 << 32));
        assert_eq!(ts(1_773_022_830, None), 1_773_022_830);
    }

    #[test]
    fn small_ext4_fixture_is_readable() {
        let fs = crate::rawfs_fixture::open_small();
        let unit = fs
            .lookup("/etc/systemd/system/svc.service", true)
            .unwrap()
            .expect("應該找得到單元檔");
        assert!(unit.is_regular());
        assert_eq!(unit.crtime, Some(1_773_022_830));
        let text = String::from_utf8(fs.read_data(&unit, 1 << 20).unwrap()).unwrap();
        assert_eq!(text.len() as u64, unit.size);
        assert!(text.starts_with("[Unit]\n"), "{}", text);
        assert!(text.contains("ExecStart=/usr/bin/tool --serve"), "{}", text);
        let tool = fs.lookup("/usr/bin/tool", true).unwrap().unwrap();
        assert_eq!(tool.size, crate::rawfs_fixture::TOOL_SIZE);
        let body = fs.read_data(&tool, 1 << 20).unwrap();
        for (i, b) in body.iter().enumerate() {
            assert_eq!(*b, crate::rawfs_fixture::tool_byte(i), "位置 {}", i);
        }
        assert_eq!(fs.read_data(&tool, 100).unwrap().len(), 100);
    }

    #[test]
    fn small_ext4_fixture_directories_and_symlinks() {
        let fs = crate::rawfs_fixture::open_small();
        let dir = fs.lookup("/etc/systemd/system", true).unwrap().unwrap();
        let mut names: Vec<String> = fs
            .read_dir(&dir)
            .unwrap()
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![".", "..", "multi-user.target.wants", "svc.service"]
        );
        let link = fs
            .lookup(
                "/etc/systemd/system/multi-user.target.wants/svc.service",
                false,
            )
            .unwrap()
            .unwrap();
        assert!(link.is_symlink());
        assert_eq!(
            fs.read_link(&link).unwrap(),
            b"/etc/systemd/system/svc.service".to_vec()
        );
        let followed = fs
            .lookup(
                "/etc/systemd/system/multi-user.target.wants/svc.service",
                true,
            )
            .unwrap()
            .unwrap();
        assert!(followed.is_regular());
        let other = fs
            .lookup("/lib/systemd/system/other.service", true)
            .unwrap()
            .expect("經過 /lib 連結找得到");
        assert!(other.is_regular());
    }

    #[test]
    fn small_ext4_fixture_missing_paths_are_none() {
        let fs = crate::rawfs_fixture::open_small();
        assert!(fs.lookup("/etc/nope", true).unwrap().is_none());
        assert!(fs
            .lookup("/etc/systemd/system/svc.service/x", true)
            .unwrap()
            .is_none());
        assert!(fs.lookup("/usr/bin/../bin/tool", true).unwrap().is_some());
    }

    #[test]
    fn symlink_loop_is_an_error_not_a_hang() {
        let fs = crate::rawfs_fixture::open_small();
        let r = fs.lookup("/loop-a", true);
        assert!(matches!(r, Err(RawError::Corrupt(_))), "{:?}", r);
    }

    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn mke2fs_available() -> bool {
        Command::new("mke2fs").arg("-V").output().is_ok()
    }

    fn build(
        name: &str,
        opts: &[&str],
        size: &str,
        populate: impl FnOnce(&Path),
    ) -> Option<Vec<u8>> {
        if !mke2fs_available() {
            eprintln!("略過 {}：這台機器沒有 mke2fs", name);
            return None;
        }
        let dir: PathBuf =
            std::env::temp_dir().join(format!("rawfs-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let tree = dir.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        populate(&tree);
        let img = dir.join("img");
        let out = Command::new("mke2fs")
            .env("E2FSPROGS_FAKE_TIME", "1773022830")
            .args(["-q", "-F"])
            .args(opts)
            .arg("-d")
            .arg(&tree)
            .arg(&img)
            .arg(size)
            .output()
            .unwrap();
        if !out.status.success() {
            eprintln!(
                "略過 {}：mke2fs 不接受這組選項（{}）",
                name,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        let data = std::fs::read(&img).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        Some(data)
    }

    fn pattern(n: usize, seed: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 31 + seed) % 253) as u8).collect()
    }

    #[test]
    fn modern_features_1k_blocks_64bit_and_checksums() {
        let body = pattern(5000, 1);
        let b2 = body.clone();
        let Some(img) = build(
            "modern",
            &[
                "-t",
                "ext4",
                "-b",
                "1024",
                "-O",
                "64bit,metadata_csum,extent,flex_bg,^has_journal",
            ],
            "4M",
            move |t| {
                std::fs::create_dir_all(t.join("a/b")).unwrap();
                std::fs::write(t.join("a/b/f.bin"), &b2).unwrap();
            },
        ) else {
            return;
        };
        let fs = Ext4::open(MemDev(img)).unwrap();
        assert_eq!(fs.block_size(), 1024);
        let f = fs.lookup("/a/b/f.bin", true).unwrap().unwrap();
        assert_eq!(f.size, 5000);
        assert_eq!(f.crtime, Some(1_773_022_830));
        assert_eq!(fs.read_data(&f, 1 << 20).unwrap(), body);
    }

    #[test]
    fn huge_directory_lists_every_name_exactly_once() {
        let n = 4000usize;
        let Some(img) = build(
            "bigdir",
            &[
                "-t",
                "ext4",
                "-b",
                "1024",
                "-O",
                "dir_index,^has_journal",
                "-N",
                "6000",
            ],
            "16M",
            move |t| {
                std::fs::create_dir_all(t.join("d")).unwrap();
                for i in 0..n {
                    std::fs::write(
                        t.join(format!("d/file-{:05}-with-a-fairly-long-name", i)),
                        b"x",
                    )
                    .unwrap();
                }
            },
        ) else {
            return;
        };
        let fs = Ext4::open(MemDev(img)).unwrap();
        let d = fs.lookup("/d", true).unwrap().unwrap();
        let mut names: Vec<String> = fs
            .read_dir(&d)
            .unwrap()
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).to_string())
            .filter(|s| s != "." && s != "..")
            .collect();
        assert_eq!(names.len(), n, "名字不多不少");
        names.sort();
        names.dedup();
        assert_eq!(names.len(), n, "沒有重複");
        assert!(fs
            .lookup("/d/file-03999-with-a-fairly-long-name", true)
            .unwrap()
            .is_some());
        assert!(fs
            .lookup("/d/file-04000-with-a-fairly-long-name", true)
            .unwrap()
            .is_none());
    }

    #[test]
    fn fragmented_sparse_file_needs_an_extent_index_node() {
        let mut expect = vec![0u8; 400 * 1024];
        for k in 0..25 {
            let chunk = pattern(4096, k);
            expect[k * 16384..k * 16384 + 4096].copy_from_slice(&chunk);
        }
        let e2 = expect.clone();
        let Some(img) = build(
            "sparse",
            &["-t", "ext4", "-b", "4096", "-O", "^has_journal"],
            "8M",
            move |t| {
                use std::io::{Seek, SeekFrom, Write};
                let mut f = std::fs::File::create(t.join("s.bin")).unwrap();
                for k in 0..25usize {
                    f.seek(SeekFrom::Start((k * 16384) as u64)).unwrap();
                    f.write_all(&e2[k * 16384..k * 16384 + 4096]).unwrap();
                }
                f.set_len(400 * 1024).unwrap();
            },
        ) else {
            return;
        };
        let fs = Ext4::open(MemDev(img)).unwrap();
        let f = fs.lookup("/s.bin", true).unwrap().unwrap();
        assert_eq!(f.size, 400 * 1024);
        assert!(fs.extents(&f).unwrap().len() >= 20);
        assert!(le16(&f.fork, 6) > 0, "extent 樹深度應該大於 0");
        assert_eq!(fs.read_data(&f, 1 << 20).unwrap(), expect);
        assert_eq!(fs.read_data(&f, 20000).unwrap(), expect[..20000].to_vec());
    }

    #[test]
    fn old_style_block_map_files_with_indirect_blocks() {
        let body = pattern(600 * 1024, 7);
        let b2 = body.clone();
        let Some(img) = build("ext3", &["-t", "ext3", "-b", "1024"], "8M", move |t| {
            std::fs::write(t.join("big.bin"), &b2).unwrap()
        }) else {
            return;
        };
        let fs = Ext4::open(MemDev(img)).unwrap();
        let f = fs.lookup("/big.bin", true).unwrap().unwrap();
        assert_eq!(f.flags & FL_EXTENTS, 0, "這個檔案不該用 extents");
        assert_eq!(fs.read_data(&f, 1 << 22).unwrap(), body);
    }

    #[test]
    fn inline_data_is_reported_unsupported_not_misread() {
        let Some(img) = build(
            "inline",
            &["-t", "ext4", "-O", "inline_data,^has_journal"],
            "4M",
            |t| std::fs::write(t.join("tiny.txt"), b"hello").unwrap(),
        ) else {
            return;
        };
        let fs = Ext4::open(MemDev(img)).unwrap();
        let f = fs.lookup("/tiny.txt", true);
        match f {
            Err(RawError::Unsupported(_)) => eprintln!("內嵌資料：路徑解析階段就回報不支援"),
            Ok(Some(inode)) => {
                assert!(matches!(
                    fs.read_data(&inode, 100),
                    Err(RawError::Unsupported(_))
                ));
            }
            other => panic!("預期不支援，實際 {:?}", other),
        }
    }
}
