use super::{
    be16, be32, be64, io_err, read_extent_data, Dev, DirEntry, Extent, Inode, RawError, RawFs, Res,
    MAX_DIR_BYTES,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

const SB_MAGIC: u32 = 0x5846_5342;
const INODE_MAGIC: u16 = 0x494e;
const BMAP_MAGIC_V4: u32 = 0x424d_4150;
const BMAP_MAGIC_V5: u32 = 0x424d_4133;
const DIR_DATA_V4: u32 = 0x5844_3244;
const DIR_BLOCK_V4: u32 = 0x5844_3242;
const DIR_DATA_V5: u32 = 0x5844_4433;
const DIR_BLOCK_V5: u32 = 0x5844_4233;
const SYMLINK_MAGIC: u32 = 0x5853_4c4d;

const FMT_LOCAL: u32 = 1;
const FMT_EXTENTS: u32 = 2;
const FMT_BTREE: u32 = 3;
const FL_REALTIME: u32 = 0x100;

const FEAT2_FTYPE: u32 = 0x200;
const VERSION_DIRV2: u16 = 0x2000;
const VERSION_BORG: u16 = 0x4000;
const VERSION_MOREBITS: u16 = 0x8000;
const INCOMPAT_FTYPE: u32 = 0x1;
const INCOMPAT_SPINODES: u32 = 0x2;
const INCOMPAT_META_UUID: u32 = 0x4;
const INCOMPAT_KNOWN: u32 = INCOMPAT_FTYPE | INCOMPAT_SPINODES | INCOMPAT_META_UUID;

const DIR_LEAF_OFFSET_BYTES: u64 = 1 << 35;
const SYMLINK_MAX: u64 = 1024;
const CLUSTER: u64 = 16 * 1024;
const BTREE_BUDGET: u32 = 262_144;
const CACHE_MAX: usize = 2048;

const fn crc32c_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC32C: [u32; 256] = crc32c_table();

fn crc32c_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC32C[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

fn crc_ok(buf: &[u8], off: usize) -> bool {
    if buf.len() < off + 4 {
        return false;
    }
    let mut c = 0xffff_ffffu32;
    c = crc32c_update(c, &buf[..off]);
    c = crc32c_update(c, &[0u8; 4]);
    c = crc32c_update(c, &buf[off + 4..]);
    let stored = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
    stored == !c
}

fn ceil_log2(n: u64) -> u32 {
    if n <= 1 {
        0
    } else {
        64 - (n - 1).leading_zeros()
    }
}

fn timestamp(raw: &[u8], off: usize) -> i64 {
    be32(raw, off) as i32 as i64
}

pub struct Xfs<D: Dev> {
    dev: D,
    bs: u64,
    inode_size: u64,
    ino_blk_log: u32,
    ag_blk_log: u32,
    ag_blocks: u64,
    ag_count: u64,
    dblocks: u64,
    root_ino: u64,
    dir_blk_log: u32,
    v5: bool,
    ftype: bool,
    cache: RefCell<HashMap<u64, Rc<Vec<u8>>>>,
}

impl<D: Dev> Xfs<D> {
    pub fn open(dev: D) -> Res<Self> {
        let mut sb = vec![0u8; 512];
        dev.read_data_at(0, &mut sb).map_err(io_err)?;
        if be32(&sb, 0) != SB_MAGIC {
            return Err(RawError::NotXfs);
        }
        let versionnum = be16(&sb, 100);
        let ver = versionnum & 0xf;
        if ver != 4 && ver != 5 {
            return Err(RawError::Unsupported(format!("XFS 超級區塊版本 {}", ver)));
        }
        if versionnum & VERSION_BORG != 0 {
            return Err(RawError::Unsupported("大小寫不分的檔名".to_string()));
        }
        let bs = be32(&sb, 4) as u64;
        let blocklog = sb[120] as u32;
        if !(512..=65536).contains(&bs) || bs != 1u64 << blocklog {
            return Err(RawError::Corrupt(format!("區塊大小 {}", bs)));
        }
        let sectsize = be16(&sb, 102) as usize;
        if !(512..=4096).contains(&sectsize) {
            return Err(RawError::Corrupt(format!("磁區大小 {}", sectsize)));
        }
        let inode_size = be16(&sb, 104) as u64;
        let inodelog = sb[122] as u32;
        let ino_blk_log = sb[123] as u32;
        if !(256..=2048).contains(&inode_size)
            || inode_size != 1u64 << inodelog
            || bs != inode_size << ino_blk_log
            || be16(&sb, 106) as u64 != 1u64 << ino_blk_log
        {
            return Err(RawError::Corrupt(format!(
                "inode 大小 {}、每區塊 inode 數對不上",
                inode_size
            )));
        }
        let dblocks = be64(&sb, 8);
        let ag_blocks = be32(&sb, 84) as u64;
        let ag_count = be32(&sb, 88) as u64;
        let ag_blk_log = sb[124] as u32;
        if ag_blocks == 0
            || ag_count == 0
            || ag_blk_log != ceil_log2(ag_blocks)
            || dblocks <= (ag_count - 1) * ag_blocks
            || dblocks > ag_count * ag_blocks
        {
            return Err(RawError::Corrupt("分配群組的數字互相矛盾".to_string()));
        }
        if dblocks.checked_mul(bs).is_none() {
            return Err(RawError::Corrupt("裝置大小超出範圍".to_string()));
        }
        let dir_blk_log = sb[192] as u32;
        if bs << dir_blk_log > 65536 {
            return Err(RawError::Corrupt(format!(
                "目錄區塊大小指數 {}",
                dir_blk_log
            )));
        }
        let (v5, ftype);
        if ver == 5 {
            let incompat = be32(&sb, 216);
            if incompat & !INCOMPAT_KNOWN != 0 {
                return Err(RawError::Unsupported(format!(
                    "XFS 新版功能旗標 0x{:x}",
                    incompat & !INCOMPAT_KNOWN
                )));
            }
            if sectsize > sb.len() {
                sb.resize(sectsize, 0);
                dev.read_data_at(0, &mut sb).map_err(io_err)?;
            }
            if !crc_ok(&sb[..sectsize], 224) {
                return Err(RawError::Corrupt("超級區塊的檢查碼不對".to_string()));
            }
            v5 = true;
            ftype = incompat & INCOMPAT_FTYPE != 0;
        } else {
            if versionnum & VERSION_DIRV2 == 0 {
                return Err(RawError::Unsupported("第一版目錄".to_string()));
            }
            let features2 = if versionnum & VERSION_MOREBITS != 0 {
                be32(&sb, 200)
            } else {
                0
            };
            v5 = false;
            ftype = features2 & FEAT2_FTYPE != 0;
        }
        Ok(Xfs {
            dev,
            bs,
            inode_size,
            ino_blk_log,
            ag_blk_log,
            ag_blocks,
            ag_count,
            dblocks,
            root_ino: be64(&sb, 56),
            dir_blk_log,
            v5,
            ftype,
            cache: RefCell::new(HashMap::new()),
        })
    }

    fn dir_block_bytes(&self) -> u64 {
        self.bs << self.dir_blk_log
    }

    fn fsb_linear(&self, fsb: u64, count: u64) -> Res<u64> {
        let agno = fsb >> self.ag_blk_log;
        let agbno = fsb & ((1u64 << self.ag_blk_log) - 1);
        if agno >= self.ag_count || agbno >= self.ag_blocks || agbno + count > self.ag_blocks {
            return Err(RawError::Corrupt(format!("區塊位址 {} 超出群組範圍", fsb)));
        }
        let linear = agno * self.ag_blocks + agbno;
        if linear + count > self.dblocks {
            return Err(RawError::Corrupt(format!("區塊位址 {} 超出裝置範圍", fsb)));
        }
        Ok(linear)
    }

    fn read_block(&self, linear: u64) -> Res<Vec<u8>> {
        let mut buf = vec![0u8; self.bs as usize];
        self.dev
            .read_data_at(linear * self.bs, &mut buf)
            .map_err(io_err)?;
        Ok(buf)
    }

    fn inode_offset(&self, ino: u64) -> Res<u64> {
        let agbno_bits = self.ag_blk_log;
        let off_bits = self.ino_blk_log;
        let agno = ino >> (off_bits + agbno_bits);
        let agbno = (ino >> off_bits) & ((1u64 << agbno_bits) - 1);
        let idx = ino & ((1u64 << off_bits) - 1);
        if ino == 0 || agno >= self.ag_count || agbno >= self.ag_blocks {
            return Err(RawError::Corrupt(format!("inode 編號 {} 超出範圍", ino)));
        }
        let linear = agno * self.ag_blocks + agbno;
        if linear >= self.dblocks {
            return Err(RawError::Corrupt(format!("inode {} 超出裝置範圍", ino)));
        }
        Ok(linear * self.bs + idx * self.inode_size)
    }

    fn inode_raw(&self, ino: u64) -> Res<Vec<u8>> {
        let off = self.inode_offset(ino)?;
        let cluster = CLUSTER.max(self.bs);
        let base = off / cluster * cluster;
        let at = (off - base) as usize;
        let size = self.inode_size as usize;
        let chunk = {
            let cached = self.cache.borrow().get(&base).cloned();
            match cached {
                Some(c) => c,
                None => {
                    let mut buf = vec![0u8; cluster as usize];
                    if self.dev.read_data_at(base, &mut buf).is_err() {
                        let blk = off / self.bs * self.bs;
                        let mut one = vec![0u8; self.bs as usize];
                        self.dev.read_data_at(blk, &mut one).map_err(io_err)?;
                        let rel = (blk - base) as usize;
                        buf[rel..rel + one.len()].copy_from_slice(&one);
                    }
                    let c = Rc::new(buf);
                    let mut map = self.cache.borrow_mut();
                    if map.len() >= CACHE_MAX {
                        map.clear();
                    }
                    map.insert(base, Rc::clone(&c));
                    c
                }
            }
        };
        Ok(chunk[at..at + size].to_vec())
    }

    fn parse_inode(&self, ino: u64, raw: &[u8]) -> Res<Inode> {
        if be16(raw, 0) != INODE_MAGIC {
            return Err(RawError::Corrupt(format!(
                "inode {} 的魔數不對（這個位置不是 inode）",
                ino
            )));
        }
        let version = raw[4];
        let core = match version {
            1 | 2 => 100,
            3 => 176,
            v => return Err(RawError::Unsupported(format!("XFS inode 版本 {}", v))),
        };
        if (version == 3) != self.v5 {
            return Err(RawError::Corrupt(format!(
                "inode {} 的版本 {} 和檔案系統不符",
                ino, version
            )));
        }
        if version == 3 {
            if !crc_ok(raw, 100) {
                return Err(RawError::Corrupt(format!("inode {} 的檢查碼不對", ino)));
            }
            if be64(raw, 152) != ino {
                return Err(RawError::Corrupt(format!(
                    "inode 裡寫的編號和位置不符（{}）",
                    ino
                )));
            }
        }
        let mode = be16(raw, 2);
        if mode == 0 {
            return Err(RawError::Corrupt(format!("inode {} 沒有在使用", ino)));
        }
        let format = raw[5] as u32;
        let size = be64(raw, 56);
        if size > i64::MAX as u64 {
            return Err(RawError::Corrupt(format!("inode {} 的大小不合理", ino)));
        }
        let forkoff = raw[82] as usize;
        let fork_len = if forkoff != 0 {
            forkoff * 8
        } else {
            raw.len().saturating_sub(core)
        };
        if core + fork_len > raw.len() {
            return Err(RawError::Corrupt(format!(
                "inode {} 的資料分支超出範圍",
                ino
            )));
        }
        let di_flags = be16(raw, 90);
        let mut flags = format;
        if di_flags & 0x1 != 0 {
            flags |= FL_REALTIME;
        }
        let links = if version == 1 {
            be16(raw, 6) as u32
        } else {
            be32(raw, 16)
        };
        Ok(Inode {
            ino,
            mode,
            size,
            links,
            flags,
            atime: timestamp(raw, 32),
            mtime: timestamp(raw, 40),
            ctime: timestamp(raw, 48),
            crtime: if version == 3 {
                Some(timestamp(raw, 144))
            } else {
                None
            },
            fork: raw[core..core + fork_len].to_vec(),
            aux: be32(raw, 76),
        })
    }

    #[cfg(test)]
    pub fn into_dyn(self) -> Box<dyn RawFs>
    where
        D: 'static,
    {
        Box::new(self)
    }

    fn format_of(inode: &Inode) -> u32 {
        inode.flags & 0xff
    }

    fn extents(&self, inode: &Inode) -> Res<Vec<Extent>> {
        if inode.flags & FL_REALTIME != 0 {
            return Err(RawError::Unsupported(
                "放在即時（realtime）裝置上的檔案".to_string(),
            ));
        }
        let mut out = Vec::new();
        match Self::format_of(inode) {
            FMT_EXTENTS => {
                let n = inode.aux as usize;
                if n.checked_mul(16).is_none_or(|b| b > inode.fork.len()) {
                    return Err(RawError::Corrupt("區段個數超出資料分支".to_string()));
                }
                for i in 0..n {
                    self.push_record(&inode.fork[i * 16..i * 16 + 16], &mut out)?;
                }
            }
            FMT_BTREE => {
                let mut budget = BTREE_BUDGET;
                self.walk_root(inode, &mut out, &mut budget)?;
            }
            f => {
                return Err(RawError::Unsupported(format!("資料分支格式 {}", f)));
            }
        }
        out.sort_by_key(|e| e.lblk);
        Ok(out)
    }

    fn push_record(&self, rec: &[u8], out: &mut Vec<Extent>) -> Res<()> {
        let l0 = be64(rec, 0);
        let l1 = be64(rec, 8);
        let unwritten = l0 >> 63 != 0;
        let startoff = (l0 & 0x7fff_ffff_ffff_ffff) >> 9;
        let startblock = ((l0 & 0x1ff) << 43) | (l1 >> 21);
        let count = l1 & 0x1f_ffff;
        if count == 0 {
            return Ok(());
        }
        if startoff.saturating_add(count) > (i64::MAX as u64) / self.bs {
            return Err(RawError::Corrupt("區段的檔案內位置不合理".to_string()));
        }
        let pblk = self.fsb_linear(startblock, count)?;
        out.push(Extent {
            lblk: startoff,
            len: count,
            pblk,
            unwritten,
        });
        Ok(())
    }

    fn walk_root(&self, inode: &Inode, out: &mut Vec<Extent>, budget: &mut u32) -> Res<()> {
        let fork = &inode.fork;
        if fork.len() < 4 {
            return Err(RawError::Corrupt("btree 根太小".to_string()));
        }
        let level = be16(fork, 0) as u32;
        let numrecs = be16(fork, 2) as usize;
        let maxrecs = (fork.len() - 4) / 16;
        if level == 0 || level > 8 || numrecs > maxrecs {
            return Err(RawError::Corrupt(
                "btree 根的層數或項目數不合理".to_string(),
            ));
        }
        let ptrs = 4 + maxrecs * 8;
        for i in 0..numrecs {
            let fsb = be64(fork, ptrs + i * 8);
            self.walk_block(inode.ino, fsb, level - 1, out, budget)?;
        }
        Ok(())
    }

    fn walk_block(
        &self,
        owner: u64,
        fsb: u64,
        expect_level: u32,
        out: &mut Vec<Extent>,
        budget: &mut u32,
    ) -> Res<()> {
        if *budget == 0 {
            return Err(RawError::Corrupt("區段 btree 的區塊太多".to_string()));
        }
        *budget -= 1;
        let data = self.read_block(self.fsb_linear(fsb, 1)?)?;
        let magic = be32(&data, 0);
        let hdr = match (magic, self.v5) {
            (BMAP_MAGIC_V4, false) => 24,
            (BMAP_MAGIC_V5, true) => 72,
            _ => {
                return Err(RawError::Corrupt("區段 btree 區塊的魔數不對".to_string()));
            }
        };
        if self.v5 {
            if !crc_ok(&data, 64) {
                return Err(RawError::Corrupt("區段 btree 區塊的檢查碼不對".to_string()));
            }
            if be64(&data, 56) != owner {
                return Err(RawError::Corrupt(
                    "區段 btree 區塊屬於別的 inode".to_string(),
                ));
            }
        }
        let level = be16(&data, 4) as u32;
        let numrecs = be16(&data, 6) as usize;
        if level != expect_level {
            return Err(RawError::Corrupt("區段 btree 的層數對不上".to_string()));
        }
        if level == 0 {
            if hdr + numrecs * 16 > data.len() {
                return Err(RawError::Corrupt(
                    "區段 btree 葉子的項目數超出區塊".to_string(),
                ));
            }
            for i in 0..numrecs {
                self.push_record(&data[hdr + i * 16..hdr + i * 16 + 16], out)?;
            }
        } else {
            let maxrecs = (data.len() - hdr) / 16;
            if numrecs > maxrecs {
                return Err(RawError::Corrupt(
                    "區段 btree 內部節點的項目數超出區塊".to_string(),
                ));
            }
            let ptrs = hdr + maxrecs * 8;
            for i in 0..numrecs {
                let child = be64(&data, ptrs + i * 8);
                self.walk_block(owner, child, level - 1, out, budget)?;
            }
        }
        Ok(())
    }

    fn read_short_dir(&self, dir: &Inode) -> Res<Vec<DirEntry>> {
        let fork = &dir.fork[..dir.fork.len().min(dir.size as usize)];
        if fork.len() < 6 {
            return Err(RawError::Corrupt("短格式目錄太小".to_string()));
        }
        let count = fork[0] as usize;
        let isz = if fork[1] != 0 { 8 } else { 4 };
        let read_ino = |o: usize| -> Res<u64> {
            if o + isz > fork.len() {
                return Err(RawError::Corrupt("短格式目錄的項目超出範圍".to_string()));
            }
            Ok(if isz == 8 {
                be64(fork, o)
            } else {
                be32(fork, o) as u64
            })
        };
        let mut out = vec![
            DirEntry {
                ino: dir.ino,
                name: b".".to_vec(),
                file_type: 2,
            },
            DirEntry {
                ino: read_ino(2)?,
                name: b"..".to_vec(),
                file_type: 2,
            },
        ];
        let mut o = 2 + isz;
        for _ in 0..count {
            if o + 3 > fork.len() {
                return Err(RawError::Corrupt("短格式目錄的項目超出範圍".to_string()));
            }
            let namelen = fork[o] as usize;
            let name_at = o + 3;
            let ft_at = name_at + namelen;
            let ino_at = ft_at + usize::from(self.ftype);
            if namelen == 0 || ino_at + isz > fork.len() {
                return Err(RawError::Corrupt("短格式目錄的項目超出範圍".to_string()));
            }
            out.push(DirEntry {
                ino: read_ino(ino_at)?,
                name: fork[name_at..ft_at].to_vec(),
                file_type: if self.ftype { fork[ft_at] } else { 0 },
            });
            o = ino_at + isz;
        }
        Ok(out)
    }

    fn parse_dir_block(&self, blk: &[u8], out: &mut Vec<DirEntry>) -> Res<()> {
        let magic = be32(blk, 0);
        if magic == 0 {
            return Ok(());
        }
        let (hdr, is_block) = match (magic, self.v5) {
            (DIR_DATA_V4, false) => (16usize, false),
            (DIR_BLOCK_V4, false) => (16, true),
            (DIR_DATA_V5, true) => (64, false),
            (DIR_BLOCK_V5, true) => (64, true),
            _ => {
                return Err(RawError::Corrupt("目錄資料區塊的魔數不對".to_string()));
            }
        };
        if self.v5 && !crc_ok(blk, 4) {
            return Err(RawError::Corrupt("目錄資料區塊的檢查碼不對".to_string()));
        }
        let end = if is_block {
            let count = be32(blk, blk.len() - 8) as usize;
            blk.len()
                .checked_sub(8)
                .and_then(|e| e.checked_sub(count.checked_mul(8)?))
                .filter(|e| *e >= hdr)
                .ok_or_else(|| RawError::Corrupt("單區塊目錄的葉子索引超出區塊".to_string()))?
        } else {
            blk.len()
        };
        let mut o = hdr;
        while o + 8 <= end {
            if be16(blk, o) == 0xffff {
                let len = be16(blk, o + 2) as usize;
                if len < 8 || len % 8 != 0 || o + len > end {
                    return Err(RawError::Corrupt("目錄裡的空閒區段長度不合理".to_string()));
                }
                o += len;
                continue;
            }
            if o + 9 > end {
                return Err(RawError::Corrupt("目錄項目超出區塊".to_string()));
            }
            let namelen = blk[o + 8] as usize;
            let used = 9 + namelen + usize::from(self.ftype) + 2;
            let size = used.div_ceil(8) * 8;
            if namelen == 0 || o + size > end {
                return Err(RawError::Corrupt("目錄項目的長度不合理".to_string()));
            }
            out.push(DirEntry {
                ino: be64(blk, o),
                name: blk[o + 9..o + 9 + namelen].to_vec(),
                file_type: if self.ftype { blk[o + 9 + namelen] } else { 0 },
            });
            o += size;
        }
        Ok(())
    }

    fn read_remote_link(&self, inode: &Inode) -> Res<Vec<u8>> {
        let size = inode.size as usize;
        let extents = self.extents(inode)?;
        if !self.v5 {
            let mut out = Vec::with_capacity(size);
            read_extent_data(&self.dev, self.bs, &extents, inode.size, true, &mut |c| {
                out.extend_from_slice(c)
            })?;
            return Ok(out);
        }
        let mut out = vec![0u8; size];
        let mut seen = 0usize;
        for e in &extents {
            for i in 0..e.len {
                let data = self.read_block(e.pblk + i)?;
                if be32(&data, 0) != SYMLINK_MAGIC || !crc_ok(&data, 12) {
                    return Err(RawError::Corrupt(
                        "遠端符號連結區塊的魔數或檢查碼不對".to_string(),
                    ));
                }
                let at = be32(&data, 4) as usize;
                let bytes = be32(&data, 8) as usize;
                if 56 + bytes > data.len() || at.checked_add(bytes).is_none_or(|t| t > size) {
                    return Err(RawError::Corrupt(
                        "遠端符號連結區塊的長度不合理".to_string(),
                    ));
                }
                out[at..at + bytes].copy_from_slice(&data[56..56 + bytes]);
                seen += bytes;
            }
        }
        if seen != size {
            return Err(RawError::Corrupt("遠端符號連結的長度對不上".to_string()));
        }
        Ok(out)
    }
}

impl<D: Dev> RawFs for Xfs<D> {
    fn root_ino(&self) -> u64 {
        self.root_ino
    }

    fn inode(&self, ino: u64) -> Res<Inode> {
        let raw = self.inode_raw(ino)?;
        match self.parse_inode(ino, &raw) {
            Err(RawError::Corrupt(_)) => {
                self.cache.borrow_mut().clear();
                let again = self.inode_raw(ino)?;
                self.parse_inode(ino, &again)
            }
            other => other,
        }
    }

    fn read_to(&self, inode: &Inode, max: u64, sink: &mut dyn FnMut(&[u8])) -> Res<u64> {
        let total = inode.size.min(max);
        if total == 0 {
            return Ok(0);
        }
        if inode.is_symlink() {
            let target = self.read_link(inode)?;
            let n = (total as usize).min(target.len());
            sink(&target[..n]);
            return Ok(n as u64);
        }
        if Self::format_of(inode) == FMT_LOCAL {
            return Err(RawError::Unsupported(
                "資料直接放在 inode 裡的一般檔".to_string(),
            ));
        }
        let extents = self.extents(inode)?;
        read_extent_data(&self.dev, self.bs, &extents, total, true, sink)
    }

    fn read_link(&self, inode: &Inode) -> Res<Vec<u8>> {
        if !inode.is_symlink() {
            return Err(RawError::Corrupt("不是符號連結".to_string()));
        }
        if inode.size == 0 || inode.size > SYMLINK_MAX {
            return Err(RawError::Corrupt(format!("符號連結長度 {}", inode.size)));
        }
        match Self::format_of(inode) {
            FMT_LOCAL => {
                let n = inode.size as usize;
                if n > inode.fork.len() {
                    return Err(RawError::Corrupt("內嵌符號連結超出資料分支".to_string()));
                }
                Ok(inode.fork[..n].to_vec())
            }
            FMT_EXTENTS => self.read_remote_link(inode),
            f => Err(RawError::Unsupported(format!(
                "符號連結的資料分支格式 {}",
                f
            ))),
        }
    }

    fn read_dir(&self, dir: &Inode) -> Res<Vec<DirEntry>> {
        if !dir.is_dir() {
            return Err(RawError::Corrupt("不是目錄".to_string()));
        }
        if Self::format_of(dir) == FMT_LOCAL {
            return self.read_short_dir(dir);
        }
        let leaf_at = DIR_LEAF_OFFSET_BYTES / self.bs;
        let data_exts: Vec<Extent> = self
            .extents(dir)?
            .into_iter()
            .filter(|e| e.lblk < leaf_at)
            .collect();
        let blocks = data_exts.iter().map(|e| e.lblk + e.len).max().unwrap_or(0);
        let total = blocks * self.bs;
        if total > MAX_DIR_BYTES {
            return Err(RawError::Unsupported("目錄資料太大".to_string()));
        }
        if total % self.dir_block_bytes() != 0 {
            return Err(RawError::Corrupt(
                "目錄資料的長度不是目錄區塊的整數倍".to_string(),
            ));
        }
        let mut data = Vec::with_capacity(total as usize);
        read_extent_data(&self.dev, self.bs, &data_exts, total, true, &mut |c| {
            data.extend_from_slice(c)
        })?;
        let mut out = Vec::new();
        for blk in data.chunks_exact(self.dir_block_bytes() as usize) {
            self.parse_dir_block(blk, &mut out)?;
        }
        Ok(out)
    }

    fn forget_cached(&self) {
        self.cache.borrow_mut().clear();
    }

    fn lags_behind_memory(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io;
    use std::os::unix::fs::FileExt;

    struct FileImg(std::fs::File);

    impl Dev for FileImg {
        fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
            self.0.read_exact_at(buf, off)
        }
    }

    fn open_img(path: &str) -> Xfs<FileImg> {
        Xfs::open(FileImg(std::fs::File::open(path).unwrap())).unwrap()
    }

    #[test]
    fn crc32c_known_answer() {
        let c = !crc32c_update(0xffff_ffff, b"123456789");
        assert_eq!(c, 0xE306_9283);
    }

    #[test]
    fn garbage_is_not_xfs() {
        struct Zero;
        impl Dev for Zero {
            fn read_at(&self, _off: u64, buf: &mut [u8]) -> io::Result<()> {
                buf.fill(0);
                Ok(())
            }
        }
        assert!(matches!(Xfs::open(Zero), Err(RawError::NotXfs)));
    }

    struct Row {
        ino: u64,
        size: u64,
        nlink: u32,
        kind: char,
        mode: u16,
        mtime: i64,
        ctime: i64,
        link: String,
    }

    fn read_find(path: &str) -> BTreeMap<String, Row> {
        parse_find(&std::fs::read_to_string(path).unwrap())
    }

    fn parse_find(text: &str) -> BTreeMap<String, Row> {
        let mut m = BTreeMap::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 9, "{}", line);
            m.insert(
                f[0].to_string(),
                Row {
                    ino: f[1].parse().unwrap(),
                    size: f[2].parse().unwrap(),
                    nlink: f[3].parse().unwrap(),
                    kind: f[4].chars().next().unwrap(),
                    mode: u16::from_str_radix(f[5], 8).unwrap(),
                    mtime: f[6].parse().unwrap(),
                    ctime: f[7].parse().unwrap(),
                    link: f[8].to_string(),
                },
            );
        }
        m
    }

    fn kind_of(i: &Inode) -> char {
        if i.is_regular() {
            'f'
        } else if i.is_dir() {
            'd'
        } else if i.is_symlink() {
            'l'
        } else {
            match i.mode & 0xF000 {
                0x1000 => 'p',
                0x2000 => 'c',
                0x6000 => 'b',
                0xC000 => 's',
                _ => '?',
            }
        }
    }

    fn check_tree(
        fs: &dyn RawFs,
        truth: &BTreeMap<String, Row>,
        v5: bool,
        has_ftype: bool,
    ) -> usize {
        let mut seen = 0usize;
        let mut stack = vec![(fs.root_ino(), "/".to_string())];
        let mut visited = std::collections::BTreeSet::new();
        while let Some((ino, path)) = stack.pop() {
            let inode = fs
                .inode(ino)
                .unwrap_or_else(|e| panic!("{}：{}", path, e.text()));
            let t = truth
                .get(&path)
                .unwrap_or_else(|| panic!("核心清單沒有 {}", path));
            assert_eq!(inode.ino, t.ino, "{} inode", path);
            assert_eq!(inode.size, t.size, "{} 大小", path);
            assert_eq!(inode.links, t.nlink, "{} 連結數", path);
            assert_eq!(kind_of(&inode), t.kind, "{} 種類", path);
            assert_eq!(inode.mode & 0o7777, t.mode, "{} 權限", path);
            assert_eq!(inode.mtime, t.mtime, "{} 修改時間", path);
            assert_eq!(inode.ctime, t.ctime, "{} 變更時間", path);
            assert_eq!(inode.crtime.is_some(), v5, "{} 建立時間", path);
            if let Some(c) = inode.crtime {
                assert!(
                    c <= inode.ctime && c > 1_700_000_000,
                    "{} 建立時間不合理 {}",
                    path,
                    c
                );
            }
            if inode.is_symlink() {
                let target = String::from_utf8(fs.read_link(&inode).unwrap()).unwrap();
                assert_eq!(target, t.link, "{} 連結目標", path);
            }
            seen += 1;
            if !inode.is_dir() || !visited.insert(ino) {
                continue;
            }
            let entries = fs
                .read_dir(&inode)
                .unwrap_or_else(|e| panic!("{}：{}", path, e.text()));
            let mut names = std::collections::BTreeSet::new();
            for e in entries {
                let name = String::from_utf8(e.name.clone()).unwrap();
                if name == "." || name == ".." {
                    continue;
                }
                assert!(
                    names.insert(name.clone()),
                    "{} 裡的 {} 重複出現",
                    path,
                    name
                );
                let child = if path == "/" {
                    format!("/{}", name)
                } else {
                    format!("{}/{}", path, name)
                };
                let ct = truth
                    .get(&child)
                    .unwrap_or_else(|| panic!("核心清單沒有 {}", child));
                assert_eq!(e.ino, ct.ino, "{} 目錄項目的 inode", child);
                if has_ftype {
                    let want = match ct.kind {
                        'f' => 1,
                        'd' => 2,
                        'c' => 3,
                        'b' => 4,
                        'p' => 5,
                        's' => 6,
                        'l' => 7,
                        _ => 0,
                    };
                    assert_eq!(e.file_type, want, "{} 型別", child);
                } else {
                    assert_eq!(e.file_type, 0, "{} 沒有型別欄位時要是 0", child);
                }
                stack.push((e.ino, child));
            }
            let prefix = if path == "/" {
                "/".to_string()
            } else {
                format!("{}/", path)
            };
            let want = truth
                .keys()
                .filter(|k| {
                    k.starts_with(&prefix)
                        && !k[prefix.len()..].contains('/')
                        && k.len() > prefix.len()
                })
                .count();
            assert_eq!(names.len(), want, "{} 的名字個數", path);
        }
        seen
    }

    fn pattern_tool(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 7 + 3) % 251) as u8).collect()
    }

    fn check_stream(fs: &dyn RawFs, path: &str, rule: &dyn Fn(u64) -> u8) -> u64 {
        let inode = fs
            .lookup(path, true)
            .unwrap()
            .unwrap_or_else(|| panic!("找不到 {}", path));
        let mut pos = 0u64;
        let n = fs
            .read_to(&inode, u64::MAX, &mut |c| {
                for (i, b) in c.iter().enumerate() {
                    assert_eq!(*b, rule(pos + i as u64), "{} 位置 {}", path, pos + i as u64);
                }
                pos += c.len() as u64;
            })
            .unwrap();
        assert_eq!(n, inode.size, "{} 讀到的長度", path);
        n
    }

    use crate::rawfs_fixture::{
        open_xfs_v4, open_xfs_v5, xfs_v5_image, SparseDev, XFS_V4_FIND, XFS_V5_FIND,
    };

    fn v5_with(mutate: impl FnOnce(&mut SparseDev)) -> Res<Xfs<SparseDev>> {
        let mut dev = xfs_v5_image();
        mutate(&mut dev);
        Xfs::open(dev)
    }

    fn flip(dev: &mut SparseDev, off: u64) {
        let c = dev
            .chunks
            .get_mut(&(off / 4096))
            .expect("要改的位置所在區塊不是全零");
        c[(off % 4096) as usize] ^= 0xff;
    }

    #[test]
    fn v5_fixture_matches_the_kernel_view() {
        let fs = open_xfs_v5();
        assert!(fs.v5 && fs.ftype);
        assert_eq!(fs.bs, 1024);
        assert_eq!(fs.dir_block_bytes(), 4096, "目錄區塊比檔案系統區塊大");
        let truth = parse_find(XFS_V5_FIND);
        let seen = check_tree(&fs, &truth, true, true);
        assert_eq!(seen, truth.len(), "走過的名字數要等於核心清單");
        let shift = fs.ino_blk_log + fs.ag_blk_log;
        assert!(
            truth.values().any(|r| r.ino >> shift > 0),
            "測試樹應該有放在第二個群組的 inode"
        );
        assert!(truth.values().any(|r| r.ino >> shift == 0));
    }

    #[test]
    fn v4_fixture_matches_the_kernel_view_without_crc_ftype_or_crtime() {
        let fs = open_xfs_v4();
        assert!(!fs.v5 && !fs.ftype);
        assert_eq!(fs.inode_size, 256);
        let truth = parse_find(XFS_V4_FIND);
        let seen = check_tree(&fs, &truth, false, false);
        assert_eq!(seen, truth.len());
        let shift = fs.ino_blk_log + fs.ag_blk_log;
        assert!(truth.values().any(|r| r.ino >> shift > 0));
    }

    #[test]
    fn v5_fixture_file_contents_follow_the_build_rules() {
        let fs = open_xfs_v5();
        let tool = fs.lookup("/usr/bin/tool", true).unwrap().unwrap();
        assert_eq!(fs.read_data(&tool, 1 << 20).unwrap(), pattern_tool(3000));
        assert_eq!(fs.read_data(&tool, 100).unwrap().len(), 100, "上限要生效");
        let text = String::from_utf8(
            fs.read_data(
                &fs.lookup("/etc/systemd/system/svc.service", true)
                    .unwrap()
                    .unwrap(),
                4096,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(text.contains("ExecStart=/usr/bin/tool --serve"), "{}", text);
        let frag = fs.lookup("/big/frag", true).unwrap().unwrap();
        assert_eq!(Xfs::<SparseDev>::format_of(&frag), FMT_BTREE);
        assert_eq!(
            check_stream(&fs, "/big/frag", &|p| if (p / 1024) % 2 == 0 {
                0x41
            } else {
                0
            }),
            80 * 1024
        );
        assert_eq!(
            check_stream(
                &fs,
                "/big/sparse",
                &|p| if (100 * 1024..102 * 1024).contains(&p) {
                    0x44
                } else {
                    0
                }
            ),
            200 * 1024
        );
        assert_eq!(
            check_stream(&fs, "/big/unwritten", &|p| if (2048..4096).contains(&p) {
                0x45
            } else {
                0
            }),
            16 * 1024
        );
        assert_eq!(check_stream(&fs, "/big/one-block", &|_| b'B'), 1024);
        assert_eq!(check_stream(&fs, "/big/odd", &|_| b'C'), 1025);
        assert_eq!(
            fs.read_data(&fs.lookup("/big/empty", true).unwrap().unwrap(), 10)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(fs.lookup("/d/sf/abs", true).unwrap().unwrap().ino, tool.ino);
        assert_eq!(
            fs.lookup("/d/sf/abs", false).unwrap().unwrap().mode & 0xF000,
            0xA000
        );
        assert!(fs.lookup("/d/sf/nonexistent", true).unwrap().is_none());
        assert!(fs.lookup("/usr/bin/tool/x", true).unwrap().is_none());
    }

    fn dir_shape<D: Dev>(fs: &Xfs<D>, path: &str) -> (u32, u64, u64) {
        let dir = fs.lookup(path, true).unwrap().unwrap();
        let fmt = Xfs::<D>::format_of(&dir);
        if fmt == FMT_LOCAL {
            return (fmt, 0, 0);
        }
        let leaf_at = DIR_LEAF_OFFSET_BYTES / fs.bs;
        let ex = fs.extents(&dir).unwrap();
        let data: u64 = ex.iter().filter(|e| e.lblk < leaf_at).map(|e| e.len).sum();
        let beyond: u64 = ex.iter().filter(|e| e.lblk >= leaf_at).map(|e| e.len).sum();
        (
            fmt,
            data * fs.bs / fs.dir_block_bytes(),
            beyond * fs.bs / fs.dir_block_bytes(),
        )
    }

    fn names_in<D: Dev>(fs: &Xfs<D>, path: &str) -> usize {
        let dir = fs.lookup(path, true).unwrap().unwrap();
        fs.read_dir(&dir)
            .unwrap()
            .iter()
            .filter(|e| e.name != b"." && e.name != b"..")
            .count()
    }

    #[test]
    fn v5_fixture_shapes_cover_every_directory_form() {
        let fs = open_xfs_v5();
        assert_eq!(dir_shape(&fs, "/d/sf").0, FMT_LOCAL);
        assert_eq!(dir_shape(&fs, "/d/empty").0, FMT_LOCAL);
        assert_eq!(dir_shape(&fs, "/d/blk"), (FMT_EXTENTS, 1, 0));
        let (_, data, beyond) = dir_shape(&fs, "/d/leaf");
        assert!(data >= 2 && beyond == 1, "葉子形式 {} {}", data, beyond);
        let (_, data, beyond) = dir_shape(&fs, "/d/node");
        assert!(data >= 6 && beyond >= 3, "節點形式 {} {}", data, beyond);
        for (d, n) in [
            ("/d/blk", 12),
            ("/d/leaf", 120),
            ("/d/node", 600),
            ("/d/sf", 8),
            ("/d/empty", 0),
        ] {
            assert_eq!(names_in(&fs, d), n, "{}", d);
        }
    }

    #[test]
    fn v4_fixture_shapes_cover_short_block_and_leaf_with_one_block_directories() {
        let fs = open_xfs_v4();
        assert_eq!(
            fs.dir_block_bytes(),
            fs.bs,
            "V4 測試映像的目錄區塊和檔案系統區塊一樣大"
        );
        assert_eq!(dir_shape(&fs, "/d/sf").0, FMT_LOCAL);
        assert_eq!(dir_shape(&fs, "/d/blk"), (FMT_EXTENTS, 1, 0));
        let (_, data, beyond) = dir_shape(&fs, "/d/leaf");
        assert!(data >= 2 && beyond == 1, "葉子形式 {} {}", data, beyond);
        for (d, n) in [("/d/blk", 12), ("/d/leaf", 120), ("/d/sf", 8)] {
            assert_eq!(names_in(&fs, d), n, "{}", d);
        }
    }

    #[test]
    fn unsupported_features_are_said_not_guessed() {
        let r = v5_with(|d| d.chunks.get_mut(&0).unwrap()[219] |= 0x08);
        assert!(
            matches!(r, Err(RawError::Unsupported(ref w)) if w.contains("0x8")),
            "{:?}",
            r.err()
        );
        let r = v5_with(|d| d.chunks.get_mut(&0).unwrap()[100] |= 0x40);
        assert!(matches!(r, Err(RawError::Unsupported(_))), "{:?}", r.err());
        let r = v5_with(|d| d.chunks.get_mut(&0).unwrap()[300] ^= 1);
        assert!(
            matches!(r, Err(RawError::Corrupt(ref w)) if w.contains("檢查碼")),
            "{:?}",
            r.err()
        );
        let r = v5_with(|d| d.chunks.get_mut(&0).unwrap()[6] ^= 0x01);
        assert!(matches!(r, Err(RawError::Corrupt(_))), "{:?}", r.err());
    }

    #[test]
    fn corrupted_metadata_is_rejected_by_the_checksum() {
        let fs = open_xfs_v5();
        let tool = fs.lookup("/usr/bin/tool", true).unwrap().unwrap();
        let ino_off = fs.inode_offset(tool.ino).unwrap();
        let bad = v5_with(|d| flip(d, ino_off + 19)).unwrap();
        let e = bad.inode(tool.ino).unwrap_err();
        assert!(
            matches!(e, RawError::Corrupt(ref w) if w.contains("檢查碼")),
            "{:?}",
            e
        );
        let leaf = fs.lookup("/d/leaf", true).unwrap().unwrap();
        let first = fs.extents(&leaf).unwrap()[0];
        let bad = v5_with(|d| flip(d, first.pblk * 1024 + 100)).unwrap();
        let leaf2 = bad.lookup("/d/leaf", true).unwrap().unwrap();
        let e = bad.read_dir(&leaf2).unwrap_err();
        assert!(
            matches!(e, RawError::Corrupt(ref w) if w.contains("檢查碼")),
            "{:?}",
            e
        );
        let frag = fs.lookup("/big/frag", true).unwrap().unwrap();
        let child = be64(&frag.fork, 4 + (frag.fork.len() - 4) / 16 * 8);
        let lin = fs.fsb_linear(child, 1).unwrap();
        let bad = v5_with(|d| flip(d, lin * 1024 + 80)).unwrap();
        let frag2 = bad.lookup("/big/frag", true).unwrap().unwrap();
        assert!(bad.extents(&frag2).is_err());
    }

    fn exercise(fs: &dyn RawFs) {
        let mut todo = vec![fs.root_ino()];
        let mut seen = std::collections::BTreeSet::new();
        let mut budget = 3000;
        while let Some(ino) = todo.pop() {
            if budget == 0 || !seen.insert(ino) {
                continue;
            }
            budget -= 1;
            let Ok(inode) = fs.inode(ino) else { continue };
            if inode.is_dir() {
                if let Ok(entries) = fs.read_dir(&inode) {
                    todo.extend(
                        entries
                            .iter()
                            .filter(|e| e.name != b"." && e.name != b"..")
                            .map(|e| e.ino),
                    );
                }
            } else if inode.is_symlink() {
                let _ = fs.read_link(&inode);
            } else {
                let _ = fs.read_data(&inode, 64 * 1024);
            }
        }
    }

    #[test]
    fn corrupted_images_never_panic() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for v5 in [true, false] {
            let base = if v5 {
                xfs_v5_image()
            } else {
                crate::rawfs_fixture::xfs_v4_image()
            };
            let idxs: Vec<u64> = {
                let mut v: Vec<u64> = base.chunks.keys().copied().collect();
                v.sort();
                v
            };
            for round in 0..150 {
                let mut dev = if v5 {
                    xfs_v5_image()
                } else {
                    crate::rawfs_fixture::xfs_v4_image()
                };
                for _ in 0..(1 + round % 4) {
                    let c = idxs[(next() % idxs.len() as u64) as usize];
                    let at = (next() % 4096) as usize;
                    let chunk = dev.chunks.get_mut(&c).unwrap();
                    chunk[at] = chunk[at].wrapping_add(1 + (next() % 255) as u8);
                }
                if let Ok(fs) = Xfs::open(dev) {
                    exercise(&fs);
                }
            }
        }
    }

    #[test]
    fn a_free_or_wrong_inode_number_is_an_error_not_a_guess() {
        let fs = open_xfs_v5();
        assert!(fs.inode(0).is_err());
        assert!(fs.inode(u64::MAX >> 8).is_err(), "超出群組範圍");
        let used: std::collections::BTreeSet<u64> =
            parse_find(XFS_V5_FIND).values().map(|r| r.ino).collect();
        let max = *used.iter().max().unwrap();
        let free = (max + 1..max + 64).find(|i| !used.contains(i)).unwrap();
        let e = fs.inode(free).unwrap_err();
        assert!(matches!(e, RawError::Corrupt(_)), "{:?}", e);
    }

    #[test]
    #[ignore = "需要外部映像檔"]
    fn real_xfs_image_matches_the_kernel_view() {
        let (Ok(img), Ok(find)) = (std::env::var("RK_XFS_IMG"), std::env::var("RK_XFS_FIND"))
        else {
            panic!("請設定 RK_XFS_IMG 與 RK_XFS_FIND");
        };
        let kind = std::env::var("RK_XFS_KIND").unwrap_or_else(|_| "v5".into());
        let fs = open_img(&img);
        assert_eq!(fs.v5, kind.starts_with("v5"), "格式版本");
        let truth = read_find(&find);
        let seen = check_tree(&fs, &truth, fs.v5, fs.ftype);
        assert_eq!(seen, truth.len(), "走過的名字數要等於核心清單");
        let tool = fs.lookup("/usr/bin/tool", true).unwrap().unwrap();
        assert_eq!(fs.read_data(&tool, 1 << 20).unwrap(), pattern_tool(10_000));
        let n = check_stream(&fs, "/big/frag", &|p| {
            if (p / 4096) % 2 == 0 {
                0x41
            } else {
                0
            }
        });
        assert_eq!(n, 48 << 20);
        let n = check_stream(&fs, "/big/sparse", &|p| {
            if (50 << 20..(50 << 20) + 4096).contains(&p) {
                0x44
            } else {
                0
            }
        });
        assert_eq!(n, 100 << 20);
        let n = check_stream(&fs, "/big/unwritten", &|p| {
            if (4096..8192).contains(&p) {
                0x45
            } else {
                0
            }
        });
        assert_eq!(n, 1 << 20);
        check_stream(&fs, "/big/one-block", &|_| b'B');
        check_stream(&fs, "/big/odd", &|_| b'C');
        let via = fs.lookup("/d/sf/abs", true).unwrap().unwrap();
        assert_eq!(via.ino, tool.ino);
        assert!(fs.lookup("/d/sf/nonexistent", true).unwrap().is_none());
    }
}
