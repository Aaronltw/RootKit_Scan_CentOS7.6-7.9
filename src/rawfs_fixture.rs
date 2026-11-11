use crate::rawfs::xfs::Xfs;
use crate::rawfs::{Dev, Ext4};
use std::collections::HashMap;
use std::io;

pub struct MemDev(pub Vec<u8>);

impl Dev for MemDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let off = off as usize;
        if off + buf.len() > self.0.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "超出映像檔"));
        }
        buf.copy_from_slice(&self.0[off..off + buf.len()]);
        Ok(())
    }
}

pub const TOOL_SIZE: u64 = 10_000;

pub fn tool_byte(i: usize) -> u8 {
    ((i * 7 + 3) % 251) as u8
}

const BLOCK: usize = 4096;

fn decode(text: &str) -> Vec<u8> {
    let mut img = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let (kind, rest) = line.split_once(' ').expect("映像檔文字格式錯誤");
        match kind {
            "Z" => img.resize(img.len() + rest.trim().parse::<usize>().unwrap() * BLOCK, 0),
            "D" => {
                let hex = rest.trim();
                assert_eq!(
                    hex.len(),
                    BLOCK * 2,
                    "一個區塊要有 {} 個十六進位字元",
                    BLOCK * 2
                );
                for i in (0..hex.len()).step_by(2) {
                    img.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
                }
            }
            _ => panic!("不認得的映像檔行 {}", kind),
        }
    }
    img
}

pub fn small_image() -> Vec<u8> {
    decode(include_str!("testdata/ext4-small.txt"))
}

pub fn open_small() -> Ext4<MemDev> {
    Ext4::open(MemDev(small_image())).expect("測試映像應該能打開")
}

pub struct SparseDev {
    pub len: u64,
    pub chunks: HashMap<u64, Vec<u8>>,
}

impl Dev for SparseDev {
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        if off + buf.len() as u64 > self.len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "超出映像檔"));
        }
        let mut done = 0usize;
        while done < buf.len() {
            let pos = off + done as u64;
            let (idx, within) = (pos / 4096, (pos % 4096) as usize);
            let n = (4096 - within).min(buf.len() - done);
            match self.chunks.get(&idx) {
                Some(c) => buf[done..done + n].copy_from_slice(&c[within..within + n]),
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        Ok(())
    }
}

fn decode_sparse(text: &str) -> SparseDev {
    let mut dev = SparseDev {
        len: 0,
        chunks: HashMap::new(),
    };
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut it = line.splitn(3, ' ');
        match it.next() {
            Some("L") => dev.len = it.next().unwrap().parse().unwrap(),
            Some("C") => {
                let idx: u64 = it.next().unwrap().parse().unwrap();
                let hex = it.next().unwrap().trim();
                assert_eq!(
                    hex.len(),
                    BLOCK * 2,
                    "一個區塊要有 {} 個十六進位字元",
                    BLOCK * 2
                );
                let bytes = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect();
                dev.chunks.insert(idx, bytes);
            }
            other => panic!("不認得的映像檔行 {:?}", other),
        }
    }
    dev
}

pub fn xfs_v5_image() -> SparseDev {
    decode_sparse(include_str!("testdata/xfs-small-v5.txt"))
}
pub const XFS_V5_FIND: &str = include_str!("testdata/xfs-small-v5.find");

pub fn xfs_v4_image() -> SparseDev {
    decode_sparse(include_str!("testdata/xfs-small-v4.txt"))
}
pub const XFS_V4_FIND: &str = include_str!("testdata/xfs-small-v4.find");

pub fn open_xfs_v5() -> Xfs<SparseDev> {
    Xfs::open(xfs_v5_image()).expect("V5 測試映像應該能打開")
}

pub fn open_xfs_v4() -> Xfs<SparseDev> {
    Xfs::open(xfs_v4_image()).expect("V4 測試映像應該能打開")
}
