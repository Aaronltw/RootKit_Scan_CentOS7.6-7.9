use crate::model::{LocalAddr, LocalAddrs};
use std::net::Ipv4Addr;

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn close(fd: i32) -> i32;
}

const AF_INET: i32 = 2;
const SOCK_DGRAM: i32 = 2;
const SIOCGIFCONF: u64 = 0x8912;
const MAX_ENTRIES: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
struct IfReq {
    name: [u8; 16],
    family: u16,
    port: u16,
    addr: [u8; 4],
    rest: [u8; 16],
}

#[repr(C)]
struct IfConf {
    len: i32,
    buf: *mut IfReq,
}

fn blank() -> IfReq {
    IfReq {
        name: [0; 16],
        family: 0,
        port: 0,
        addr: [0; 4],
        rest: [0; 16],
    }
}

pub fn collect_local_addrs() -> LocalAddrs {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        return LocalAddrs::default();
    }
    let mut entries = 32usize;
    let result = loop {
        let mut buf = vec![blank(); entries];
        let mut conf = IfConf {
            len: (entries * std::mem::size_of::<IfReq>()) as i32,
            buf: buf.as_mut_ptr(),
        };
        let rc = unsafe { ioctl(fd, SIOCGIFCONF, &mut conf as *mut IfConf) };
        if rc < 0 {
            break None;
        }
        let used = (conf.len.max(0) as usize) / std::mem::size_of::<IfReq>();
        if used >= entries && entries < MAX_ENTRIES {
            entries *= 2;
            continue;
        }
        buf.truncate(used.min(entries));
        break Some(buf);
    };
    unsafe { close(fd) };
    match result {
        Some(reqs) => LocalAddrs {
            ran: true,
            items: from_requests(&reqs),
        },
        None => LocalAddrs::default(),
    }
}

fn from_requests(reqs: &[IfReq]) -> Vec<LocalAddr> {
    let mut out: Vec<LocalAddr> = Vec::new();
    for r in reqs {
        if r.family != AF_INET as u16 {
            continue;
        }
        let addr = Ipv4Addr::from(r.addr);
        if addr.is_loopback() {
            continue;
        }
        let end = r.name.iter().position(|&b| b == 0).unwrap_or(r.name.len());
        let iface = String::from_utf8_lossy(&r.name[..end]).to_string();
        let item = LocalAddr { iface, addr };
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

pub fn kind_of(addr: Ipv4Addr) -> &'static str {
    let o = addr.octets();
    if addr.is_private() {
        "內網"
    } else if addr.is_link_local() {
        "本機自動配置"
    } else if o[0] == 100 && (64..=127).contains(&o[1]) {
        "營運商共用"
    } else {
        "公開"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(name: &str, family: u16, addr: [u8; 4]) -> IfReq {
        let mut r = blank();
        r.name[..name.len()].copy_from_slice(name.as_bytes());
        r.family = family;
        r.addr = addr;
        r
    }

    #[test]
    fn struct_sizes_match_the_kernel_layout() {
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
        assert_eq!(std::mem::size_of::<IfConf>(), 16);
    }

    #[test]
    fn loopback_other_families_and_duplicates_are_dropped_and_alias_names_kept() {
        let reqs = vec![
            req("lo", 2, [127, 0, 0, 1]),
            req("eth0", 2, [198, 51, 100, 20]),
            req("eth0:1", 2, [192, 168, 250, 20]),
            req("eth0", 2, [198, 51, 100, 20]),
            req("weird0", 10, [1, 2, 3, 4]),
        ];
        let got = from_requests(&reqs);
        assert_eq!(
            got,
            vec![
                LocalAddr {
                    iface: "eth0".into(),
                    addr: Ipv4Addr::new(198, 51, 100, 20)
                },
                LocalAddr {
                    iface: "eth0:1".into(),
                    addr: Ipv4Addr::new(192, 168, 250, 20)
                },
            ]
        );
    }

    #[test]
    fn kinds_follow_the_private_ranges() {
        let k = |a: [u8; 4]| kind_of(Ipv4Addr::from(a));
        assert_eq!(k([10, 1, 2, 3]), "內網");
        assert_eq!(k([172, 16, 0, 1]), "內網");
        assert_eq!(k([172, 31, 255, 254]), "內網");
        assert_eq!(k([192, 168, 0, 5]), "內網");
        assert_eq!(k([198, 51, 100, 20]), "公開");
        assert_eq!(k([172, 32, 0, 1]), "公開");
        assert_eq!(k([169, 254, 3, 4]), "本機自動配置");
        assert_eq!(k([100, 64, 0, 1]), "營運商共用");
        assert_eq!(k([100, 128, 0, 1]), "公開");
        assert_eq!(k([8, 8, 8, 8]), "公開");
    }

    #[test]
    fn asking_the_local_machine_works_and_never_lists_loopback() {
        let got = collect_local_addrs();
        assert!(got.ran, "本機應該問得到網卡清單");
        assert!(got.items.iter().all(|a| !a.addr.is_loopback()));
        assert!(got.items.iter().all(|a| !a.iface.is_empty()));
    }
}
