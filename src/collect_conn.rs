use crate::model::{CapturePair, ConnSample, HeldSocket, PeerQuery, PortKey, Proto};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16,
    addr: u32,
    zero: [u8; 8],
}

#[repr(C)]
struct SockaddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockaddrIn, len: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn sendto(
        fd: i32,
        buf: *const u8,
        len: usize,
        flags: i32,
        addr: *const SockaddrNl,
        alen: u32,
    ) -> isize;
    fn poll(fds: *mut PollFd, n: u64, timeout: i32) -> i32;
    fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn ptrace(request: i32, ...) -> i64;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn __errno_location() -> *mut i32;
    fn fork() -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn _exit(code: i32) -> !;
    fn setpriority(which: i32, who: u32, prio: i32) -> i32;
    fn sched_setscheduler(pid: i32, policy: i32, param: *const i32) -> i32;
}

const AF_INET: i32 = 2;
const AF_PACKET: i32 = 17;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOCK_RAW: i32 = 3;
const ETH_P_ALL_BE: i32 = 0x0003_u16.to_be() as i32;
const EADDRINUSE: i32 = 98;
const POLLIN: i16 = 1;

fn read_text(path: &str) -> String {
    fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn inuse_of(text: &str, prefix: &str) -> i64 {
    sockstat_value(text, prefix, "inuse").max(0)
}

fn sockstat_value(text: &str, prefix: &str, key: &str) -> i64 {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            let t: Vec<&str> = rest.split_whitespace().collect();
            for pair in t.chunks(2) {
                if pair.len() == 2 && pair[0] == key {
                    return pair[1].parse().unwrap_or(-1);
                }
            }
        }
    }
    -1
}

fn table_rows(path: &str) -> (i64, i64, i64) {
    let (mut excl, mut tw, mut syn) = (0, 0, 0);
    for line in read_text(path).lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 3 {
            match f[3] {
                "06" => tw += 1,
                "03" => syn += 1,
                _ => excl += 1,
            }
        }
    }
    (excl, tw, syn)
}

fn plain_rows(path: &str) -> i64 {
    read_text(path)
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .count() as i64
}

pub fn collect_conn_sample(start: Instant) -> ConnSample {
    let t_ms = start.elapsed().as_millis() as u64;
    let s4 = read_text("/proc/net/sockstat");
    let s6 = read_text("/proc/net/sockstat6");
    let (e4, w4, y4) = table_rows("/proc/net/tcp");
    let (e6, w6, y6) = table_rows("/proc/net/tcp6");
    let (ru4, rl4, ru6, rl6) = (
        plain_rows("/proc/net/udp"),
        plain_rows("/proc/net/udplite"),
        plain_rows("/proc/net/udp6"),
        plain_rows("/proc/net/udplite6"),
    );
    let (a4, a6) = (
        read_text("/proc/net/sockstat"),
        read_text("/proc/net/sockstat6"),
    );
    let su_after = inuse_of(&a4, "UDP:")
        + inuse_of(&a4, "UDPLITE:")
        + inuse_of(&a6, "UDP6:")
        + inuse_of(&a6, "UDPLITE6:");
    ConnSample {
        t_ms,
        inuse4: inuse_of(&s4, "TCP:"),
        tw: sockstat_value(&s4, "TCP:", "tw").max(0),
        inuse6: inuse_of(&s6, "TCP6:"),
        e4,
        w4,
        y4,
        e6,
        w6,
        y6,
        su4: inuse_of(&s4, "UDP:"),
        sl4: inuse_of(&s4, "UDPLITE:"),
        su6: inuse_of(&s6, "UDP6:"),
        sl6: inuse_of(&s6, "UDPLITE6:"),
        su_after,
        ru4,
        rl4,
        ru6,
        rl6,
    }
}

fn local_port_of_row(line: &str) -> Option<u16> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let local = f.get(1)?;
    u16::from_str_radix(local.rsplit_once(':')?.1, 16).ok()
}

pub fn listed_ports() -> Vec<PortKey> {
    let mut set = BTreeSet::new();
    for (path, proto) in [
        ("/proc/net/tcp", Proto::Tcp),
        ("/proc/net/tcp6", Proto::Tcp),
        ("/proc/net/udp", Proto::Udp),
        ("/proc/net/udp6", Proto::Udp),
    ] {
        for line in read_text(path).lines().skip(1) {
            if let Some(port) = local_port_of_row(line) {
                set.insert(PortKey { proto, port });
            }
        }
    }
    set.into_iter().collect()
}

fn table_inodes() -> BTreeSet<u64> {
    let mut set = BTreeSet::new();
    let tables: [(&str, usize); 11] = [
        ("/proc/net/tcp", 9),
        ("/proc/net/tcp6", 9),
        ("/proc/net/udp", 9),
        ("/proc/net/udp6", 9),
        ("/proc/net/udplite", 9),
        ("/proc/net/udplite6", 9),
        ("/proc/net/raw", 9),
        ("/proc/net/raw6", 9),
        ("/proc/net/unix", 6),
        ("/proc/net/netlink", 9),
        ("/proc/net/packet", 8),
    ];
    for (path, idx) in tables {
        for line in read_text(path).lines().skip(1) {
            if let Some(v) = line
                .split_whitespace()
                .nth(idx)
                .and_then(|v| v.parse::<u64>().ok())
            {
                set.insert(v);
            }
        }
    }
    set
}

fn try_bind(proto: Proto, addr: u32, port: u16) -> Option<i32> {
    let ty = match proto {
        Proto::Tcp => SOCK_STREAM,
        Proto::Udp => SOCK_DGRAM,
    };
    let fd = unsafe { socket(AF_INET, ty, 0) };
    if fd < 0 {
        return None;
    }
    let sa = SockaddrIn {
        family: AF_INET as u16,
        port: port.to_be(),
        addr,
        zero: [0; 8],
    };
    let r = unsafe { bind(fd, &sa, std::mem::size_of::<SockaddrIn>() as u32) };
    let err = if r == 0 {
        0
    } else {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    };
    unsafe { close(fd) };
    Some(err)
}

pub fn probe_ports() -> Vec<PortKey> {
    let mut out = Vec::new();
    for proto in [Proto::Tcp, Proto::Udp] {
        out.extend(
            (1..=65535u16)
                .filter(|p| try_bind(proto, 0, *p) == Some(EADDRINUSE))
                .map(|port| PortKey { proto, port }),
        );
    }
    out
}

pub fn recheck_ports(candidates: &[PortKey], rounds: u32, gap_ms: u64) -> Vec<PortKey> {
    let mut vanished: BTreeSet<PortKey> = BTreeSet::new();
    for _ in 0..rounds {
        std::thread::sleep(Duration::from_millis(gap_ms));
        for k in candidates {
            if !vanished.contains(k) && try_bind(k.proto, 0, k.port) != Some(EADDRINUSE) {
                vanished.insert(*k);
            }
        }
    }
    vanished.into_iter().collect()
}

pub fn local_ipv4_addrs() -> Vec<Ipv4Addr> {
    let text = read_text("/proc/net/fib_trie");
    let mut out = BTreeSet::new();
    let mut last: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("|--") {
            last = rest.trim().parse().ok();
        } else if t.contains("/32 host LOCAL") {
            if let Some(a) = last {
                out.insert(a);
            }
        }
    }
    out.into_iter().collect()
}

pub fn port_local_addrs(key: PortKey, addrs: &[Ipv4Addr]) -> Vec<String> {
    addrs
        .iter()
        .filter(|a| {
            try_bind(key.proto, u32::from_ne_bytes(a.octets()), key.port) == Some(EADDRINUSE)
        })
        .map(|a| a.to_string())
        .collect()
}

fn socket_inode_of_link(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn comm_of(pid: u32) -> String {
    let stat = read_text(&format!("/proc/{}/stat", pid));
    match (stat.find('('), stat.rfind(')')) {
        (Some(a), Some(b)) if b > a => stat[a + 1..b].to_string(),
        _ => String::new(),
    }
}

pub fn held_sockets(pids: &[u32]) -> Vec<HeldSocket> {
    let before = table_inodes();
    let pids: BTreeSet<u32> = pids.iter().copied().collect();
    let mut found = Vec::new();
    for pid in pids {
        let Ok(rd) = fs::read_dir(format!("/proc/{}/fd", pid)) else {
            continue;
        };
        for e in rd.flatten() {
            let Some(fd) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            let Ok(link) = fs::read_link(e.path()) else {
                continue;
            };
            let Some(inode) = link.to_str().and_then(socket_inode_of_link) else {
                continue;
            };
            if !before.contains(&inode) {
                found.push((pid, fd, inode));
            }
        }
    }
    let after = table_inodes();
    found
        .into_iter()
        .filter(|(_, _, inode)| !after.contains(inode))
        .map(|(pid, fd, inode)| HeldSocket {
            pid,
            comm: comm_of(pid),
            exe: fs::read_link(format!("/proc/{}/exe", pid))
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
            fd,
            inode,
        })
        .collect()
}

pub fn visible_user_pids(exclude: &[u32]) -> Vec<u32> {
    let me = std::process::id();
    let mut v: Vec<u32> = fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|p| *p != 1 && *p != me && !exclude.contains(p))
        .collect();
    v.sort_unstable();
    v
}

pub fn conntrack_present() -> bool {
    fs::metadata("/proc/net/nf_conntrack").is_ok()
}

pub fn conntrack_proto(line: &str) -> Option<Proto> {
    if line.contains(" tcp ") {
        Some(Proto::Tcp)
    } else if line.contains(" udp ") {
        Some(Proto::Udp)
    } else {
        None
    }
}

pub fn conntrack_lines(ports: &[PortKey]) -> Vec<String> {
    read_text("/proc/net/nf_conntrack")
        .lines()
        .filter(|l| {
            let Some(proto) = conntrack_proto(l) else {
                return false;
            };
            let has = |k: &str| {
                key_value(l, k)
                    .and_then(|v| v.parse::<u16>().ok())
                    .is_some_and(|port| ports.contains(&PortKey { proto, port }))
            };
            has("sport=") || has("dport=")
        })
        .map(|l| l.chars().take(300).collect())
        .collect()
}

pub fn key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pos = line.find(key)?;
    let rest = &line[pos + key.len()..];
    Some(rest.split_whitespace().next().unwrap_or(""))
}

fn ip_text(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            format!("[{}]", Ipv6Addr::from(a))
        }
        _ => String::new(),
    }
}

fn proto_of_number(n: u8) -> Option<Proto> {
    match n {
        6 => Some(Proto::Tcp),
        17 => Some(Proto::Udp),
        _ => None,
    }
}

pub fn parse_frame(buf: &[u8]) -> Option<(Proto, String, String)> {
    if buf.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
    let (proto, src, dst, l4) = match ethertype {
        0x0800 => {
            if buf.len() < 34 {
                return None;
            }
            let proto = proto_of_number(buf[23])?;
            let ihl = (buf[14] & 0x0F) as usize * 4;
            (proto, &buf[26..30], &buf[30..34], 14 + ihl)
        }
        0x86DD => {
            if buf.len() < 54 {
                return None;
            }
            let proto = proto_of_number(buf[20])?;
            (proto, &buf[22..38], &buf[38..54], 54)
        }
        _ => return None,
    };
    if buf.len() < l4 + 4 {
        return None;
    }
    let sp = u16::from_be_bytes([buf[l4], buf[l4 + 1]]);
    let dp = u16::from_be_bytes([buf[l4 + 2], buf[l4 + 3]]);
    Some((
        proto,
        format!("{}:{}", ip_text(src), sp),
        format!("{}:{}", ip_text(dst), dp),
    ))
}

fn port_of(endpoint: &str) -> Option<u16> {
    endpoint.rsplit_once(':')?.1.parse().ok()
}

pub fn capture_pairs(secs: u32, ports: &[PortKey]) -> Vec<CapturePair> {
    let fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_ALL_BE) };
    if fd < 0 {
        return Vec::new();
    }
    let mut counts: BTreeMap<(Proto, String, String), u32> = BTreeMap::new();
    let end = Instant::now() + Duration::from_secs(secs as u64);
    let mut buf = vec![0u8; 65536];
    while Instant::now() < end {
        let mut pfd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        let left = end
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(500) as i32;
        if unsafe { poll(&mut pfd, 1, left) } <= 0 {
            continue;
        }
        let n = unsafe { recv(fd, buf.as_mut_ptr(), buf.len(), 0) };
        if n <= 0 {
            continue;
        }
        if let Some((proto, a, b)) = parse_frame(&buf[..n as usize]) {
            let wanted = [&a, &b]
                .iter()
                .any(|e| port_of(e).is_some_and(|port| ports.contains(&PortKey { proto, port })));
            if wanted {
                let (a, b) = if a <= b { (a, b) } else { (b, a) };
                *counts.entry((proto, a, b)).or_insert(0) += 1;
            }
        }
    }
    unsafe { close(fd) };
    counts
        .into_iter()
        .map(|((proto, a, b), count)| CapturePair { proto, a, b, count })
        .collect()
}

const AF_NETLINK: i32 = 16;
const NETLINK_GENERIC: i32 = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const TCP_METRICS_CMD_GET: u8 = 1;
const TCP_METRICS_ATTR_ADDR_IPV4: u16 = 1;
const TCP_METRICS_ATTR_ADDR_IPV6: u16 = 2;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

pub fn nla(typ: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    v.extend_from_slice(&typ.to_ne_bytes());
    v.extend_from_slice(payload);
    v.resize(align4(v.len()), 0);
    v
}

pub fn genl_msg(typ: u16, flags: u16, seq: u32, cmd: u8, attrs: &[u8]) -> Vec<u8> {
    let len = 16 + 4 + attrs.len();
    let mut v = Vec::new();
    v.extend_from_slice(&(len as u32).to_ne_bytes());
    v.extend_from_slice(&typ.to_ne_bytes());
    v.extend_from_slice(&flags.to_ne_bytes());
    v.extend_from_slice(&seq.to_ne_bytes());
    v.extend_from_slice(&0u32.to_ne_bytes());
    v.push(cmd);
    v.push(1);
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(attrs);
    v
}

fn nl_messages(resp: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= resp.len() {
        let len =
            u32::from_ne_bytes([resp[off], resp[off + 1], resp[off + 2], resp[off + 3]]) as usize;
        let typ = u16::from_ne_bytes([resp[off + 4], resp[off + 5]]);
        if len < 16 || off + len > resp.len() {
            break;
        }
        out.push((typ, &resp[off + 16..off + len]));
        off += align4(len);
    }
    out
}

fn nl_attrs(body: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 4.min(body.len());
    while off + 4 <= body.len() {
        let len = u16::from_ne_bytes([body[off], body[off + 1]]) as usize;
        let typ = u16::from_ne_bytes([body[off + 2], body[off + 3]]) & 0x3fff;
        if len < 4 || off + len > body.len() {
            break;
        }
        out.push((typ, &body[off + 4..off + len]));
        off += align4(len);
    }
    out
}

pub fn parse_family_id(resp: &[u8]) -> Option<u16> {
    for (typ, body) in nl_messages(resp) {
        if typ == NLMSG_ERROR {
            return None;
        }
        for (t, v) in nl_attrs(body) {
            if t == CTRL_ATTR_FAMILY_ID && v.len() >= 2 {
                return Some(u16::from_ne_bytes([v[0], v[1]]));
            }
        }
    }
    None
}

pub fn parse_metrics(resp: &[u8], family: u16) -> (Vec<String>, bool) {
    let mut addrs = Vec::new();
    let mut done = false;
    for (typ, body) in nl_messages(resp) {
        if typ == NLMSG_DONE || typ == NLMSG_ERROR {
            done = true;
        } else if typ == family {
            for (t, v) in nl_attrs(body) {
                let ok = (t == TCP_METRICS_ATTR_ADDR_IPV4 && v.len() == 4)
                    || (t == TCP_METRICS_ATTR_ADDR_IPV6 && v.len() == 16);
                if ok {
                    addrs.push(ip_text(v));
                }
            }
        }
    }
    (addrs, done)
}

fn nl_recv(fd: i32, buf: &mut [u8]) -> Option<usize> {
    let mut pfd = PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    };
    if unsafe { poll(&mut pfd, 1, 1000) } <= 0 {
        return None;
    }
    let n = unsafe { recv(fd, buf.as_mut_ptr(), buf.len(), 0) };
    if n <= 0 {
        None
    } else {
        Some(n as usize)
    }
}

pub fn tcp_metrics_addrs() -> Option<Vec<String>> {
    let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) };
    if fd < 0 {
        return None;
    }
    let kernel = SockaddrNl {
        family: AF_NETLINK as u16,
        pad: 0,
        pid: 0,
        groups: 0,
    };
    let send = |msg: &[u8]| unsafe {
        sendto(
            fd,
            msg.as_ptr(),
            msg.len(),
            0,
            &kernel,
            std::mem::size_of::<SockaddrNl>() as u32,
        )
    };
    let result = (|| {
        let name = nla(CTRL_ATTR_FAMILY_NAME, b"tcp_metrics\0");
        let q = genl_msg(GENL_ID_CTRL, NLM_F_REQUEST, 1, CTRL_CMD_GETFAMILY, &name);
        if send(&q) < 0 {
            return None;
        }
        let mut buf = vec![0u8; 32 * 1024];
        let n = nl_recv(fd, &mut buf)?;
        let family = parse_family_id(&buf[..n])?;
        let dump = genl_msg(
            family,
            NLM_F_REQUEST | NLM_F_DUMP,
            2,
            TCP_METRICS_CMD_GET,
            &[],
        );
        if send(&dump) < 0 {
            return None;
        }
        let mut all = Vec::new();
        for _ in 0..200 {
            let Some(n) = nl_recv(fd, &mut buf) else {
                break;
            };
            let (a, done) = parse_metrics(&buf[..n], family);
            all.extend(a);
            if done {
                break;
            }
        }
        all.sort();
        all.dedup();
        Some(all)
    })();
    unsafe { close(fd) };
    result
}

pub fn visible_remote_addrs() -> Vec<String> {
    let mut set = BTreeSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for line in read_text(path).lines().skip(1) {
            if let Some(remote) = line.split_whitespace().nth(2) {
                if let Some(a) = proc_addr_text(remote) {
                    set.insert(a);
                }
            }
        }
    }
    set.into_iter().collect()
}

pub fn proc_addr_text(field: &str) -> Option<String> {
    let hex = field.rsplit_once(':')?.0;
    if hex.len() != 8 && hex.len() != 32 {
        return None;
    }
    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(8) {
        let w = u32::from_str_radix(&hex[i..i + 8], 16).ok()?;
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    if bytes.iter().all(|b| *b == 0) {
        return None;
    }
    Some(ip_text(&bytes))
}

const PTRACE_PEEKDATA: i32 = 2;
const PTRACE_POKEDATA: i32 = 5;
const PTRACE_SINGLESTEP: i32 = 9;
const PTRACE_GETREGS: i32 = 12;
const PTRACE_SETREGS: i32 = 13;
const PTRACE_DETACH: i32 = 17;
const PTRACE_SEIZE: i32 = 0x4206;
const PTRACE_INTERRUPT: i32 = 0x4207;
const WALL: i32 = 0x4000_0000;
const WNOHANG: i32 = 1;
const R_R10: usize = 7;
const R_R8: usize = 9;
const R_RAX: usize = 10;
const R_RDX: usize = 12;
const R_RSI: usize = 13;
const R_RDI: usize = 14;
const R_ORIG_RAX: usize = 15;
const R_RIP: usize = 16;
const R_RSP: usize = 19;
const SYS_GETSOCKNAME: u64 = 51;
const SYS_GETPEERNAME: u64 = 52;
const SYS_GETSOCKOPT: u64 = 55;
const SOL_SOCKET: u64 = 1;
const SO_PEERNAME: u64 = 28;
const SOL_TCP: u64 = 6;
const TCP_INFO: u64 = 11;

fn clear_errno() {
    unsafe { *__errno_location() = 0 };
}

fn errno() -> i32 {
    unsafe { *__errno_location() }
}

fn pt(req: i32, pid: i32, addr: usize, data: usize) -> Result<i64, String> {
    clear_errno();
    let r = unsafe { ptrace(req, pid, addr, data) };
    let e = errno();
    if r == -1 && e != 0 {
        Err(format!("ptrace({}) 失敗，errno {}", req, e))
    } else {
        Ok(r)
    }
}

fn getregs(pid: i32) -> Result<[u64; 27], String> {
    let mut regs = [0u64; 27];
    pt(PTRACE_GETREGS, pid, 0, regs.as_mut_ptr() as usize)?;
    Ok(regs)
}

fn setregs(pid: i32, regs: &[u64; 27]) -> Result<(), String> {
    pt(PTRACE_SETREGS, pid, 0, regs.as_ptr() as usize).map(|_| ())
}

fn wait_stop(pid: i32, ms: u64) -> Result<(), String> {
    let end = Instant::now() + Duration::from_millis(ms);
    loop {
        let mut st = 0i32;
        let r = unsafe { waitpid(pid, &mut st, WALL | WNOHANG) };
        if r == pid {
            return Ok(());
        }
        if r < 0 {
            return Err("waitpid 失敗".into());
        }
        if Instant::now() >= end {
            return Err("等不到行程停下來".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub fn parse_sockaddr(b: &[u8]) -> String {
    if b.len() < 8 {
        return "-".into();
    }
    match u16::from_ne_bytes([b[0], b[1]]) {
        2 => format!("{}:{}", ip_text(&b[4..8]), u16::from_be_bytes([b[2], b[3]])),
        10 if b.len() >= 24 => format!(
            "{}:{}",
            ip_text(&b[8..24]),
            u16::from_be_bytes([b[2], b[3]])
        ),
        f => format!("family={}", f),
    }
}

pub fn tgid_of(pid: u32) -> Option<u32> {
    read_text(&format!("/proc/{}/status", pid))
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
}

fn tracer_pid(pid: u32) -> Option<u32> {
    read_text(&format!("/proc/{}/status", pid))
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|v| v.trim().parse().ok())
}

fn vma_perms_at(maps: &str, addr: usize) -> Option<String> {
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let (Some(range), Some(perms)) = (it.next(), it.next()) else {
            continue;
        };
        let Some((lo, hi)) = range.split_once('-') else {
            continue;
        };
        let (Ok(lo), Ok(hi)) = (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
        else {
            continue;
        };
        if addr >= lo && addr < hi {
            return Some(perms.to_string());
        }
    }
    None
}

fn perm_is(maps: &str, addr: usize, idx: usize, ch: u8) -> bool {
    vma_perms_at(maps, addr)
        .map(|p| p.as_bytes().get(idx) == Some(&ch))
        .unwrap_or(false)
}

fn find_syscall_bytes(
    bytes: &[u8],
    start: usize,
    prefer: usize,
    ok: &dyn Fn(usize) -> bool,
) -> Option<usize> {
    let mut best: Option<usize> = None;
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] != 0x0F || bytes[i + 1] != 0x05 {
            continue;
        }
        let a = start + i;
        if !ok(a) || !ok(a + 1) {
            continue;
        }
        if best.is_none_or(|b| a.abs_diff(prefer) < b.abs_diff(prefer)) {
            best = Some(a);
        }
    }
    best
}

fn parse_vma_header(line: &str) -> Option<(usize, usize)> {
    let first = line.split_whitespace().next()?;
    if first.ends_with(':') {
        return None;
    }
    let (lo, hi) = first.split_once('-')?;
    Some((
        usize::from_str_radix(lo, 16).ok()?,
        usize::from_str_radix(hi, 16).ok()?,
    ))
}

fn first_number(v: &str) -> u64 {
    v.split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn vdso_range(maps: &str) -> Option<(usize, usize)> {
    let line = maps.lines().find(|l| l.trim_end().ends_with("[vdso]"))?;
    let (lo, hi) = line.split_whitespace().next()?.split_once('-')?;
    Some((
        usize::from_str_radix(lo, 16).ok()?,
        usize::from_str_radix(hi, 16).ok()?,
    ))
}

fn plain_small_pages<I: Iterator<Item = String>>(lines: I, addr: usize) -> bool {
    let (mut inside, mut seen) = (false, false);
    let (mut huge_kb, mut page_kb, mut hugetlb) = (0u64, 4u64, false);
    for line in lines {
        if let Some((lo, hi)) = parse_vma_header(&line) {
            if inside {
                break;
            }
            inside = addr >= lo && addr < hi;
            continue;
        }
        if !inside {
            continue;
        }
        seen = true;
        if let Some(v) = line.strip_prefix("AnonHugePages:") {
            huge_kb = first_number(v);
        } else if let Some(v) = line.strip_prefix("KernelPageSize:") {
            page_kb = first_number(v);
        } else if let Some(v) = line.strip_prefix("VmFlags:") {
            hugetlb = v.split_whitespace().any(|f| f == "ht");
        }
    }
    seen && huge_kb == 0 && page_kb == 4 && !hugetlb
}

fn smaps_plain_small_pages(pid: u32, addr: usize) -> bool {
    use std::io::{BufRead, BufReader};
    match fs::File::open(format!("/proc/{}/smaps", pid)) {
        Ok(f) => plain_small_pages(BufReader::new(f).lines().map_while(Result::ok), addr),
        Err(_) => false,
    }
}

fn fail_all(pid: u32, fds: &[u32], msg: &str) -> Vec<PeerQuery> {
    fds.iter()
        .map(|fd| PeerQuery {
            pid,
            fd: *fd,
            local: "-".into(),
            peer: "-".into(),
            error: Some(msg.to_string()),
            state: None,
        })
        .collect()
}

fn clean_field(s: &str) -> String {
    s.replace(['\t', '\n'], " ")
}

fn encode_queries(qs: &[PeerQuery]) -> Vec<u8> {
    let mut s = String::new();
    for q in qs {
        s.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            q.fd,
            clean_field(&q.local),
            clean_field(&q.peer),
            clean_field(q.error.as_deref().unwrap_or("")),
            q.state.map(|v| v.to_string()).unwrap_or_default()
        ));
    }
    s.into_bytes()
}

fn decode_queries(pid: u32, bytes: &[u8]) -> Vec<PeerQuery> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|l| {
            let mut it = l.split('\t');
            let fd = it.next()?.parse().ok()?;
            let local = it.next()?.to_string();
            let peer = it.next()?.to_string();
            let err = it.next()?;
            let state = it.next().and_then(|v| v.parse().ok());
            Some(PeerQuery {
                pid,
                fd,
                local,
                peer,
                error: if err.is_empty() {
                    None
                } else {
                    Some(err.to_string())
                },
                state,
            })
        })
        .collect()
}

fn run_in_child<F: FnOnce() -> Vec<u8>>(f: F, timeout_ms: u64) -> Result<Vec<u8>, String> {
    let mut p = [0i32; 2];
    if unsafe { pipe(p.as_mut_ptr()) } != 0 {
        return Err("建不起管線，無法在子行程查詢".into());
    }
    let child = unsafe { fork() };
    if child < 0 {
        unsafe {
            close(p[0]);
            close(p[1]);
        }
        return Err("fork 失敗，無法在子行程查詢".into());
    }
    if child == 0 {
        unsafe {
            close(p[0]);
            for fd in 0..=2 {
                if fd != p[1] {
                    close(fd);
                }
            }
            setpriority(0, 0, 19);
            let param = 0i32;
            sched_setscheduler(0, 5, &param);
        }
        let data = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_default();
        let mut off = 0;
        while off < data.len() {
            let n = unsafe { write(p[1], data[off..].as_ptr(), data.len() - off) };
            if n <= 0 {
                break;
            }
            off += n as usize;
        }
        unsafe { _exit(0) }
    }
    unsafe { close(p[1]) };
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = Vec::new();
    let result = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break Err(format!(
                "逾時（{} 毫秒）核心沒有回應，可能卡在核心裡；已放棄這一步，掃描照常繼續",
                timeout_ms
            ));
        }
        let mut pfd = PollFd {
            fd: p[0],
            events: POLLIN,
            revents: 0,
        };
        let r = unsafe { poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
        if r < 0 {
            if errno() == 4 {
                continue;
            }
            break Err("等待子行程時出錯".into());
        }
        if r == 0 {
            continue;
        }
        let mut chunk = [0u8; 4096];
        let n = unsafe { read(p[0], chunk.as_mut_ptr(), chunk.len()) };
        if n < 0 {
            if errno() == 4 {
                continue;
            }
            break Err("讀子行程結果時出錯".into());
        }
        if n == 0 {
            break Ok(std::mem::take(&mut buf));
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    };
    unsafe { close(p[0]) };
    if result.is_ok() {
        let end = Instant::now() + Duration::from_millis(200);
        loop {
            let mut st = 0i32;
            let r = unsafe { waitpid(child, &mut st, WNOHANG) };
            if r != 0 || Instant::now() >= end {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    result
}

static PEER_QUERY_TIMED_OUT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn query_peers(pid: u32, fds: &[u32]) -> Vec<PeerQuery> {
    use std::sync::atomic::Ordering;
    if PEER_QUERY_TIMED_OUT.load(Ordering::Relaxed) {
        return fail_all(pid, fds, "前一次暫時查詢逾時，為安全略過");
    }
    let budget = (1500 + 100 * fds.len() as u64).min(8000);
    let fds_owned = fds.to_vec();
    match run_in_child(
        move || encode_queries(&query_peers_direct(pid, &fds_owned)),
        budget,
    ) {
        Ok(bytes) => {
            let got = decode_queries(pid, &bytes);
            if got.is_empty() && !fds.is_empty() {
                fail_all(pid, fds, "子行程沒有回報結果")
            } else {
                got
            }
        }
        Err(e) => {
            if e.starts_with("逾時") {
                PEER_QUERY_TIMED_OUT.store(true, Ordering::Relaxed);
            }
            fail_all(pid, fds, &e)
        }
    }
}

fn inject_getsockopt(
    ipid: i32,
    orig: &[u64; 27],
    tramp: usize,
    scratch: usize,
    lenaddr: usize,
    fd: u32,
    (level, opt, len): (u64, u64, u64),
) -> Result<i64, String> {
    for i in 0..16 {
        pt(PTRACE_POKEDATA, ipid, scratch + 8 * i, 0)?;
    }
    pt(PTRACE_POKEDATA, ipid, lenaddr, len as usize)?;
    let mut r = *orig;
    r[R_RAX] = SYS_GETSOCKOPT;
    r[R_RDI] = fd as u64;
    r[R_RSI] = level;
    r[R_RDX] = opt;
    r[R_R10] = scratch as u64;
    r[R_R8] = lenaddr as u64;
    r[R_ORIG_RAX] = u64::MAX;
    r[R_RIP] = tramp as u64;
    setregs(ipid, &r)?;
    pt(PTRACE_SINGLESTEP, ipid, 0, 0)?;
    wait_stop(ipid, 500)?;
    Ok(getregs(ipid)?[R_RAX] as i64)
}

fn sockaddr_is_ipv6(raw: &[u8]) -> bool {
    raw.len() >= 2 && u16::from_ne_bytes([raw[0], raw[1]]) == 10
}

fn query_peers_direct(pid: u32, fds: &[u32]) -> Vec<PeerQuery> {
    let fail = |msg: &str| {
        fds.iter()
            .map(|fd| PeerQuery {
                pid,
                fd: *fd,
                local: "-".into(),
                peer: "-".into(),
                error: Some(msg.to_string()),
                state: None,
            })
            .collect::<Vec<_>>()
    };
    match tracer_pid(pid) {
        Some(0) => {}
        Some(t) => return fail(&format!("已被行程 {} 追蹤，不查詢", t)),
        None => return fail("讀不到行程狀態"),
    }
    let ipid = pid as i32;
    if let Err(e) = pt(PTRACE_SEIZE, ipid, 0, 0) {
        return fail(&e);
    }
    let mut out = Vec::new();
    let attach = (|| -> Result<(), String> {
        pt(PTRACE_INTERRUPT, ipid, 0, 0)?;
        wait_stop(ipid, 500)
    })();
    if let Err(e) = attach {
        let _ = pt(PTRACE_DETACH, ipid, 0, 0);
        return fail(&e);
    }
    let inner = (|| -> Result<(), String> {
        let orig = getregs(ipid)?;
        let scratch = ((orig[R_RSP].wrapping_sub(2048)) & !0xF) as usize;
        let lenaddr = scratch + 512;
        let rip = orig[R_RIP] as usize;
        let maps = read_text(&format!("/proc/{}/maps", pid));
        if maps.is_empty() {
            return Err("讀不到目標的記憶體配置，為安全略過".into());
        }
        let scratch_ok = |a: usize| perm_is(&maps, a, 0, b'r') && perm_is(&maps, a, 1, b'w');
        if !scratch_ok(scratch) || !scratch_ok(lenaddr + 7) {
            return Err("目標堆疊下方的暫存區不可寫，為安全略過".into());
        }
        let exec_ok = |a: usize| perm_is(&maps, a, 0, b'r') && perm_is(&maps, a, 2, b'x');
        let win_start = rip.saturating_sub(64);
        let mut win = Vec::with_capacity(17 * 8);
        for i in 0..17 {
            match pt(PTRACE_PEEKDATA, ipid, win_start + 8 * i, 0) {
                Ok(w) => win.extend_from_slice(&(w as u64).to_le_bytes()),
                Err(_) => win.extend_from_slice(&[0u8; 8]),
            }
        }
        let mut existing = find_syscall_bytes(&win, win_start, rip.wrapping_sub(2), &exec_ok);
        if existing.is_none() {
            if let Some((lo, hi)) = vdso_range(&maps) {
                let len = (hi - lo).min(16 * 1024);
                let mut vb = Vec::with_capacity(len);
                for i in 0..len.div_ceil(8) {
                    match pt(PTRACE_PEEKDATA, ipid, lo + 8 * i, 0) {
                        Ok(w) => vb.extend_from_slice(&(w as u64).to_le_bytes()),
                        Err(_) => vb.extend_from_slice(&[0u8; 8]),
                    }
                }
                existing = find_syscall_bytes(&vb, lo, lo, &exec_ok);
            }
        }
        let (tramp, patch) = match existing {
            Some(a) => (a, false),
            None => {
                if exec_ok(rip)
                    && (perm_is(&maps, rip, 1, b'w') || smaps_plain_small_pages(pid, rip))
                {
                    (rip, true)
                } else {
                    return Err(
                        "找不到可借用的系統呼叫指令，目標程式碼又可能是不可寫的大頁，為安全略過"
                            .into(),
                    );
                }
            }
        };
        let mut words: Vec<usize> = (0..16).map(|i| scratch + 8 * i).collect();
        words.push(lenaddr);
        if patch {
            words.push(rip);
        }
        let mut saved = Vec::new();
        for a in &words {
            saved.push((*a, pt(PTRACE_PEEKDATA, ipid, *a, 0)? as u64));
        }
        if patch {
            let rip_word = saved.last().map(|s| s.1).unwrap_or(0);
            pt(
                PTRACE_POKEDATA,
                ipid,
                rip,
                ((rip_word & !0xFFFF) | 0x050F) as usize,
            )?;
        }
        let run = (|| -> Result<(), String> {
            for fd in fds {
                let mut local = String::from("-");
                let mut peer = String::from("-");
                let mut error = None;
                for (label, nr) in [(0, SYS_GETSOCKNAME), (1, SYS_GETPEERNAME)] {
                    for i in 0..16 {
                        pt(PTRACE_POKEDATA, ipid, scratch + 8 * i, 0)?;
                    }
                    pt(PTRACE_POKEDATA, ipid, lenaddr, 128)?;
                    let mut r = orig;
                    r[R_RAX] = nr;
                    r[R_RDI] = *fd as u64;
                    r[R_RSI] = scratch as u64;
                    r[R_RDX] = lenaddr as u64;
                    r[R_ORIG_RAX] = u64::MAX;
                    r[R_RIP] = tramp as u64;
                    setregs(ipid, &r)?;
                    pt(PTRACE_SINGLESTEP, ipid, 0, 0)?;
                    wait_stop(ipid, 500)?;
                    let after = getregs(ipid)?;
                    let ret = after[R_RAX] as i64;
                    if ret == 0 {
                        let mut raw = Vec::new();
                        for i in 0..4 {
                            let w = pt(PTRACE_PEEKDATA, ipid, scratch + 8 * i, 0)? as u64;
                            raw.extend_from_slice(&w.to_ne_bytes());
                        }
                        let text = parse_sockaddr(&raw);
                        if label == 0 {
                            local = text;
                        } else {
                            peer = text;
                        }
                    } else if label == 1 {
                        error = Some(format!("errno {}", -ret));
                    }
                }
                let mut state = None;
                if local != "-" && error.as_deref() == Some("errno 107") {
                    let tcp_info = (SOL_TCP, TCP_INFO, 16);
                    let ret =
                        inject_getsockopt(ipid, &orig, tramp, scratch, lenaddr, *fd, tcp_info)?;
                    if ret == 0 {
                        let w = pt(PTRACE_PEEKDATA, ipid, scratch, 0)? as u64;
                        state = Some((w & 0xFF) as u8);
                    }
                }
                if state == Some(2) {
                    let mut len = 16;
                    for _ in 0..2 {
                        let ret = inject_getsockopt(
                            ipid,
                            &orig,
                            tramp,
                            scratch,
                            lenaddr,
                            *fd,
                            (SOL_SOCKET, SO_PEERNAME, len),
                        )?;
                        if ret != 0 {
                            break;
                        }
                        let mut raw = Vec::new();
                        for i in 0..4 {
                            let w = pt(PTRACE_PEEKDATA, ipid, scratch + 8 * i, 0)? as u64;
                            raw.extend_from_slice(&w.to_ne_bytes());
                        }
                        if sockaddr_is_ipv6(&raw) && len < 28 {
                            len = 28;
                            continue;
                        }
                        peer = parse_sockaddr(&raw);
                        error = None;
                        break;
                    }
                }
                out.push(PeerQuery {
                    pid,
                    fd: *fd,
                    local,
                    peer,
                    error,
                    state,
                });
            }
            Ok(())
        })();
        for (a, v) in &saved {
            let _ = pt(PTRACE_POKEDATA, ipid, *a, *v as usize);
        }
        let restored = setregs(ipid, &orig);
        run.and(restored)
    })();
    let detach = pt(PTRACE_DETACH, ipid, 0, 0);
    match (inner, detach) {
        (Ok(()), Ok(_)) => out,
        (Err(e), _) | (_, Err(e)) => {
            if out.is_empty() {
                fail(&e)
            } else {
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS_EXCERPT: &str = "\
00400000-0074d000 r-xp 00000000 00:00 0 \n\
0074d000-00ab8000 r--p 00000000 00:00 0 \n\
00ab8000-00d78000 rw-p 00000000 00:00 0 \n\
0e000000-0e400000 rw-p 00000000 00:00 0 \n\
7f1f1bf0d000-7f1f1bf0e000 r--p 00000000 08:00 48613                      /usr/bin/exampled-svc\n\
7fff70a3e000-7fff70a5f000 rw-p 00000000 00:00 0                          [stack]\n\
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]\n";

    #[test]
    fn an_ipv6_socket_address_needs_the_longer_so_peername_length() {
        let mut v4 = vec![0u8; 32];
        v4[0] = 2;
        v4[2] = 0x48;
        v4[3] = 0x0B;
        v4[4..8].copy_from_slice(&[198, 51, 100, 200]);
        assert!(!sockaddr_is_ipv6(&v4));
        assert_eq!(parse_sockaddr(&v4), "198.51.100.200:18443");
        let mut v6 = vec![0u8; 32];
        v6[0] = 10;
        assert!(sockaddr_is_ipv6(&v6));
        assert!(!sockaddr_is_ipv6(&[10]));
    }

    #[test]
    fn memory_area_permissions_are_read_from_maps() {
        let p = vma_perms_at(MAPS_EXCERPT, 0x409cce).unwrap();
        assert_eq!(p, "r-xp");
        assert!(perm_is(MAPS_EXCERPT, 0x409cce, 2, b'x'));
        assert!(!perm_is(MAPS_EXCERPT, 0x409cce, 1, b'w'));
        assert!(perm_is(MAPS_EXCERPT, 0x7fff70a5c6d0, 1, b'w'));
        assert_eq!(vma_perms_at(MAPS_EXCERPT, 0x1234), None);
        assert!(!perm_is(MAPS_EXCERPT, 0x1234, 1, b'w'));
        assert!(perm_is(MAPS_EXCERPT, 0x74cfff, 2, b'x'));
        assert!(!perm_is(MAPS_EXCERPT, 0x74d000, 2, b'x'));
        assert_eq!(vma_perms_at("garbage\n\nzz-zz r-xp\n", 0x10), None);
    }

    #[test]
    fn existing_syscall_instruction_is_borrowed_instead_of_writing() {
        let rip = 0x409cce;
        let start = rip - 64;
        let mut win = vec![0x90u8; 17 * 8];
        win[62] = 0x0F;
        win[63] = 0x05;
        let ok = |a: usize| perm_is(MAPS_EXCERPT, a, 2, b'x');
        assert_eq!(find_syscall_bytes(&win, start, rip - 2, &ok), Some(rip - 2));
        win[10] = 0x0F;
        win[11] = 0x05;
        assert_eq!(find_syscall_bytes(&win, start, rip - 2, &ok), Some(rip - 2));
        win[62] = 0x90;
        win[63] = 0x90;
        assert_eq!(
            find_syscall_bytes(&win, start, rip - 2, &ok),
            Some(start + 10)
        );
        win[10] = 0x90;
        win[11] = 0x90;
        assert_eq!(find_syscall_bytes(&win, start, rip - 2, &ok), None);
    }

    #[test]
    fn a_syscall_pattern_outside_executable_memory_is_not_borrowed() {
        let start = 0xab8000 + 0x100;
        let mut win = vec![0u8; 32];
        win[4] = 0x0F;
        win[5] = 0x05;
        let ok = |a: usize| perm_is(MAPS_EXCERPT, a, 2, b'x');
        assert_eq!(find_syscall_bytes(&win, start, start, &ok), None);
        let start = 0x74d000 - 1;
        let mut win = vec![0u8; 8];
        win[0] = 0x0F;
        win[1] = 0x05;
        assert_eq!(find_syscall_bytes(&win, start, start, &ok), None);
    }

    #[test]
    fn huge_page_code_is_never_treated_as_safe_to_write() {
        let huge = "\
00400000-0074d000 r-xp 00000000 00:00 0 \n\
Size:               3380 kB\n\
Rss:                3380 kB\n\
AnonHugePages:      2048 kB\n\
VmFlags: rd ex mr mp me ac sd \n\
0074d000-00ab8000 r--p 00000000 00:00 0 \n\
Size:               3500 kB\n\
AnonHugePages:         0 kB\n\
KernelPageSize:        4 kB\n\
VmFlags: rd mr mp me ac sd \n";
        let lines = |t: &str| t.lines().map(String::from).collect::<Vec<_>>().into_iter();
        assert!(!plain_small_pages(lines(huge), 0x409cce));
        assert!(plain_small_pages(lines(huge), 0x800000));
        assert!(!plain_small_pages(lines(huge), 0x1234));
        assert!(!plain_small_pages(lines(""), 0x409cce));
        let ht = "00400000-00600000 r-xp 0 00:00 0 \nAnonHugePages: 0 kB\nKernelPageSize: 2048 kB\nVmFlags: rd ex ht\n";
        assert!(!plain_small_pages(lines(ht), 0x400000));
        let ht2 = "00400000-00600000 r-xp 0 00:00 0 \nAnonHugePages: 0 kB\nKernelPageSize: 4 kB\nVmFlags: rd ex ht\n";
        assert!(!plain_small_pages(lines(ht2), 0x400000));
    }

    #[test]
    fn query_results_survive_the_trip_through_the_pipe_format() {
        let qs = vec![
            PeerQuery {
                pid: 7,
                fd: 3,
                local: "127.0.0.1:47878".into(),
                peer: "-".into(),
                error: Some("errno 107".into()),
                state: Some(10),
            },
            PeerQuery {
                pid: 7,
                fd: 4,
                local: "10.0.0.1:1".into(),
                peer: "198.51.100.200:18443".into(),
                error: None,
                state: None,
            },
            PeerQuery {
                pid: 7,
                fd: 5,
                local: "-".into(),
                peer: "-".into(),
                error: Some("找不到可借用的系統呼叫指令\t含 Tab\n與換行".into()),
                state: None,
            },
        ];
        let back = decode_queries(7, &encode_queries(&qs));
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].error.as_deref(), Some("errno 107"));
        assert_eq!(back[0].state, Some(10), "socket 狀態要跟著送回主程式");
        assert_eq!(back[1].state, None);
        assert_eq!(back[1].peer, "198.51.100.200:18443");
        assert_eq!(back[1].error, None);
        assert_eq!(
            back[2].error.as_deref(),
            Some("找不到可借用的系統呼叫指令 含 Tab 與換行")
        );
        assert!(decode_queries(7, b"").is_empty());
        assert!(decode_queries(7, b"garbage line\n").is_empty());
    }

    #[test]
    fn the_child_does_not_keep_the_inherited_stdio_open_but_still_returns_its_result() {
        let r = run_in_child(
            || {
                let open = (0..3)
                    .filter(|fd| std::fs::read_link(format!("/proc/self/fd/{}", fd)).is_ok())
                    .count();
                vec![open as u8]
            },
            3000,
        )
        .unwrap();
        assert_eq!(r, vec![0u8]);
    }

    #[test]
    fn work_in_the_child_comes_back_and_a_stuck_child_is_abandoned_on_time() {
        let ok = run_in_child(|| b"hello".to_vec(), 3000).unwrap();
        assert_eq!(ok, b"hello");
        let t0 = Instant::now();
        let r = run_in_child(
            || {
                std::thread::sleep(Duration::from_secs(3));
                b"late".to_vec()
            },
            300,
        );
        assert!(r.unwrap_err().starts_with("逾時"));
        assert!(t0.elapsed() < Duration::from_millis(1500));
    }

    #[test]
    fn vdso_area_is_found_in_maps() {
        let maps =
            "7ffd9376d000-7ffd9376f000 r-xp 00000000 00:00 0                          [vdso]\n\
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]\n";
        assert_eq!(vdso_range(maps), Some((0x7ffd9376d000, 0x7ffd9376f000)));
        assert_eq!(vdso_range(MAPS_EXCERPT), None);
    }

    #[test]
    #[ignore]
    fn lab_watchdog_with_old_poke() {
        let pid: u32 = std::env::var("LAB_PID").unwrap().parse().unwrap();
        let t0 = Instant::now();
        let r = run_in_child(
            move || {
                let ipid = pid as i32;
                let _ = pt(PTRACE_SEIZE, ipid, 0, 0);
                let _ = pt(PTRACE_INTERRUPT, ipid, 0, 0);
                let _ = wait_stop(ipid, 500);
                if let Ok(regs) = getregs(ipid) {
                    let rip = regs[R_RIP] as usize;
                    let w = pt(PTRACE_PEEKDATA, ipid, rip, 0).unwrap_or(0) as u64;
                    let _ = pt(
                        PTRACE_POKEDATA,
                        ipid,
                        rip,
                        ((w & !0xFFFF) | 0x050F) as usize,
                    );
                }
                let _ = pt(PTRACE_DETACH, ipid, 0, 0);
                b"done".to_vec()
            },
            1500,
        );
        println!(
            "LAB_WATCHDOG elapsed_ms={} result={:?}",
            t0.elapsed().as_millis(),
            r.as_ref().map(|v| v.len())
        );
        assert!(r.is_err());
        assert!(t0.elapsed() < Duration::from_secs(4));
    }

    #[test]
    #[ignore]
    fn lab_query_peers_from_env() {
        let pid: u32 = std::env::var("LAB_PID").unwrap().parse().unwrap();
        let fds: Vec<u32> = std::env::var("LAB_FDS")
            .unwrap()
            .split(',')
            .map(|x| x.parse().unwrap())
            .collect();
        let t0 = Instant::now();
        let r = query_peers(pid, &fds);
        println!("LAB_RESULT elapsed_ms={} {:?}", t0.elapsed().as_millis(), r);
        if std::env::var("LAB_EXPECT_ADDR").is_ok() {
            assert!(!r.is_empty() && r.iter().all(|q| q.error.is_none() && q.peer != "-"));
        }
    }

    #[test]
    fn sockstat_values() {
        let t4 =
            "sockets: used 130\nTCP: inuse 8 orphan 0 tw 5 alloc 10 mem 1\nUDP: inuse 3 mem 0\n";
        assert_eq!(sockstat_value(t4, "TCP:", "inuse"), 8);
        assert_eq!(sockstat_value(t4, "TCP:", "tw"), 5);
        assert_eq!(sockstat_value(t4, "TCP:", "nothing"), -1);
        assert_eq!(sockstat_value("TCP6: inuse 6\n", "TCP6:", "inuse"), 6);
        assert_eq!(sockstat_value("", "TCP:", "inuse"), -1);
    }

    #[test]
    fn local_port_parsing() {
        let v4 = "   0: 0100007F:9A3E 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19709 1 ffff";
        assert_eq!(local_port_of_row(v4), Some(0x9A3E));
        let v6 = "   4: 00000000000000000000000001000000:A5D0 00000000000000000000000001000000:816E 01 00000000:00000000 00:0000";
        assert_eq!(local_port_of_row(v6), Some(0xA5D0));
        assert_eq!(local_port_of_row("garbage"), None);
    }

    #[test]
    fn socket_link_inode() {
        assert_eq!(socket_inode_of_link("socket:[27846]"), Some(27846));
        assert_eq!(socket_inode_of_link("/dev/null"), None);
        assert_eq!(socket_inode_of_link("anon_inode:[eventpoll]"), None);
    }

    #[test]
    fn conntrack_key_values() {
        let l = "ipv4     2 tcp      6 431999 ESTABLISHED src=10.99.0.1 dst=10.99.0.1 sport=35018 dport=37269 src=10.99.0.1 dst=10.99.0.1 sport=37269 dport=35018 [ASSURED]";
        assert_eq!(key_value(l, "src="), Some("10.99.0.1"));
        assert_eq!(key_value(l, "sport="), Some("35018"));
        assert_eq!(key_value(l, "dport="), Some("37269"));
        assert_eq!(key_value(l, "nothing="), None);
    }

    fn eth_ipv4_tcp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20];
        f[12] = 0x08;
        f[13] = 0x00;
        f[14] = 0x45;
        f[23] = 6;
        f[26..30].copy_from_slice(&src);
        f[30..34].copy_from_slice(&dst);
        f[34..36].copy_from_slice(&sp.to_be_bytes());
        f[36..38].copy_from_slice(&dp.to_be_bytes());
        f
    }

    #[test]
    fn frame_parsing_ipv4_ipv6_tcp_udp_and_other() {
        let f = eth_ipv4_tcp([10, 99, 0, 1], [10, 99, 0, 1], 35018, 37269);
        assert_eq!(
            parse_frame(&f),
            Some((
                Proto::Tcp,
                "10.99.0.1:35018".into(),
                "10.99.0.1:37269".into()
            ))
        );
        let mut udp = f.clone();
        udp[23] = 17;
        assert_eq!(
            parse_frame(&udp),
            Some((
                Proto::Udp,
                "10.99.0.1:35018".into(),
                "10.99.0.1:37269".into()
            )),
            "UDP 封包同樣取兩端"
        );
        let mut icmp = f.clone();
        icmp[23] = 1;
        assert_eq!(parse_frame(&icmp), None, "不是 TCP 也不是 UDP 就不收");
        let mut v6 = vec![0u8; 14 + 40 + 20];
        v6[12] = 0x86;
        v6[13] = 0xDD;
        v6[20] = 6;
        v6[37] = 1;
        v6[53] = 1;
        v6[54..56].copy_from_slice(&40000u16.to_be_bytes());
        v6[56..58].copy_from_slice(&22u16.to_be_bytes());
        assert_eq!(
            parse_frame(&v6),
            Some((Proto::Tcp, "[::1]:40000".into(), "[::1]:22".into()))
        );
        v6[20] = 17;
        assert_eq!(
            parse_frame(&v6).map(|t| t.0),
            Some(Proto::Udp),
            "IPv6 的 UDP 也認得"
        );
        assert_eq!(parse_frame(&[0u8; 5]), None);
    }

    #[test]
    fn conntrack_line_protocol() {
        assert_eq!(
            conntrack_proto("ipv4     2 tcp      6 431999 ESTABLISHED src=1.1.1.1 dst=2.2.2.2"),
            Some(Proto::Tcp)
        );
        assert_eq!(
            conntrack_proto("ipv4     2 udp      17 29 src=1.1.1.1 dst=2.2.2.2 sport=1 dport=2"),
            Some(Proto::Udp)
        );
        assert_eq!(
            conntrack_proto("ipv4     2 icmp     1 29 src=1.1.1.1"),
            None
        );
    }

    #[test]
    fn missing_sockstat_line_counts_as_zero_in_use() {
        assert_eq!(
            inuse_of(
                "TCP: inuse 8 tw 1
",
                "UDP6:"
            ),
            0
        );
        assert_eq!(
            inuse_of(
                "UDP: inuse 3 mem 0
",
                "UDP:"
            ),
            3
        );
        assert_eq!(
            inuse_of(
                "UDPLITE: inuse 0
",
                "UDP:"
            ),
            0,
            "UDPLITE 不是 UDP"
        );
    }

    #[test]
    fn sockaddr_parsing() {
        let mut v4 = [0u8; 16];
        v4[0] = 2;
        v4[2..4].copy_from_slice(&54738u16.to_be_bytes());
        v4[4..8].copy_from_slice(&[10, 99, 0, 1]);
        assert_eq!(parse_sockaddr(&v4), "10.99.0.1:54738");
        let mut v6 = [0u8; 28];
        v6[0] = 10;
        v6[2..4].copy_from_slice(&22u16.to_be_bytes());
        v6[23] = 1;
        assert_eq!(parse_sockaddr(&v6), "[::1]:22");
        assert_eq!(parse_sockaddr(&[0u8; 4]), "-");
    }

    #[test]
    fn netlink_message_building() {
        let a = nla(2, b"tcp_metrics\0");
        assert_eq!(a.len(), 16);
        assert_eq!(u16::from_ne_bytes([a[0], a[1]]), 16);
        assert_eq!(u16::from_ne_bytes([a[2], a[3]]), 2);
        let m = genl_msg(0x10, 1, 7, 3, &a);
        assert_eq!(m.len(), 16 + 4 + 16);
        assert_eq!(
            u32::from_ne_bytes([m[0], m[1], m[2], m[3]]) as usize,
            m.len()
        );
        assert_eq!(m[16], 3, "命令");
        assert_eq!(m[17], 1, "版本");
        assert_eq!(nla(1, &[1, 2, 3]).len(), 8);
    }

    #[test]
    fn family_id_and_metrics_parsing() {
        let id = nla(CTRL_ATTR_FAMILY_ID, &0x1234u16.to_ne_bytes());
        let resp = genl_msg(0x10, 0, 1, 1, &id);
        assert_eq!(parse_family_id(&resp), Some(0x1234));
        assert_eq!(parse_family_id(&[0u8; 8]), None);
        let mut a1 = nla(TCP_METRICS_ATTR_ADDR_IPV4, &[10, 99, 0, 1]);
        a1.extend(nla(3, &5000u64.to_ne_bytes()));
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        let a2 = nla(TCP_METRICS_ATTR_ADDR_IPV6, &v6);
        let mut resp = genl_msg(0x1234, 2, 2, 1, &a1);
        resp.extend(genl_msg(0x1234, 2, 2, 1, &a2));
        let mut done = vec![0u8; 20];
        done[0..4].copy_from_slice(&20u32.to_ne_bytes());
        done[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        resp.extend(done);
        let (addrs, finished) = parse_metrics(&resp, 0x1234);
        assert_eq!(addrs, vec!["10.99.0.1".to_string(), "[::1]".to_string()]);
        assert!(finished);
        let (none, finished) = parse_metrics(&resp, 0x9999);
        assert!(none.is_empty() && finished, "別的家族的訊息不收");
    }

    #[test]
    fn proc_address_text_decoding() {
        assert_eq!(
            proc_addr_text("0100007F:0016").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(proc_addr_text("00000000:0000"), None);
        assert_eq!(
            proc_addr_text("00000000000000000000000001000000:0016").as_deref(),
            Some("[::1]")
        );
        assert_eq!(
            proc_addr_text("00000000000000000000000000000000:0000"),
            None
        );
        assert_eq!(proc_addr_text("zz:1"), None);
    }

    #[test]
    fn port_of_endpoint() {
        assert_eq!(port_of("10.99.0.1:54738"), Some(54738));
        assert_eq!(port_of("[::1]:22"), Some(22));
        assert_eq!(port_of("nonsense"), None);
    }
}
