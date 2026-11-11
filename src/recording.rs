use crate::model::{
    AuditLogin, CapturePair, ConnSample, FileInfo, HeldSocket, LoadLine, LogCopy, Meta, ModLists,
    ModSample, NameCheck, Observation, OriginFacts, PeerQuery, PortKey, ProcEvidence, ProcSample,
    Proto, RawFile, RawFileFact, RawLookup, SessionFile, Unlisted,
};
use crate::model::{
    ContentMismatch, ContentScan, DeletedProc, DeletedScan, DirCover, DiskDevice, DiskScan,
    DiskStatus, DiskWalk, ExeContradiction, ExeScan, HiddenFile, LocalAddr, LocalAddrs, PathNow,
    ProcCover, ProcSocket,
};

const MAGIC: &str = "rootkit-scan-record 21";
const OLD_MAGICS: [&str; 12] = [
    "rootkit-scan-record 9",
    "rootkit-scan-record 10",
    "rootkit-scan-record 11",
    "rootkit-scan-record 12",
    "rootkit-scan-record 13",
    "rootkit-scan-record 14",
    "rootkit-scan-record 15",
    "rootkit-scan-record 16",
    "rootkit-scan-record 17",
    "rootkit-scan-record 18",
    "rootkit-scan-record 19",
    "rootkit-scan-record 20",
];

pub const EMBED_BEGIN: &str = "=== 錄製檔開始 ===";
pub const EMBED_END: &str = "=== 錄製檔結束 ===";

pub fn extract_embedded(text: &str) -> Result<Option<String>, String> {
    let mut lines = text.lines();
    if !lines.any(|l| l == EMBED_BEGIN) {
        return Ok(None);
    }
    let mut out = String::new();
    for l in lines {
        if l == EMBED_END {
            return Ok(Some(out));
        }
        out.push_str(l);
        out.push('\n');
    }
    Err("報告裡的錄製檔沒有結尾標記，檔案可能被截斷".to_string())
}

fn esc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'/' || b == b'-' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn clean_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control()
                || matches!(
                    c,
                    '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
                )
            {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn unesc(s: &str) -> String {
    clean_text(&unesc_raw(s))
}

fn unesc_raw(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    v.as_ref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "-".into())
}

fn opt_text(v: &Option<String>) -> String {
    v.as_deref().map(esc_or_dash).unwrap_or_else(|| "-".into())
}

fn esc_or_dash(s: &str) -> String {
    match s {
        "" => "%".into(),
        "-" => "%2D".into(),
        _ => esc(s),
    }
}

fn unesc_or_empty(s: &str) -> String {
    if s == "%" {
        String::new()
    } else {
        unesc(s)
    }
}

fn unopt_text(s: &str) -> Option<String> {
    if s == "-" {
        None
    } else {
        Some(unesc_or_empty(s))
    }
}

fn unopt_multiline(s: &str) -> Option<String> {
    match s {
        "-" => None,
        "%" => Some(String::new()),
        _ => Some(unesc_raw(s)),
    }
}

fn pair_text(v: &Option<(u32, u32)>) -> String {
    v.map(|(a, b)| format!("{},{}", a, b))
        .unwrap_or_else(|| "-".into())
}

fn parse_pair(s: &str) -> Result<Option<(u32, u32)>, String> {
    if s == "-" {
        return Ok(None);
    }
    let (a, b) = s.split_once(',').ok_or("紀錄檔的帳號欄位格式不對")?;
    Ok(Some((
        a.parse().map_err(|_| "紀錄檔的帳號欄位不是數字")?,
        b.parse().map_err(|_| "紀錄檔的帳號欄位不是數字")?,
    )))
}

fn info_text(v: &Option<FileInfo>) -> String {
    match v {
        None => "-".into(),
        Some(FileInfo::Ok {
            size,
            mtime,
            ctime,
            nlink,
        }) => format!("ok,{},{},{},{}", size, mtime, ctime, nlink),
        Some(FileInfo::Err(e)) => format!("err,{}", esc(e)),
    }
}

fn parse_info(s: &str) -> Result<Option<FileInfo>, String> {
    if s == "-" {
        return Ok(None);
    }
    if let Some(e) = s.strip_prefix("err,") {
        return Ok(Some(FileInfo::Err(unesc(e))));
    }
    let v: Vec<&str> = s
        .strip_prefix("ok,")
        .ok_or("紀錄檔的檔案資訊欄位格式不對")?
        .split(',')
        .collect();
    if v.len() != 4 {
        return Err("紀錄檔的檔案資訊欄位格式不對".into());
    }
    let n = |x: &str| -> Result<i64, String> {
        x.parse()
            .map_err(|_| "紀錄檔的檔案資訊欄位不是數字".to_string())
    };
    Ok(Some(FileInfo::Ok {
        size: n(v[0])? as u64,
        mtime: n(v[1])?,
        ctime: n(v[2])?,
        nlink: n(v[3])? as u64,
    }))
}

fn join_list(v: &[String]) -> String {
    if v.is_empty() {
        "-".into()
    } else {
        v.iter().map(|s| esc(s)).collect::<Vec<_>>().join(",")
    }
}

fn split_list(s: &str) -> Vec<String> {
    if s == "-" {
        Vec::new()
    } else {
        s.split(',').map(unesc).collect()
    }
}

pub fn encode(obs: &Observation) -> String {
    let m = &obs.meta;
    let mut s = String::new();
    s.push_str(MAGIC);
    s.push('\n');
    s.push_str(&format!(
        "meta hostname={} kernel={} os={} epoch={} btime={} clk_tck={} is_root={} pid_max={} uptime={} elapsed={} scanner={}\n",
        esc(&m.hostname),
        esc(&m.kernel),
        esc(&m.os),
        m.epoch,
        m.btime,
        m.clk_tck,
        m.is_root as u8,
        m.pid_max,
        m.uptime_s,
        m.elapsed_ms,
        opt_text(&m.scanner_sha256)
    ));
    for smp in &obs.proc_samples {
        s.push_str(&format!(
            "sample t_ms={} listed={} alive={} cg={} sread={} strust={} sched={} timer={}\n",
            smp.t_ms,
            smp.n_listed,
            smp.n_alive,
            smp.n_cgroup,
            smp.sched_read as u8,
            smp.sched_trusted as u8,
            smp.n_sched,
            smp.n_timer
        ));
        for u in &smp.unlisted {
            s.push_str(&format!(
                "u pid={} via={} start={} ppid={} comm={} exe={} cmd={}\n",
                u.pid,
                via_text(u),
                u.starttime,
                opt(&u.ppid),
                esc(&u.comm),
                u.exe.as_deref().map(esc).unwrap_or_else(|| "-".into()),
                esc(&u.cmdline)
            ));
        }
    }
    for ms in &obs.mod_samples {
        s.push_str(&format!(
            "msample t_ms={} nlb={} nlm={} nla={} l1={} l2={} sub={} van={}\n",
            ms.t_ms,
            ms.nl_before,
            ms.nl_mid,
            ms.nl_after,
            ms.n_list1,
            ms.n_list2,
            ms.n_sub,
            ms.vanished
        ));
    }
    let l = &obs.mod_lists;
    s.push_str(&format!(
        "lists proc_before={} proc_after={} sys_before={} sys_after={}\n",
        join_list(&l.proc_before),
        join_list(&l.proc_after),
        join_list(&l.sys_before),
        join_list(&l.sys_after)
    ));
    for lg in &obs.logs {
        s.push_str(&format!(
            "log source={} readable={} records={} first_seq={} gaps={} banner={} min_epoch={} files={} skipped={} unread={}\n",
            esc(&lg.source),
            lg.readable as u8,
            lg.records,
            opt(&lg.first_seq),
            lg.seq_gaps,
            lg.boot_banner as u8,
            opt(&lg.min_epoch),
            lg.files,
            lg.skipped,
            lg.unread
        ));
        for ll in &lg.load_lines {
            s.push_str(&format!(
                "ll name={} epoch={} seq={} text={}\n",
                esc(&ll.name),
                opt(&ll.epoch),
                opt(&ll.seq),
                esc(&ll.text)
            ));
        }
    }
    for nc in &obs.name_checks {
        s.push_str(&format!(
            "nc name={} stat={} init={} taint={} addr={}\n",
            esc(&nc.name),
            nc.stat_ok as u8,
            esc(&nc.initstate),
            esc(&nc.taint),
            esc(&nc.text_addr)
        ));
    }
    for c in &obs.conn_samples {
        s.push_str(&format!(
            "csample t_ms={} inuse4={} tw={} inuse6={} e4={} w4={} y4={} e6={} w6={} y6={} su4={} sl4={} su6={} sl6={} sa={} ru4={} rl4={} ru6={} rl6={}\n",
            c.t_ms, c.inuse4, c.tw, c.inuse6, c.e4, c.w4, c.y4, c.e6, c.w6, c.y6,
            c.su4, c.sl4, c.su6, c.sl6, c.su_after, c.ru4, c.rl4, c.ru6, c.rl6
        ));
    }
    let k = &obs.conn;
    s.push_str(&format!(
        "conn listed_before={} listed_after={} inuse1={} inuse2={} vanished={} rounds={} vcap={} conntrack={} capture={} capture_secs={} ptrace={} metrics={} tcp_metrics={} visible={}{}{}\n",
        join_ports(&k.listed_ports_before),
        join_ports(&k.listed_ports_after),
        join_ports(&k.inuse_ports_pass1),
        join_ports(&k.inuse_ports_pass2),
        join_ports(&k.recheck_vanished),
        k.recheck_rounds,
        k.visible_capped as u8,
        k.conntrack_present as u8,
        k.capture_ran as u8,
        k.capture_secs,
        k.ptrace_ran as u8,
        k.metrics_ran as u8,
        join_list(&k.tcp_metrics),
        join_list(&k.visible_remotes),
        if k.attempts > 0 {
            format!(" attempts={}", k.attempts)
        } else {
            String::new()
        },
        if k.patrol_ran {
            format!(
                " patrol_limit={} patrol_ms={} patrol_samples={} patrol_rounds={} patrol_caught={}",
                k.patrol_limit_secs,
                k.patrol_ms,
                k.patrol_samples,
                k.patrol_rounds,
                k.patrol_caught as u8
            )
        } else {
            String::new()
        }
    ));
    for (port, addrs) in &k.port_local_addrs {
        s.push_str(&format!(
            "pla port={} addrs={}\n",
            port_text(*port),
            join_list(addrs)
        ));
    }
    for (tag, list) in [("held", &k.held), ("vheld", &k.visible_held)] {
        for h in list {
            s.push_str(&format!(
                "{} pid={} comm={} exe={} fd={} inode={}\n",
                tag,
                h.pid,
                esc(&h.comm),
                h.exe.as_deref().map(esc).unwrap_or_else(|| "-".into()),
                h.fd,
                h.inode
            ));
        }
    }
    for l in &k.conntrack_lines {
        s.push_str(&format!("ct text={}\n", esc(l)));
    }
    for c in &k.capture_pairs {
        s.push_str(&format!(
            "cap proto={} a={} b={} count={}\n",
            proto_letter(c.proto),
            esc(&c.a),
            esc(&c.b),
            c.count
        ));
    }
    for q in &k.peer_queries {
        s.push_str(&format!(
            "pq pid={} fd={} local={} peer={} err={}{}\n",
            q.pid,
            q.fd,
            esc(&q.local),
            esc(&q.peer),
            q.error.as_deref().map(esc).unwrap_or_else(|| "-".into()),
            q.state.map(|v| format!(" state={}", v)).unwrap_or_default()
        ));
    }
    let o = &obs.origin;
    if o.ran {
        s.push_str(&format!(
            "origin audit_ran={} audit_files={} audit_unread={} audit_min={}\n",
            o.audit_ran as u8,
            o.audit_files,
            o.audit_unread,
            opt(&o.audit_min_epoch)
        ));
        for f in &o.items {
            s.push_str(&format!(
                "of pid={} loginuid={} sessionid={} cgroup={} ssh_conn={} ssh_tty={} unit_checked={} unit_files={}\n",
                f.pid,
                opt(&f.loginuid),
                opt(&f.sessionid),
                opt_text(&f.cgroup),
                opt_text(&f.ssh_connection),
                opt_text(&f.ssh_tty),
                f.unit_checked as u8,
                join_list(&f.unit_files)
            ));
            if let Some(sf) = &f.session_file {
                s.push_str(&format!(
                    "osf pid={} user={} service={} kind={} remote={} tty={} state={} realtime={}\n",
                    f.pid,
                    opt_text(&sf.user),
                    opt_text(&sf.service),
                    opt_text(&sf.kind),
                    opt_text(&sf.remote_host),
                    opt_text(&sf.tty),
                    opt_text(&sf.state),
                    opt(&sf.realtime_us)
                ));
            }
        }
        for e in &o.evidence {
            s.push_str(&format!("pe pid={} {}\n", e.pid, evidence_fields(e)));
        }
        for r in &o.raw_files {
            s.push_str(&raw_line(r));
        }
        for l in &o.audit_logins {
            s.push_str(&format!(
                "oa ses={} epoch={} uid={} exe={} hostname={} addr={} terminal={}\n",
                l.ses,
                l.epoch,
                opt(&l.uid),
                esc_or_dash(&l.exe),
                esc_or_dash(&l.hostname),
                esc_or_dash(&l.addr),
                esc_or_dash(&l.terminal)
            ));
        }
    }
    s.push_str(&disk_lines(&obs.disk));
    s.push_str(&exe_lines(&obs.exe_scan));
    s.push_str(&deleted_lines(&obs.deleted_scan));
    s.push_str(&content_lines(&obs.content_scan));
    s.push_str(&addr_lines(&obs.local_addrs));
    s
}

fn addr_lines(a: &LocalAddrs) -> String {
    if !a.ran {
        return String::new();
    }
    let mut s = format!("ias n={}\n", a.items.len());
    for i in &a.items {
        s.push_str(&format!(
            "ia iface={} addr={}\n",
            esc_or_dash(&i.iface),
            i.addr
        ));
    }
    s
}

fn content_lines(c: &ContentScan) -> String {
    if !c.ran {
        return String::new();
    }
    let mut s = format!(
        "fc checked={} recent={} big={} unread={} candidates={} vanished={} roots={}\n",
        c.checked,
        c.skipped_recent,
        c.skipped_big,
        c.skipped_unreadable,
        c.candidates,
        c.vanished,
        join_list(&c.roots)
    );
    for u in &c.unavailable {
        s.push_str(&format!("fu reason={}\n", esc_or_dash(u)));
    }
    for m in &c.items {
        s.push_str(&format!(
            "fm path={} vsize={} vsha={} rsize={} rsha={} first={}\n",
            esc_or_dash(&m.path),
            m.vfs_size,
            m.vfs_sha256,
            m.raw_size,
            m.raw_sha256,
            opt(&m.first_diff)
        ));
    }
    s
}

fn evidence_fields(e: &ProcEvidence) -> String {
    format!(
        "uid={} gid={} tracer={} open_err={} bytes={} sha={} read_err={} info={}",
        pair_text(&e.uid),
        pair_text(&e.gid),
        opt(&e.tracer_pid),
        opt_text(&e.exe_open_error),
        opt(&e.exe_bytes),
        opt_text(&e.exe_sha256),
        opt_text(&e.exe_read_error),
        info_text(&e.exe_info)
    )
}

fn parse_evidence(f: &[(&str, &str)]) -> Result<ProcEvidence, String> {
    Ok(ProcEvidence {
        pid: num(f, "pid")?,
        uid: parse_pair(get(f, "uid")?)?,
        gid: parse_pair(get(f, "gid")?)?,
        tracer_pid: opt_num(f, "tracer")?,
        exe_open_error: unopt_text(get(f, "open_err")?),
        exe_bytes: opt_num(f, "bytes")?,
        exe_sha256: unopt_text(get(f, "sha")?),
        exe_read_error: unopt_text(get(f, "read_err")?),
        exe_info: parse_info(get(f, "info")?)?,
    })
}

fn exe_lines(x: &ExeScan) -> String {
    if !x.ran {
        return String::new();
    }
    let mut s = format!(
        "exe checked={} candidates={} vanished={}\n",
        x.checked, x.candidates, x.vanished
    );
    for c in &x.items {
        s.push_str(&format!(
            "xe pid={} comm={} ppid={} start={} exe={} cmd={} {}\n",
            c.pid,
            esc_or_dash(&c.comm),
            opt(&c.ppid),
            c.starttime,
            esc_or_dash(&c.exe),
            esc_or_dash(&c.cmdline),
            evidence_fields(&c.evidence)
        ));
    }
    s
}

fn path_now_text(p: &PathNow) -> String {
    match p {
        PathNow::Unknown => "unknown".into(),
        PathNow::Missing => "missing".into(),
        PathNow::Other => "other".into(),
        PathNow::File {
            ino,
            dev,
            ctime,
            mtime,
        } => format!("file:{}:{}:{}:{}", ino, dev, ctime, mtime),
    }
}

fn parse_path_now(s: &str) -> Result<PathNow, String> {
    match s {
        "unknown" => Ok(PathNow::Unknown),
        "missing" => Ok(PathNow::Missing),
        "other" => Ok(PathNow::Other),
        _ => {
            let bad = || format!("紀錄檔的路徑狀況 {} 看不懂", s);
            let rest = s.strip_prefix("file:").ok_or_else(bad)?;
            let v: Vec<&str> = rest.split(':').collect();
            if v.len() != 4 {
                return Err(bad());
            }
            Ok(PathNow::File {
                ino: v[0].parse().map_err(|_| bad())?,
                dev: v[1].parse().map_err(|_| bad())?,
                ctime: v[2].parse().map_err(|_| bad())?,
                mtime: v[3].parse().map_err(|_| bad())?,
            })
        }
    }
}

fn deleted_lines(d: &DeletedScan) -> String {
    if !d.ran {
        return String::new();
    }
    let mut s = format!(
        "dscan checked={} other_ns={} omitted={}\n",
        d.checked, d.other_ns, d.omitted
    );
    for p in &d.items {
        s.push_str(&format!(
            "dp pid={} ppid={} uid={} comm={} argv0={} cmd={} exe={} start={} fstat={} ino={} dev={} nlink={} size={} mtime={} ctime={} sha={} shanote={} crtime={} crnote={} apath={} anow={} lnow={} ns={} scap={}\n",
            p.pid,
            p.ppid,
            opt(&p.uid),
            esc_or_dash(&p.comm),
            esc_or_dash(&p.argv0),
            esc_or_dash(&p.cmdline),
            esc_or_dash(&p.exe_link),
            p.starttime,
            p.fstat_ok as u8,
            p.ino,
            p.dev,
            p.nlink,
            p.size,
            p.mtime,
            p.ctime,
            opt_text(&p.sha256),
            opt_text(&p.sha_note),
            opt(&p.crtime),
            opt_text(&p.crtime_note),
            esc_or_dash(&p.argv0_path),
            path_now_text(&p.argv0_now),
            path_now_text(&p.link_now),
            p.same_ns as u8,
            p.sockets_capped as u8
        ));
        for k in &p.sockets {
            s.push_str(&format!(
                "dps pid={} proto={} v6={} lip={} lport={} rip={} rport={} state={} lis={}\n",
                p.pid,
                if k.proto == Proto::Tcp { "t" } else { "u" },
                k.v6 as u8,
                esc_or_dash(&k.local_ip),
                k.local_port,
                esc_or_dash(&k.remote_ip),
                k.remote_port,
                esc_or_dash(&k.state),
                k.local_port_listening as u8
            ));
        }
    }
    s
}

fn parse_deleted_proc(f: &[(&str, &str)]) -> Result<DeletedProc, String> {
    Ok(DeletedProc {
        pid: num(f, "pid")?,
        ppid: num(f, "ppid")?,
        uid: opt_num(f, "uid")?,
        comm: unesc_or_empty(get(f, "comm")?),
        argv0: unesc_or_empty(get(f, "argv0")?),
        cmdline: unesc_or_empty(get(f, "cmd")?),
        exe_link: unesc_or_empty(get(f, "exe")?),
        starttime: num(f, "start")?,
        fstat_ok: num::<u8>(f, "fstat")? != 0,
        ino: num(f, "ino")?,
        dev: num(f, "dev")?,
        nlink: num(f, "nlink")?,
        size: num(f, "size")?,
        mtime: num(f, "mtime")?,
        ctime: num(f, "ctime")?,
        sha256: unopt_text(get(f, "sha")?),
        sha_note: unopt_text(get(f, "shanote")?),
        crtime: opt_num(f, "crtime")?,
        crtime_note: unopt_text(get(f, "crnote")?),
        argv0_path: unesc_or_empty(get(f, "apath")?),
        argv0_now: parse_path_now(get(f, "anow")?)?,
        link_now: parse_path_now(get(f, "lnow")?)?,
        same_ns: num::<u8>(f, "ns")? != 0,
        sockets: Vec::new(),
        sockets_capped: num::<u8>(f, "scap")? != 0,
    })
}

fn parse_deleted_socket(f: &[(&str, &str)]) -> Result<(u32, ProcSocket), String> {
    Ok((
        num(f, "pid")?,
        ProcSocket {
            proto: if get(f, "proto")? == "u" {
                Proto::Udp
            } else {
                Proto::Tcp
            },
            v6: num::<u8>(f, "v6")? != 0,
            local_ip: unesc_or_empty(get(f, "lip")?),
            local_port: num(f, "lport")?,
            remote_ip: unesc_or_empty(get(f, "rip")?),
            remote_port: num(f, "rport")?,
            state: unesc_or_empty(get(f, "state")?),
            local_port_listening: num::<u8>(f, "lis")? != 0,
        },
    ))
}

fn disk_lines(d: &DiskScan) -> String {
    if !d.ran {
        return String::new();
    }
    let mut s = format!(
        "disk rounds={} candidates={} vanished={} hidden_total={}",
        d.rounds, d.candidates, d.vanished, d.hidden_total
    );
    if d.cold_secs > 0 {
        s.push_str(&format!(" cold={}", d.cold_secs));
    }
    s.push('\n');
    for v in &d.devices {
        let head = format!(
            "dd mount={} source={} fstype={}",
            esc_or_dash(&v.mount_point),
            esc_or_dash(&v.source),
            esc_or_dash(&v.fstype)
        );
        match &v.status {
            DiskStatus::Walked(w) => {
                s.push_str(&format!(
                    "{} status=walked dirs={} entries={} fs_only={} dir_errors={} skipped={} trunc={}",
                    head, w.dirs, w.entries, w.fs_only, w.dir_errors, w.skipped_mounts, w.truncated as u8
                ));
                if w.unsettled > 0 {
                    s.push_str(&format!(" unsettled={}", w.unsettled));
                }
                s.push('\n');
            }
            DiskStatus::Unavailable(why) => s.push_str(&format!(
                "{} status=unavail reason={}\n",
                head,
                esc_or_dash(why)
            )),
        }
    }
    for h in &d.hidden {
        let r = &h.raw;
        s.push_str(&format!(
            "dh path={} dir={} name={} lstat={} ino={} kind={} size={} links={} mode={} mtime={} ctime={} crtime={} sha={} link={} children_total={} children={}\n",
            esc_or_dash(&h.path),
            esc_or_dash(&h.dir),
            esc_or_dash(&h.name),
            opt_text(&h.lstat_error),
            r.ino,
            r.kind,
            r.size,
            r.links,
            r.mode,
            r.mtime,
            r.ctime,
            opt(&r.crtime),
            opt_text(&r.sha256),
            opt_text(&r.link_target),
            h.children_total,
            join_list(&h.children)
        ));
    }
    for c in &d.proc_covers {
        s.push_str(&format!(
            "pc mount={} pid={} fstype={} source={} alive={}\n",
            esc_or_dash(&c.mount_point),
            c.pid,
            esc_or_dash(&c.fstype),
            esc_or_dash(&c.source),
            c.alive as u8
        ));
    }
    for c in &d.dir_covers {
        s.push_str(&format!(
            "dc path={} fstype={} source={} total={} names={}\n",
            esc_or_dash(&c.path),
            esc_or_dash(&c.fstype),
            esc_or_dash(&c.source),
            c.total,
            join_list(&c.names)
        ));
    }
    for p in &d.unsettled_dirs {
        s.push_str(&format!("du path={}\n", esc_or_dash(p)));
    }
    s
}

fn parse_disk_overview(f: &[(&str, &str)], d: &mut DiskScan) -> Result<(), String> {
    d.ran = true;
    d.rounds = num(f, "rounds")?;
    d.candidates = num(f, "candidates")?;
    d.vanished = num(f, "vanished")?;
    d.hidden_total = num(f, "hidden_total")?;
    d.cold_secs = get(f, "cold")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    Ok(())
}

fn parse_disk_device(f: &[(&str, &str)]) -> Result<DiskDevice, String> {
    let status = match get(f, "status")? {
        "walked" => DiskStatus::Walked(DiskWalk {
            dirs: num(f, "dirs")?,
            entries: num(f, "entries")?,
            fs_only: num(f, "fs_only")?,
            dir_errors: num(f, "dir_errors")?,
            skipped_mounts: num(f, "skipped")?,
            truncated: num::<u8>(f, "trunc")? != 0,
            unsettled: get(f, "unsettled")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }),
        "unavail" => DiskStatus::Unavailable(unesc_or_empty(get(f, "reason")?)),
        other => return Err(format!("紀錄檔的 status 欄位看不懂：{}", other)),
    };
    Ok(DiskDevice {
        mount_point: unesc_or_empty(get(f, "mount")?),
        source: unesc_or_empty(get(f, "source")?),
        fstype: unesc_or_empty(get(f, "fstype")?),
        status,
    })
}

fn parse_hidden_file(f: &[(&str, &str)]) -> Result<HiddenFile, String> {
    Ok(HiddenFile {
        path: unesc_or_empty(get(f, "path")?),
        dir: unesc_or_empty(get(f, "dir")?),
        name: unesc_or_empty(get(f, "name")?),
        lstat_error: unopt_text(get(f, "lstat")?),
        raw: RawFile {
            ino: num(f, "ino")?,
            kind: get(f, "kind")?
                .chars()
                .next()
                .ok_or("紀錄檔的 kind 欄位是空的")?,
            size: num(f, "size")?,
            links: num(f, "links")?,
            mode: num(f, "mode")?,
            mtime: num(f, "mtime")?,
            ctime: num(f, "ctime")?,
            crtime: opt_num(f, "crtime")?,
            sha256: unopt_text(get(f, "sha")?),
            link_target: unopt_text(get(f, "link")?),
            ..Default::default()
        },
        children_total: num(f, "children_total")?,
        children: split_list(get(f, "children")?),
    })
}

fn raw_line(r: &RawFileFact) -> String {
    let head = format!(
        "rf path={} vfs={} vtrunc={} vcontent={}",
        esc_or_dash(&r.path),
        opt_text(&r.vfs_error),
        r.vfs_content_truncated as u8,
        opt_text(&r.vfs_content)
    );
    match &r.raw {
        RawLookup::Unavailable(why) => format!("{} raw=unavail reason={}\n", head, esc_or_dash(why)),
        RawLookup::NotFound => format!("{} raw=notfound\n", head),
        RawLookup::Found(f) => format!(
            "{} raw=found ino={} kind={} size={} links={} mode={} mtime={} ctime={} crtime={} sha={} link={} trunc={} content={}\n",
            head,
            f.ino,
            f.kind,
            f.size,
            f.links,
            f.mode,
            f.mtime,
            f.ctime,
            opt(&f.crtime),
            opt_text(&f.sha256),
            opt_text(&f.link_target),
            f.content_truncated as u8,
            opt_text(&f.content)
        ),
    }
}

fn parse_raw_line(f: &[(&str, &str)]) -> Result<RawFileFact, String> {
    let raw = match get(f, "raw")? {
        "unavail" => RawLookup::Unavailable(unesc_or_empty(get(f, "reason")?)),
        "notfound" => RawLookup::NotFound,
        "found" => RawLookup::Found(RawFile {
            ino: num(f, "ino")?,
            kind: get(f, "kind")?
                .chars()
                .next()
                .ok_or("紀錄檔的 kind 欄位是空的")?,
            size: num(f, "size")?,
            links: num(f, "links")?,
            mode: num(f, "mode")?,
            mtime: num(f, "mtime")?,
            ctime: num(f, "ctime")?,
            crtime: opt_num(f, "crtime")?,
            sha256: unopt_text(get(f, "sha")?),
            link_target: unopt_text(get(f, "link")?),
            content_truncated: num::<u8>(f, "trunc")? != 0,
            content: unopt_multiline(get(f, "content")?),
        }),
        other => return Err(format!("紀錄檔的 raw 欄位看不懂：{}", other)),
    };
    Ok(RawFileFact {
        path: unesc_or_empty(get(f, "path")?),
        vfs_error: unopt_text(get(f, "vfs")?),
        vfs_content: unopt_multiline(get(f, "vcontent")?),
        vfs_content_truncated: num::<u8>(f, "vtrunc")? != 0,
        raw,
    })
}

fn via_text(u: &Unlisted) -> String {
    format!(
        "{}{}{}{}",
        if u.via_kill { "k" } else { "" },
        if u.via_cgroup { "c" } else { "" },
        if u.via_sched { "s" } else { "" },
        if u.via_timer { "t" } else { "" }
    )
}

fn proto_letter(p: Proto) -> char {
    match p {
        Proto::Tcp => 't',
        Proto::Udp => 'u',
    }
}

fn port_text(k: PortKey) -> String {
    format!("{}{}", proto_letter(k.proto), k.port)
}

fn parse_port_text(p: &str) -> Result<PortKey, String> {
    let bad = || format!("紀錄檔的埠 {} 格式不對（應為 t 或 u 加數字）", p);
    let proto = match p.chars().next() {
        Some('t') => Proto::Tcp,
        Some('u') => Proto::Udp,
        _ => return Err(bad()),
    };
    let port = p[1..].parse::<u16>().map_err(|_| bad())?;
    Ok(PortKey { proto, port })
}

fn join_ports(v: &[PortKey]) -> String {
    if v.is_empty() {
        "-".into()
    } else {
        v.iter()
            .map(|p| port_text(*p))
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn split_ports(s: &str) -> Result<Vec<PortKey>, String> {
    if s == "-" {
        return Ok(Vec::new());
    }
    s.split(',').map(parse_port_text).collect()
}

fn fields(line: &str) -> Vec<(&str, &str)> {
    line.split_whitespace()
        .skip(1)
        .filter_map(|t| t.split_once('='))
        .collect()
}

fn get<'a>(f: &[(&'a str, &'a str)], k: &str) -> Result<&'a str, String> {
    f.iter()
        .find(|(n, _)| *n == k)
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("紀錄檔缺少欄位 {}", k))
}

fn num<T: std::str::FromStr>(f: &[(&str, &str)], k: &str) -> Result<T, String> {
    get(f, k)?
        .parse::<T>()
        .map_err(|_| format!("紀錄檔欄位 {} 不是數字", k))
}

fn opt_flag(f: &[(&str, &str)], k: &str) -> bool {
    get(f, k).is_ok_and(|v| v == "1")
}

fn opt_num<T: std::str::FromStr>(f: &[(&str, &str)], k: &str) -> Result<Option<T>, String> {
    let v = get(f, k)?;
    if v == "-" {
        Ok(None)
    } else {
        v.parse::<T>()
            .map(Some)
            .map_err(|_| format!("紀錄檔欄位 {} 不是數字", k))
    }
}

pub fn decode(text: &str) -> Result<Observation, String> {
    let mut lines = text.lines();
    if !matches!(lines.next(), Some(m) if m == MAGIC || OLD_MAGICS.contains(&m)) {
        return Err("不是這一版 rootkit-scan 的紀錄檔（第一行不符）".into());
    }
    let mut obs = Observation::default();
    for line in lines {
        let f = fields(line);
        let tag = line.split_whitespace().next().unwrap_or("");
        match tag {
            "" => {}
            "meta" => {
                obs.meta = Meta {
                    hostname: unesc(get(&f, "hostname")?),
                    kernel: unesc(get(&f, "kernel")?),
                    os: unesc(get(&f, "os")?),
                    epoch: num(&f, "epoch")?,
                    btime: num(&f, "btime")?,
                    clk_tck: num(&f, "clk_tck")?,
                    is_root: num::<u8>(&f, "is_root")? != 0,
                    pid_max: num(&f, "pid_max")?,
                    uptime_s: num(&f, "uptime")?,
                    elapsed_ms: num(&f, "elapsed")?,
                    scanner_sha256: match get(&f, "scanner") {
                        Ok(v) => unopt_text(v),
                        Err(_) => None,
                    },
                }
            }
            "sample" => obs.proc_samples.push(ProcSample {
                t_ms: num(&f, "t_ms")?,
                n_listed: num(&f, "listed")?,
                n_alive: num(&f, "alive")?,
                n_cgroup: num(&f, "cg")?,
                sched_read: opt_flag(&f, "sread"),
                sched_trusted: opt_flag(&f, "strust"),
                n_sched: num(&f, "sched").unwrap_or(0),
                n_timer: num(&f, "timer").unwrap_or(0),
                unlisted: Vec::new(),
            }),
            "u" => {
                let last = obs
                    .proc_samples
                    .last_mut()
                    .ok_or("紀錄檔的 u 行出現在 sample 行之前")?;
                let exe = get(&f, "exe")?;
                let via = get(&f, "via")?;
                last.unlisted.push(Unlisted {
                    pid: num(&f, "pid")?,
                    via_kill: via.contains('k'),
                    via_cgroup: via.contains('c'),
                    via_sched: via.contains('s'),
                    via_timer: via.contains('t'),
                    starttime: num(&f, "start")?,
                    ppid: opt_num(&f, "ppid")?,
                    comm: unesc(get(&f, "comm")?),
                    exe: if exe == "-" { None } else { Some(unesc(exe)) },
                    cmdline: unesc(get(&f, "cmd")?),
                });
            }
            "msample" => obs.mod_samples.push(ModSample {
                t_ms: num(&f, "t_ms")?,
                nl_before: num(&f, "nlb")?,
                nl_mid: num(&f, "nlm")?,
                nl_after: num(&f, "nla")?,
                n_list1: num(&f, "l1")?,
                n_list2: num(&f, "l2")?,
                n_sub: num(&f, "sub")?,
                vanished: num(&f, "van")?,
            }),
            "lists" => {
                obs.mod_lists = ModLists {
                    proc_before: split_list(get(&f, "proc_before")?),
                    proc_after: split_list(get(&f, "proc_after")?),
                    sys_before: split_list(get(&f, "sys_before")?),
                    sys_after: split_list(get(&f, "sys_after")?),
                }
            }
            "log" => obs.logs.push(LogCopy {
                source: unesc(get(&f, "source")?),
                readable: num::<u8>(&f, "readable")? != 0,
                records: num(&f, "records")?,
                first_seq: opt_num(&f, "first_seq")?,
                seq_gaps: num(&f, "gaps")?,
                boot_banner: num::<u8>(&f, "banner")? != 0,
                min_epoch: opt_num(&f, "min_epoch")?,
                files: num(&f, "files")?,
                skipped: num(&f, "skipped")?,
                unread: num(&f, "unread")?,
                load_lines: Vec::new(),
            }),
            "ll" => {
                let last = obs
                    .logs
                    .last_mut()
                    .ok_or("紀錄檔的 ll 行出現在 log 行之前")?;
                last.load_lines.push(LoadLine {
                    name: unesc(get(&f, "name")?),
                    text: unesc(get(&f, "text")?),
                    epoch: opt_num(&f, "epoch")?,
                    seq: opt_num(&f, "seq")?,
                });
            }
            "nc" => obs.name_checks.push(NameCheck {
                name: unesc(get(&f, "name")?),
                stat_ok: num::<u8>(&f, "stat")? != 0,
                initstate: unesc(get(&f, "init")?),
                taint: unesc(get(&f, "taint")?),
                text_addr: unesc(get(&f, "addr")?),
            }),
            "csample" => obs.conn_samples.push(ConnSample {
                t_ms: num(&f, "t_ms")?,
                inuse4: num(&f, "inuse4")?,
                tw: num(&f, "tw")?,
                inuse6: num(&f, "inuse6")?,
                e4: num(&f, "e4")?,
                w4: num(&f, "w4")?,
                y4: num(&f, "y4")?,
                e6: num(&f, "e6")?,
                w6: num(&f, "w6")?,
                y6: num(&f, "y6")?,
                su4: num(&f, "su4")?,
                sl4: num(&f, "sl4")?,
                su6: num(&f, "su6")?,
                sl6: num(&f, "sl6")?,
                su_after: num(&f, "sa")?,
                ru4: num(&f, "ru4")?,
                rl4: num(&f, "rl4")?,
                ru6: num(&f, "ru6")?,
                rl6: num(&f, "rl6")?,
            }),
            "conn" => {
                let c = &mut obs.conn;
                c.listed_ports_before = split_ports(get(&f, "listed_before")?)?;
                c.listed_ports_after = split_ports(get(&f, "listed_after")?)?;
                c.inuse_ports_pass1 = split_ports(get(&f, "inuse1")?)?;
                c.inuse_ports_pass2 = split_ports(get(&f, "inuse2")?)?;
                c.recheck_vanished = split_ports(get(&f, "vanished")?)?;
                c.recheck_rounds = num(&f, "rounds")?;
                c.visible_capped = num::<u8>(&f, "vcap")? != 0;
                c.conntrack_present = num::<u8>(&f, "conntrack")? != 0;
                c.capture_ran = num::<u8>(&f, "capture")? != 0;
                c.capture_secs = num(&f, "capture_secs")?;
                c.ptrace_ran = num::<u8>(&f, "ptrace")? != 0;
                c.metrics_ran = num::<u8>(&f, "metrics")? != 0;
                c.tcp_metrics = split_list(get(&f, "tcp_metrics")?);
                c.visible_remotes = split_list(get(&f, "visible")?);
                c.attempts = if get(&f, "attempts").is_ok() {
                    num(&f, "attempts")?
                } else {
                    0
                };
                if get(&f, "patrol_limit").is_ok() {
                    c.patrol_ran = true;
                    c.patrol_limit_secs = num(&f, "patrol_limit")?;
                    c.patrol_ms = num(&f, "patrol_ms")?;
                    c.patrol_samples = num(&f, "patrol_samples")?;
                    c.patrol_rounds = num(&f, "patrol_rounds")?;
                    c.patrol_caught = num::<u8>(&f, "patrol_caught")? != 0;
                }
            }
            "pla" => obs.conn.port_local_addrs.push((
                parse_port_text(get(&f, "port")?)?,
                split_list(get(&f, "addrs")?),
            )),
            "held" | "vheld" => {
                let exe = get(&f, "exe")?;
                let h = HeldSocket {
                    pid: num(&f, "pid")?,
                    comm: unesc(get(&f, "comm")?),
                    exe: if exe == "-" { None } else { Some(unesc(exe)) },
                    fd: num(&f, "fd")?,
                    inode: num(&f, "inode")?,
                };
                if tag == "held" {
                    obs.conn.held.push(h);
                } else {
                    obs.conn.visible_held.push(h);
                }
            }
            "ct" => obs.conn.conntrack_lines.push(unesc(get(&f, "text")?)),
            "cap" => obs.conn.capture_pairs.push(CapturePair {
                proto: match get(&f, "proto")? {
                    "t" => Proto::Tcp,
                    "u" => Proto::Udp,
                    other => return Err(format!("紀錄檔的協定 {} 不認得", other)),
                },
                a: unesc(get(&f, "a")?),
                b: unesc(get(&f, "b")?),
                count: num(&f, "count")?,
            }),
            "pq" => {
                let err = get(&f, "err")?;
                obs.conn.peer_queries.push(PeerQuery {
                    pid: num(&f, "pid")?,
                    fd: num(&f, "fd")?,
                    local: unesc(get(&f, "local")?),
                    peer: unesc(get(&f, "peer")?),
                    error: if err == "-" { None } else { Some(unesc(err)) },
                    state: get(&f, "state").ok().and_then(|v| v.parse().ok()),
                });
            }
            "origin" => {
                let o = &mut obs.origin;
                o.ran = true;
                o.audit_ran = num::<u8>(&f, "audit_ran")? != 0;
                o.audit_files = num(&f, "audit_files")?;
                o.audit_unread = num(&f, "audit_unread")?;
                o.audit_min_epoch = opt_num(&f, "audit_min")?;
            }
            "of" => obs.origin.items.push(OriginFacts {
                pid: num(&f, "pid")?,
                loginuid: opt_num(&f, "loginuid")?,
                sessionid: opt_num(&f, "sessionid")?,
                cgroup: unopt_text(get(&f, "cgroup")?),
                ssh_connection: unopt_text(get(&f, "ssh_conn")?),
                ssh_tty: unopt_text(get(&f, "ssh_tty")?),
                session_file: None,
                unit_checked: num::<u8>(&f, "unit_checked")? != 0,
                unit_files: split_list(get(&f, "unit_files")?),
            }),
            "osf" => {
                let pid: u32 = num(&f, "pid")?;
                let item = obs
                    .origin
                    .items
                    .iter_mut()
                    .find(|x| x.pid == pid)
                    .ok_or("紀錄檔的 osf 行出現在對應的 of 行之前")?;
                item.session_file = Some(SessionFile {
                    user: unopt_text(get(&f, "user")?),
                    service: unopt_text(get(&f, "service")?),
                    kind: unopt_text(get(&f, "kind")?),
                    remote_host: unopt_text(get(&f, "remote")?),
                    tty: unopt_text(get(&f, "tty")?),
                    state: unopt_text(get(&f, "state")?),
                    realtime_us: opt_num(&f, "realtime")?,
                });
            }
            "pe" => obs.origin.evidence.push(parse_evidence(&f)?),
            "exe" => {
                obs.exe_scan.ran = true;
                obs.exe_scan.checked = num(&f, "checked")?;
                obs.exe_scan.candidates = num(&f, "candidates")?;
                obs.exe_scan.vanished = num(&f, "vanished")?;
            }
            "fc" => {
                obs.content_scan.ran = true;
                obs.content_scan.checked = num(&f, "checked")?;
                obs.content_scan.skipped_recent = num(&f, "recent")?;
                obs.content_scan.skipped_big = num(&f, "big")?;
                obs.content_scan.skipped_unreadable = num(&f, "unread")?;
                obs.content_scan.candidates = num(&f, "candidates")?;
                obs.content_scan.vanished = num(&f, "vanished")?;
                obs.content_scan.roots = split_list(get(&f, "roots")?);
            }
            "ias" => obs.local_addrs.ran = true,
            "ia" => {
                let addr = get(&f, "addr")?;
                obs.local_addrs.items.push(LocalAddr {
                    iface: unesc_or_empty(get(&f, "iface")?),
                    addr: addr
                        .parse()
                        .map_err(|_| format!("ia 行的位址格式不對：{}", addr))?,
                });
            }
            "fu" => obs
                .content_scan
                .unavailable
                .push(unesc_or_empty(get(&f, "reason")?)),
            "fm" => obs.content_scan.items.push(ContentMismatch {
                path: unesc_or_empty(get(&f, "path")?),
                vfs_size: num(&f, "vsize")?,
                vfs_sha256: get(&f, "vsha")?.to_string(),
                raw_size: num(&f, "rsize")?,
                raw_sha256: get(&f, "rsha")?.to_string(),
                first_diff: opt_num(&f, "first")?,
            }),
            "dscan" => {
                obs.deleted_scan.ran = true;
                obs.deleted_scan.checked = num(&f, "checked")?;
                obs.deleted_scan.other_ns = num(&f, "other_ns")?;
                obs.deleted_scan.omitted = num(&f, "omitted")?;
            }
            "dp" => obs.deleted_scan.items.push(parse_deleted_proc(&f)?),
            "dps" => {
                let (pid, sock) = parse_deleted_socket(&f)?;
                match obs
                    .deleted_scan
                    .items
                    .iter_mut()
                    .rev()
                    .find(|p| p.pid == pid)
                {
                    Some(p) => p.sockets.push(sock),
                    None => return Err(format!("紀錄檔的 dps 行找不到編號 {} 的 dp 行", pid)),
                }
            }
            "xe" => obs.exe_scan.items.push(ExeContradiction {
                pid: num(&f, "pid")?,
                comm: unesc_or_empty(get(&f, "comm")?),
                ppid: opt_num(&f, "ppid")?,
                starttime: num(&f, "start")?,
                exe: unesc_or_empty(get(&f, "exe")?),
                cmdline: unesc_or_empty(get(&f, "cmd")?),
                evidence: parse_evidence(&f)?,
            }),
            "rf" => obs.origin.raw_files.push(parse_raw_line(&f)?),
            "disk" => parse_disk_overview(&f, &mut obs.disk)?,
            "dd" => obs.disk.devices.push(parse_disk_device(&f)?),
            "dh" => obs.disk.hidden.push(parse_hidden_file(&f)?),
            "pc" => obs.disk.proc_covers.push(ProcCover {
                mount_point: unesc_or_empty(get(&f, "mount")?),
                pid: num(&f, "pid")?,
                fstype: unesc_or_empty(get(&f, "fstype")?),
                source: unesc_or_empty(get(&f, "source")?),
                alive: num::<u8>(&f, "alive")? != 0,
            }),
            "dc" => obs.disk.dir_covers.push(DirCover {
                path: unesc_or_empty(get(&f, "path")?),
                fstype: unesc_or_empty(get(&f, "fstype")?),
                source: unesc_or_empty(get(&f, "source")?),
                total: num(&f, "total")?,
                names: split_list(get(&f, "names")?),
            }),
            "du" => obs
                .disk
                .unsettled_dirs
                .push(unesc_or_empty(get(&f, "path")?)),
            "oa" => obs.origin.audit_logins.push(AuditLogin {
                ses: num(&f, "ses")?,
                epoch: num(&f, "epoch")?,
                uid: opt_num(&f, "uid")?,
                exe: unesc_or_empty(get(&f, "exe")?),
                hostname: unesc_or_empty(get(&f, "hostname")?),
                addr: unesc_or_empty(get(&f, "addr")?),
                terminal: unesc_or_empty(get(&f, "terminal")?),
            }),
            _ => return Err(format!("紀錄檔有看不懂的一行：{}", line)),
        }
    }
    Ok(obs)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn esc_roundtrip_handles_spaces_and_non_ascii() {
        for s in [
            "",
            "a b",
            "/bin/python2 /root/x.py --victim",
            "中文 與 %41",
            "a=b c\td\n",
        ] {
            assert_eq!(unesc_raw(&esc(s)), s, "編碼再還原要逐字相同");
            assert!(!esc(s).contains(' '));
        }
    }

    #[test]
    fn names_read_from_the_machine_lose_control_characters_but_keep_everything_else() {
        assert_eq!(unesc(&esc("a\nb\tc\u{1b}[2Jd\u{202e}e\r")), "a?b?c?[2Jd?e?");
        assert_eq!(unesc(&esc("中文 %41 /usr/bin/x")), "中文 %41 /usr/bin/x");
        assert_eq!(unesc_or_empty("%"), "");
        assert_eq!(
            unopt_multiline(&esc("[Unit]\nA=b\n")).as_deref(),
            Some("[Unit]\nA=b\n")
        );
        assert_eq!(unopt_multiline("-"), None);
        assert_eq!(unopt_multiline("%").as_deref(), Some(""));
    }

    #[test]
    fn list_roundtrip_including_empty() {
        for v in [
            vec![],
            vec!["a".to_string()],
            vec!["a_b".to_string(), "c-d".to_string()],
        ] {
            assert_eq!(split_list(&join_list(&v)), v);
        }
    }

    pub fn sample_observation() -> Observation {
        Observation {
            meta: Meta {
                hostname: "h 1".into(),
                kernel: "3.10.0-1160.el7.x86_64".into(),
                os: "CentOS Linux release 7.9.2009 (Core)".into(),
                epoch: 1_791_982_917,
                btime: 1_791_982_853,
                clk_tck: 100,
                is_root: true,
                pid_max: 32768,
                uptime_s: 80.76,
                elapsed_ms: 1234,
                scanner_sha256: Some(
                    "11e9fd408559a098aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                ),
            },
            proc_samples: vec![ProcSample {
                t_ms: 5,
                n_listed: 110,
                n_alive: 112,
                n_cgroup: 112,
                sched_read: false,
                sched_trusted: false,
                n_sched: 0,
                n_timer: 0,
                unlisted: vec![
                    Unlisted {
                        pid: 7652,
                        via_kill: true,
                        via_cgroup: true,
                        via_sched: false,
                        via_timer: false,
                        starttime: 7364,
                        ppid: Some(2),
                        comm: "ktestwork".into(),
                        exe: None,
                        cmdline: String::new(),
                    },
                    Unlisted {
                        pid: 7655,
                        via_kill: true,
                        via_cgroup: false,
                        via_sched: false,
                        via_timer: false,
                        starttime: 7673,
                        ppid: Some(1),
                        comm: "python2".into(),
                        exe: Some("/usr/bin/python2.7".into()),
                        cmdline: "/bin/python2 /root/x.py --victim".into(),
                    },
                ],
            }],
            mod_samples: vec![ModSample {
                t_ms: 2,
                nl_before: 121,
                nl_mid: 121,
                nl_after: 121,
                n_list1: 118,
                n_list2: 118,
                n_sub: 118,
                vanished: 0,
            }],
            mod_lists: ModLists {
                proc_before: vec!["xfs".into(), "kvm".into()],
                proc_after: vec!["xfs".into(), "kvm".into()],
                sys_before: vec!["xfs".into(), "kvm".into(), "kernel".into()],
                sys_after: vec![],
            },
            logs: vec![
                LogCopy {
                    source: "kmsg".into(),
                    readable: true,
                    records: 569,
                    first_seq: Some(0),
                    seq_gaps: 0,
                    boot_banner: false,
                    min_epoch: None,
                    files: 0,
                    skipped: 0,
                    unread: 0,
                    load_lines: vec![LoadLine {
                        name: "testmod".into(),
                        text: "testmod: loading out-of-tree module taints kernel.".into(),
                        epoch: None,
                        seq: Some(567),
                    }],
                },
                LogCopy {
                    source: "messages".into(),
                    readable: true,
                    records: 817,
                    first_seq: None,
                    seq_gaps: 0,
                    boot_banner: true,
                    min_epoch: Some(1_791_982_860),
                    files: 2,
                    skipped: 1,
                    unread: 0,
                    load_lines: vec![LoadLine {
                        name: "testmod".into(),
                        text: "Oct 14 15:48:47 h kernel: testmod: loading out-of-tree module taints kernel.".into(),
                        epoch: Some(1_791_982_927),
                        seq: None,
                    }],
                },
            ],
            name_checks: vec![NameCheck {
                name: "testmod".into(),
                stat_ok: true,
                initstate: "live".into(),
                taint: "OE".into(),
                text_addr: "0xffffffffc07d3000".into(),
            }],
            conn_samples: vec![ConnSample {
                t_ms: 3,
                inuse4: 8,
                tw: 0,
                inuse6: 3,
                e4: 5,
                w4: 0,
                y4: 0,
                e6: 3,
                w6: 0,
                y6: 0,
                su4: 3,
                sl4: 0,
                su6: 3,
                sl6: 0,
                su_after: 6,
                ru4: 3,
                rl4: 0,
                ru6: 3,
                rl6: 0,
            }],
            conn: crate::model::ConnFacts {
                recheck_rounds: 4,
                recheck_vanished: vec![PortKey::udp(54349)],
                visible_capped: true,
                visible_held: vec![HeldSocket {
                    pid: 621,
                    comm: "rpcbind".into(),
                    exe: Some("/usr/sbin/rpcbind".into()),
                    fd: 5,
                    inode: 16171,
                }],
                listed_ports_before: vec![PortKey::tcp(22), PortKey::tcp(25), PortKey::udp(111)],
                listed_ports_after: vec![PortKey::tcp(22), PortKey::tcp(25), PortKey::udp(111)],
                inuse_ports_pass1: vec![
                    PortKey::tcp(22),
                    PortKey::tcp(25),
                    PortKey::tcp(36552),
                    PortKey::tcp(42149),
                    PortKey::udp(111),
                ],
                inuse_ports_pass2: vec![
                    PortKey::tcp(22),
                    PortKey::tcp(25),
                    PortKey::tcp(36552),
                    PortKey::tcp(42149),
                    PortKey::udp(111),
                ],
                port_local_addrs: vec![
                    (PortKey::tcp(36552), vec!["127.0.0.1".into()]),
                    (PortKey::tcp(42149), vec![]),
                ],
                held: vec![HeldSocket {
                    pid: 7655,
                    comm: "python2".into(),
                    exe: Some("/usr/bin/python2.7".into()),
                    fd: 4,
                    inode: 27846,
                }],
                conntrack_present: false,
                conntrack_lines: vec!["ipv4 2 tcp 6 431999 ESTABLISHED src=10.99.0.1 dst=10.99.0.1 sport=35018 dport=37269".into()],
                capture_ran: true,
                capture_secs: 5,
                capture_pairs: vec![CapturePair {
                    proto: Proto::Tcp,
                    a: "127.0.0.1:36552".into(),
                    b: "127.0.0.1:42149".into(),
                    count: 12,
                }],
                ptrace_ran: true,
                metrics_ran: true,
                tcp_metrics: vec!["10.99.0.1".into(), "[::1]".into()],
                visible_remotes: vec!["0.0.0.0".into()],
                attempts: 1,
                patrol_limit_secs: 0,
                patrol_ran: false,
                patrol_ms: 0,
                patrol_samples: 0,
                patrol_rounds: 0,
                patrol_caught: false,
                peer_queries: vec![
                    PeerQuery {
                        pid: 7655,
                        fd: 4,
                        local: "127.0.0.1:36552".into(),
                        peer: "127.0.0.1:42149".into(),
                        error: None,
                        state: None,
                    },
                    PeerQuery {
                        pid: 7655,
                        fd: 3,
                        local: "-".into(),
                        peer: "-".into(),
                        error: Some("errno 107".into()),
                        state: None,
                    },
                ],
            },
            origin: Default::default(),
            disk: Default::default(),
            exe_scan: Default::default(),
            deleted_scan: Default::default(),
            content_scan: Default::default(),
            local_addrs: Default::default(),
        }
    }

    #[test]
    fn peer_query_socket_state_roundtrips_and_a_format_20_file_reads_back_without_it() {
        let mut obs = sample_observation();
        obs.conn.peer_queries = vec![
            PeerQuery {
                pid: 1443,
                fd: 3,
                local: "198.51.100.20:43636".into(),
                peer: "-".into(),
                error: Some("errno 107".into()),
                state: Some(10),
            },
            PeerQuery {
                pid: 1580,
                fd: 3,
                local: "-".into(),
                peer: "-".into(),
                error: Some("errno 9".into()),
                state: None,
            },
        ];
        let text = encode(&obs);
        assert!(text.contains(" err=errno%20107 state=10\n"), "{}", text);
        assert!(
            text.contains(" err=errno%209\n"),
            "沒問到狀態就不寫欄位：{}",
            text
        );
        let back = decode(&text).unwrap();
        assert_eq!(back.conn.peer_queries[0].state, Some(10));
        assert_eq!(back.conn.peer_queries[1].state, None);
        let v20 = text
            .replacen("record 21", "record 20", 1)
            .replace(" state=10", "");
        let old = decode(&v20).unwrap();
        assert_eq!(old.conn.peer_queries[0].state, None);
        assert_eq!(old.conn.peer_queries[0].local, "198.51.100.20:43636");
    }

    #[test]
    fn connection_attempts_roundtrip_and_format_16_has_none() {
        let mut obs = sample_observation();
        obs.conn.attempts = 5;
        let text = encode(&obs);
        assert!(text.contains(" attempts=5\n"), "{}", text);
        assert_eq!(decode(&text).unwrap().conn.attempts, 5);
        let mut none = sample_observation();
        none.conn.attempts = 0;
        let t0 = encode(&none);
        assert!(!t0.contains("attempts="), "{}", t0);
        assert_eq!(decode(&t0).unwrap().conn.attempts, 0);
        let v16 = t0.replacen("record 21", "record 16", 1);
        assert_eq!(decode(&v16).unwrap().conn.attempts, 0);
    }

    fn sample_deleted() -> DeletedScan {
        DeletedScan {
            ran: true,
            checked: 90,
            other_ns: 2,
            omitted: 0,
            items: vec![DeletedProc {
                pid: 7585,
                ppid: 7564,
                uid: Some(0),
                comm: "systemd-fakemal".into(),
                argv0: "/usr/bin/systemd-fakemal".into(),
                cmdline: "/usr/bin/systemd-fakemal /root/fakemal.py - 1".into(),
                exe_link: "/usr/bin/systemd-fakemal (deleted)".into(),
                starttime: 5148,
                fstat_ok: true,
                ino: 8409410,
                dev: 64513,
                nlink: 0,
                size: 7144,
                mtime: 1793692775,
                ctime: 1793692779,
                sha256: Some("ee".repeat(32)),
                sha_note: None,
                crtime: Some(1793692774),
                crtime_note: None,
                argv0_path: "/usr/bin/systemd-fakemal".into(),
                argv0_now: PathNow::Missing,
                link_now: PathNow::File {
                    ino: 5,
                    dev: 64513,
                    ctime: 6,
                    mtime: 7,
                },
                same_ns: true,
                sockets: vec![
                    ProcSocket {
                        proto: Proto::Tcp,
                        v6: false,
                        local_ip: "10.9.9.1".into(),
                        local_port: 35946,
                        remote_ip: "203.0.113.50".into(),
                        remote_port: 18443,
                        state: "02".into(),
                        local_port_listening: false,
                    },
                    ProcSocket {
                        proto: Proto::Udp,
                        v6: true,
                        local_ip: "::".into(),
                        local_port: 5353,
                        remote_ip: "::".into(),
                        remote_port: 0,
                        state: "07".into(),
                        local_port_listening: false,
                    },
                ],
                sockets_capped: false,
            }],
        }
    }

    #[test]
    fn deleted_programs_roundtrip_and_format_18_has_none() {
        let mut obs = sample_observation();
        obs.deleted_scan = sample_deleted();
        let text = encode(&obs);
        assert!(
            text.contains("\ndscan checked=90 other_ns=2 omitted=0\n"),
            "{}",
            text
        );
        assert_eq!(decode(&text).unwrap().deleted_scan, obs.deleted_scan);
        let mut weird = sample_observation();
        let mut d = sample_deleted();
        d.items[0].comm = "-".into();
        d.items[0].argv0 = String::new();
        d.items[0].cmdline = "a b=c\nd".into();
        d.items[0].sha256 = None;
        d.items[0].sha_note = Some("超過 512 MiB".into());
        d.items[0].crtime = None;
        d.items[0].crtime_note = Some("xfs".into());
        weird.deleted_scan = d;
        let back = decode(&encode(&weird)).unwrap().deleted_scan;
        assert_eq!(back.items[0].comm, "-");
        assert_eq!(back.items[0].argv0, "");
        assert_eq!(back.items[0].cmdline, "a b=c?d");
        assert_eq!(back.items[0].sha_note.as_deref(), Some("超過 512 MiB"));
        assert_eq!(back.items[0].crtime, None);
        let none = encode(&sample_observation());
        assert!(!none.contains("dscan"), "{}", none);
        let v18 = none.replacen("record 21", "record 18", 1);
        assert!(!decode(&v18).unwrap().deleted_scan.ran);
        let bad = format!(
            "{}dps pid=1 proto=t v6=0 lip=a lport=1 rip=b rport=2 state=01 lis=0\n",
            none
        );
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn patrol_roundtrip_and_format_17_has_none() {
        let mut obs = sample_observation();
        obs.conn.patrol_ran = true;
        obs.conn.patrol_limit_secs = 150;
        obs.conn.patrol_ms = 23456;
        obs.conn.patrol_samples = 47;
        obs.conn.patrol_rounds = 2;
        obs.conn.patrol_caught = true;
        let text = encode(&obs);
        assert!(
            text.contains(
                " patrol_limit=150 patrol_ms=23456 patrol_samples=47 patrol_rounds=2 patrol_caught=1\n"
            ),
            "{}",
            text
        );
        let back = decode(&text).unwrap().conn;
        assert!(back.patrol_ran && back.patrol_caught);
        assert_eq!(
            (
                back.patrol_limit_secs,
                back.patrol_ms,
                back.patrol_samples,
                back.patrol_rounds
            ),
            (150, 23456, 47, 2)
        );
        let none = encode(&sample_observation());
        assert!(!none.contains("patrol_"), "{}", none);
        let back = decode(&none).unwrap().conn;
        assert!(!back.patrol_ran && back.patrol_ms == 0 && !back.patrol_caught);
        let v17 = none.replacen("record 21", "record 17", 1);
        assert!(!decode(&v17).unwrap().conn.patrol_ran);
    }

    #[test]
    fn local_addresses_roundtrip_and_format_15_has_none() {
        let mut obs = sample_observation();
        obs.local_addrs = LocalAddrs {
            ran: true,
            items: vec![
                LocalAddr {
                    iface: "eth0".into(),
                    addr: "198.51.100.20".parse().unwrap(),
                },
                LocalAddr {
                    iface: "eth0:1".into(),
                    addr: "192.168.250.20".parse().unwrap(),
                },
            ],
        };
        let text = encode(&obs);
        assert!(text.contains("ias n=2\n"), "{}", text);
        assert!(
            text.contains("ia iface=eth0 addr=198.51.100.20\n"),
            "{}",
            text
        );
        assert!(
            text.contains("ia iface=eth0%3A1 addr=192.168.250.20\n"),
            "{}",
            text
        );
        assert_eq!(decode(&text).unwrap(), obs);
        let mut empty = sample_observation();
        empty.local_addrs = LocalAddrs {
            ran: true,
            items: vec![],
        };
        assert_eq!(decode(&encode(&empty)).unwrap(), empty);
        let plain = sample_observation();
        assert!(!encode(&plain).contains("ias "));
        let v15 = encode(&plain).replacen("record 21", "record 15", 1);
        assert!(!decode(&v15).unwrap().local_addrs.ran);
        let bad = text.replace("addr=198.51.100.20", "addr=999.1.1.1");
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let obs = sample_observation();
        assert_eq!(decode(&encode(&obs)).unwrap(), obs);
    }

    #[test]
    fn udp_ports_and_udp_capture_roundtrip() {
        let mut obs = sample_observation();
        obs.conn.inuse_ports_pass1.push(PortKey::udp(49240));
        obs.conn
            .port_local_addrs
            .push((PortKey::udp(49240), vec!["127.0.0.1".into()]));
        obs.conn.capture_pairs.push(CapturePair {
            proto: Proto::Udp,
            a: "127.0.0.1:34091".into(),
            b: "127.0.0.1:49240".into(),
            count: 4,
        });
        let text = encode(&obs);
        assert!(text.contains("pla port=u49240"));
        assert!(text.contains("cap proto=u "));
        assert_eq!(decode(&text).unwrap(), obs);
    }

    #[test]
    fn unread_log_files_roundtrip() {
        let mut obs = sample_observation();
        obs.logs[1].unread = 2;
        let text = encode(&obs);
        assert!(text.contains("unread=2"));
        assert_eq!(decode(&text).unwrap(), obs);
    }

    #[test]
    fn content_scan_roundtrip_and_older_formats_have_no_content_section() {
        let mut obs = sample_observation();
        obs.content_scan = ContentScan {
            ran: true,
            checked: 1688,
            skipped_recent: 3,
            skipped_big: 1,
            skipped_unreadable: 2,
            candidates: 4,
            vanished: 3,
            roots: vec!["/etc".into(), "/home/we ird/.ssh".into()],
            unavailable: vec!["/usr/local/bin：這個路徑放在 xfs 檔案系統".into()],
            items: vec![
                ContentMismatch {
                    path: "/etc/we ird".into(),
                    vfs_size: 2041,
                    vfs_sha256: "ab".repeat(32),
                    raw_size: 2098,
                    raw_sha256: "cd".repeat(32),
                    first_diff: Some(1204),
                },
                ContentMismatch {
                    path: "/usr/local/bin/x".into(),
                    vfs_size: 1,
                    vfs_sha256: "01".repeat(32),
                    raw_size: 1,
                    raw_sha256: "02".repeat(32),
                    first_diff: None,
                },
            ],
        };
        let text = encode(&obs);
        assert!(text.contains("\nfc checked=1688 recent=3 big=1 unread=2 candidates=4 vanished=3 roots=/etc,/home/we%20ird/.ssh\n"), "{}", text);
        assert!(text.contains("\nfu reason="), "{}", text);
        assert!(
            text.contains("\nfm path=/etc/we%20ird vsize=2041 "),
            "{}",
            text
        );
        assert_eq!(decode(&text).unwrap(), obs);
        let plain = sample_observation();
        assert!(!encode(&plain).contains("\nfc "));
        let v14 = encode(&plain).replacen("record 21", "record 14", 1);
        assert!(!decode(&v14).unwrap().content_scan.ran);
    }

    #[test]
    fn exe_scan_roundtrip_and_older_formats_have_no_exe_section() {
        let mut obs = sample_observation();
        obs.exe_scan = ExeScan {
            ran: true,
            checked: 113,
            candidates: 3,
            vanished: 2,
            items: vec![ExeContradiction {
                pid: 4321,
                comm: "x y".into(),
                ppid: Some(1),
                starttime: 777,
                exe: "/opt/we ird/x".into(),
                cmdline: "/opt/we ird/x --a=1".into(),
                evidence: ProcEvidence {
                    pid: 4321,
                    uid: Some((0, 0)),
                    gid: Some((0, 0)),
                    tracer_pid: Some(0),
                    exe_open_error: None,
                    exe_bytes: Some(123),
                    exe_sha256: Some("ab".repeat(32)),
                    exe_read_error: None,
                    exe_info: Some(FileInfo::Err("ENOENT".into())),
                },
            }],
        };
        let text = encode(&obs);
        assert!(
            text.contains("\nexe checked=113 candidates=3 vanished=2\n"),
            "{}",
            text
        );
        assert!(
            text.contains("\nxe pid=4321 comm=x%20y ppid=1 start=777 "),
            "{}",
            text
        );
        assert_eq!(decode(&text).unwrap(), obs);
        let plain = sample_observation();
        assert!(!encode(&plain).contains("\nexe "));
        let v13 = encode(&plain).replacen("record 21", "record 13", 1);
        assert!(!decode(&v13).unwrap().exe_scan.ran);
    }

    #[test]
    fn disk_scan_roundtrip_and_older_formats_have_no_disk_section() {
        let mut obs = sample_observation();
        obs.disk = DiskScan {
            ran: true,
            devices: vec![
                DiskDevice {
                    mount_point: "/".into(),
                    source: "/dev/sda".into(),
                    fstype: "ext4".into(),
                    status: DiskStatus::Walked(DiskWalk {
                        dirs: 52_117,
                        entries: 1_604_000,
                        fs_only: 3,
                        dir_errors: 1,
                        skipped_mounts: 9,
                        truncated: true,
                        unsettled: 0,
                    }),
                },
                DiskDevice {
                    mount_point: "/boot".into(),
                    source: "/dev/sda1".into(),
                    fstype: "btrfs".into(),
                    status: DiskStatus::Unavailable(
                        "btrfs 檔案系統，原始磁碟解析目前只支援 ext4 與 XFS".into(),
                    ),
                },
                DiskDevice {
                    mount_point: "/data".into(),
                    source: "/dev/xvdb1".into(),
                    fstype: "xfs".into(),
                    status: DiskStatus::Walked(DiskWalk {
                        dirs: 10,
                        entries: 200,
                        unsettled: 4,
                        ..Default::default()
                    }),
                },
            ],
            rounds: 3,
            candidates: 5,
            vanished: 2,
            hidden: vec![
                HiddenFile {
                    path: "/usr/bin/exa svcd".into(),
                    dir: "/usr/bin".into(),
                    name: "exa svcd".into(),
                    lstat_error: Some("ENOENT".into()),
                    raw: RawFile {
                        ino: 48613,
                        kind: 'f',
                        size: 1_983_716,
                        links: 1,
                        mode: 0o755,
                        mtime: 1_773_022_830,
                        ctime: 1_773_022_830,
                        crtime: Some(1_773_022_830),
                        sha256: Some("ab".repeat(32)),
                        link_target: None,
                        ..Default::default()
                    },
                    children: Vec::new(),
                    children_total: 0,
                },
                HiddenFile {
                    path: "/tmp/.x".into(),
                    dir: "/tmp".into(),
                    name: ".x".into(),
                    lstat_error: None,
                    raw: RawFile {
                        ino: 7,
                        kind: 'd',
                        size: 4096,
                        links: 2,
                        mode: 0o700,
                        mtime: 1,
                        ctime: 2,
                        crtime: None,
                        ..Default::default()
                    },
                    children: vec!["a b".into(), "c".into()],
                    children_total: 25,
                },
            ],
            hidden_total: 3,
            proc_covers: vec![
                ProcCover {
                    mount_point: "/proc/4321".into(),
                    pid: 4321,
                    fstype: "tmpfs".into(),
                    source: "tmpfs".into(),
                    alive: true,
                },
                ProcCover {
                    mount_point: "/proc/77/fd".into(),
                    pid: 77,
                    fstype: "ext4".into(),
                    source: "/dev/sdb 1".into(),
                    alive: false,
                },
            ],
            dir_covers: vec![DirCover {
                path: "/usr/lib/we ird".into(),
                fstype: "tmpfs".into(),
                source: "tmpfs".into(),
                total: 25,
                names: vec!["a b".into(), ".x".into()],
            }],
            unsettled_dirs: vec!["/data/tmp".into(), "/data/we ird".into()],
            cold_secs: 60,
        };
        let text = encode(&obs);
        assert!(text.contains(" status=walked dirs=10 entries=200 fs_only=0 dir_errors=0 skipped=0 trunc=0 unsettled=4\n"));
        assert!(text.contains("\ndu path=/data/we%20ird\n"));
        assert!(
            text.contains("\npc mount=/proc/4321 pid=4321 fstype=tmpfs source=tmpfs alive=1\n"),
            "{}",
            text
        );
        assert!(
            text.contains("\ndc path=/usr/lib/we%20ird fstype=tmpfs source=tmpfs total=25 "),
            "{}",
            text
        );
        assert!(
            text.contains("\ndisk rounds=3 candidates=5 vanished=2 hidden_total=3 cold=60\n"),
            "{}",
            text
        );
        assert!(
            text.contains("\ndd mount=/ source=/dev/sda fstype=ext4 status=walked"),
            "{}",
            text
        );
        assert_eq!(decode(&text).unwrap(), obs);
        let v19 = text
            .replacen("record 21", "record 19", 1)
            .replace(" cold=60", "")
            .replace(" unsettled=4", "")
            .lines()
            .filter(|l| !l.starts_with("du "))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let back = decode(&v19).unwrap();
        assert_eq!(back.disk.cold_secs, 0);
        assert!(back.disk.unsettled_dirs.is_empty());
        assert!(back
            .disk
            .devices
            .iter()
            .all(|d| !matches!(&d.status, DiskStatus::Walked(w) if w.unsettled > 0)));
        let plain = sample_observation();
        assert!(!encode(&plain).contains("\ndisk "));
        let v12 = encode(&plain).replacen("record 21", "record 12", 1);
        assert!(!decode(&v12).unwrap().disk.ran);
    }

    #[test]
    fn origin_roundtrip_and_old_format_still_readable() {
        let mut obs = sample_observation();
        obs.origin = crate::model::OriginData {
            ran: true,
            evidence: vec![
                ProcEvidence {
                    pid: 7655,
                    uid: Some((0, 0)),
                    gid: Some((0, 1)),
                    tracer_pid: Some(0),
                    exe_open_error: None,
                    exe_bytes: Some(1_983_716),
                    exe_sha256: Some(
                        "92f136731d2f8c678fd7b5f3fbd8f80fbc5ac60f9d4eccf7279f17de993caabe".into(),
                    ),
                    exe_read_error: None,
                    exe_info: Some(FileInfo::Err("ENOENT".into())),
                },
                ProcEvidence {
                    pid: 7656,
                    uid: None,
                    gid: None,
                    tracer_pid: None,
                    exe_open_error: Some("EACCES".into()),
                    exe_bytes: None,
                    exe_sha256: None,
                    exe_read_error: Some("超過 512 MiB 的上限，沒有算指紋".into()),
                    exe_info: Some(FileInfo::Ok {
                        size: 66_060_288,
                        mtime: 1_773_022_830,
                        ctime: 1_773_022_830,
                        nlink: 1,
                    }),
                },
            ],
            items: vec![
                OriginFacts {
                    pid: 7655,
                    loginuid: Some(0),
                    sessionid: Some(2),
                    cgroup: Some("/user.slice/user-0.slice/session-2.scope".into()),
                    ssh_connection: Some("203.0.113.7 51776 10.0.0.1 22".into()),
                    ssh_tty: None,
                    session_file: Some(SessionFile {
                        user: Some("root".into()),
                        service: Some("sshd".into()),
                        kind: None,
                        remote_host: Some("-".into()),
                        tty: None,
                        state: Some("closing".into()),
                        realtime_us: Some(1_793_086_267_544_472),
                    }),
                    unit_checked: false,
                    unit_files: vec![],
                },
                OriginFacts {
                    pid: 7656,
                    loginuid: Some(crate::model::ID_UNSET),
                    sessionid: None,
                    cgroup: Some("/system.slice/a b.service".into()),
                    unit_checked: true,
                    unit_files: vec!["/etc/systemd/system/a b.service".into()],
                    ..Default::default()
                },
            ],
            audit_ran: true,
            audit_files: 2,
            audit_unread: 1,
            audit_min_epoch: Some(1_791_000_000),
            raw_files: vec![
                RawFileFact {
                    path: "/etc/systemd/system/x y.service".into(),
                    vfs_error: Some("ENOENT".into()),
                    vfs_content: None,
                    vfs_content_truncated: false,
                    raw: RawLookup::Found(RawFile {
                        ino: 48614,
                        kind: 'f',
                        size: 310,
                        links: 1,
                        mode: 0o644,
                        mtime: 1_772_323_210,
                        ctime: 1_772_323_210,
                        crtime: Some(1_773_022_830),
                        sha256: Some("ab".repeat(32)),
                        link_target: None,
                        content: Some(
                            "[Unit]\nDescription=a b %c\n\n[Service]\nExecStart=/usr/bin/x --a=1\n"
                                .into(),
                        ),
                        content_truncated: true,
                    }),
                },
                RawFileFact {
                    path: "/usr/lib/systemd/system/x.service".into(),
                    vfs_error: None,
                    vfs_content: Some("[Unit]\nDescription=從檔案系統讀的 100%\n".into()),
                    vfs_content_truncated: true,
                    raw: RawLookup::NotFound,
                },
                RawFileFact {
                    path: "/lib/systemd/system/x.service".into(),
                    vfs_error: Some("EACCES".into()),
                    vfs_content: None,
                    vfs_content_truncated: false,
                    raw: RawLookup::Unavailable(
                        "這個路徑放在 xfs 檔案系統，原始磁碟解析目前只支援 ext4".into(),
                    ),
                },
                RawFileFact {
                    path: "/etc/systemd/system/multi-user.target.wants/x.service".into(),
                    vfs_error: None,
                    vfs_content: None,
                    vfs_content_truncated: false,
                    raw: RawLookup::Found(RawFile {
                        ino: 48623,
                        kind: 'l',
                        size: 40,
                        links: 1,
                        mode: 0o777,
                        mtime: 1,
                        ctime: 2,
                        crtime: None,
                        sha256: None,
                        link_target: Some("/etc/systemd/system/x.service".into()),
                        content: Some(String::new()),
                        content_truncated: false,
                    }),
                },
            ],
            audit_logins: vec![AuditLogin {
                ses: 2,
                epoch: 1_793_086_267,
                uid: Some(0),
                exe: "/usr/sbin/sshd".into(),
                hostname: String::new(),
                addr: "::1".into(),
                terminal: "ssh".into(),
            }],
        };
        for smp in obs.proc_samples.iter_mut() {
            smp.sched_read = true;
            smp.sched_trusted = true;
            smp.n_sched = 114;
            smp.n_timer = 20;
            for u in smp.unlisted.iter_mut() {
                u.via_sched = true;
                u.via_timer = u.via_cgroup;
            }
        }
        let text = encode(&obs);
        assert!(text.starts_with("rootkit-scan-record 21\n"));
        assert!(
            text.contains(" sread=1 strust=1 sched=114 timer=20\n"),
            "{}",
            text
        );
        assert!(text.contains("u pid=7652 via=kcst "), "{}", text);
        assert!(text.contains("u pid=7655 via=ks "), "{}", text);
        assert!(
            text.contains("pe pid=7655 uid=0,0 gid=0,1 tracer=0"),
            "{}",
            text
        );
        assert!(text.contains("scanner=11e9fd408559a098"), "{}", text);
        assert_eq!(decode(&text).unwrap(), obs);
        let mut plain = sample_observation();
        plain.meta.scanner_sha256 = None;
        let v11 = encode(&plain).replacen("record 21", "record 11", 1);
        assert!(decode(&v11).unwrap().origin.raw_files.is_empty());
        let v9 = encode(&plain)
            .replacen("record 21", "record 9", 1)
            .replace(" scanner=-", "");
        let back = decode(&v9).unwrap();
        assert!(!back.origin.ran);
        assert!(back.meta.scanner_sha256.is_none());
        let v10 = encode(&plain)
            .replacen("record 11", "record 10", 1)
            .replace(" scanner=-", "");
        assert!(decode(&v10).is_ok());
        assert!(decode("rootkit-scan-record 10\nosf pid=1 user=- service=- kind=- remote=- tty=- state=- realtime=-\n").is_err());
    }

    #[test]
    fn decode_rejects_old_format_and_bad_ports() {
        assert!(
            decode("rootkit-scan-record 8\n").is_err(),
            "舊版格式沒有未讀欄位，不混用"
        );
        let bad = encode(&sample_observation()).replace("pla port=t36552", "pla port=36552");
        assert!(decode(&bad).is_err(), "埠沒有協定字母就看不懂");
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode("hello\n").is_err());
        assert!(
            decode("rootkit-scan-record 9\nu pid=1 via=k start=1 ppid=- comm=a exe=- cmd=\n")
                .is_err()
        );
        assert!(decode("rootkit-scan-record 9\nmystery x=1\n").is_err());
    }
}
