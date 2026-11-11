use crate::collect_origin::UNIT_DIRS;
use crate::judge::{
    source_label, ConnJudgement, ContentJudgement, ExeJudgement, FileJudgement, HiddenProc,
    Listener, ModJudgement, NamedModule, OriginJudgement, OriginKind, ProcJudgement,
};
use crate::model::{
    DiskStatus, FileInfo, HiddenFile, Observation, OriginFacts, PortKey, ProcEvidence, Proto,
    RawFile, RawFileFact, RawLookup,
};
use crate::timeutil::{fmt_tw, fmt_tw_sec};

const LINE: &str = "────────────────────────────────────────────────────────────";

fn born(h: &HiddenProc, clk_tck: u64) -> String {
    if h.info.starttime == 0 {
        return "無法取得".into();
    }
    format!(
        "開機後 {:.1} 秒",
        h.info.starttime as f64 / clk_tck.max(1) as f64
    )
}

fn name_of(h: &HiddenProc) -> String {
    if h.info.comm.is_empty() {
        "無法取得".into()
    } else {
        h.info.comm.clone()
    }
}

fn conn_items(c: &ConnJudgement) -> usize {
    if !c.confirmed {
        0
    } else {
        c.groups.len()
    }
}

fn taint_words(taint: &str) -> String {
    let mut w = Vec::new();
    if taint.contains('O') {
        w.push("被標為外來模組");
    }
    if taint.contains('E') {
        w.push("沒有簽章");
    }
    if w.is_empty() {
        String::new()
    } else {
        format!("{}；", w.join("、"))
    }
}

fn module_item(i: usize, m: &NamedModule, gap: Option<usize>, out: &mut String) {
    out.push_str(&format!("[{}] 被藏的模組　名字：{}\n", i, m.name));
    let state = if m.initstate.is_empty() {
        String::new()
    } else {
        format!("（狀態：{}）", m.initstate)
    };
    kv_app(
        out,
        "怎麼知道的",
        &format!(
            "用名字 {} 直接問核心，核心回答「存在」{}；但「模組清單」和「模組目錄清單」兩份名單都沒有列出它。",
            m.name, state
        ),
    );
    if let Some(g) = gap {
        kv_app(
            out,
            "輔助證據",
            &format!(
                "模組目錄的計數比列出來的多 {}（證據較弱，兩者出自同一份核心資料）。",
                g
            ),
        );
    }
    let srcs: Vec<String> = m
        .sources
        .iter()
        .map(|s| {
            format!(
                "{}（{}）",
                source_label(&s.source),
                if s.covered {
                    "紀錄完整"
                } else {
                    "紀錄可能不完整"
                }
            )
        })
        .collect();
    let mut from = match srcs.len() {
        0 => "無".to_string(),
        1 => format!("{}有載入紀錄。", srcs[0]),
        _ => format!("{}各有載入紀錄。", srcs.join("、")),
    };
    if let Some((thread, diff)) = &m.born_with {
        from.push_str(&format!(
            "\n載入那一行紀錄的時間，與被藏的核心執行緒 {} 的啟動時間只差 {} 秒。",
            thread, diff
        ));
    }
    kv_app(out, "名字來源", &from);
    let mut other = taint_words(&m.taint);
    if !m.taint.is_empty() {
        other.push_str(&format!("污染旗標 {}；", m.taint));
    }
    if !m.text_addr.is_empty() {
        other.push_str(&format!("模組位址 {}", m.text_addr));
    }
    if !other.is_empty() {
        kv_app(out, "其他", other.trim_end_matches('；'));
    }
    out.push('\n');
}

fn sources_text(sources: &[crate::judge::EndpointSource]) -> String {
    sources
        .iter()
        .map(|s| s.label())
        .collect::<Vec<_>>()
        .join("、")
}

fn attempts_text(obs: &Observation) -> String {
    let k = &obs.conn;
    let ct = if k.conntrack_present {
        "連線追蹤表（有這個功能，但沒有這些埠的紀錄）"
    } else {
        "連線追蹤表（這台機器沒有載入這個功能）"
    };
    let cap = if k.capture_ran {
        format!("旁聽封包 {} 秒（沒有看到這些埠的封包）", k.capture_secs)
    } else {
        "旁聽封包（沒有執行）".to_string()
    };
    let visible_pids: std::collections::BTreeSet<u32> =
        k.visible_held.iter().map(|h| h.pid).collect();
    let visible_queried = k
        .peer_queries
        .iter()
        .filter(|q| visible_pids.contains(&q.pid))
        .map(|q| q.pid)
        .collect::<std::collections::BTreeSet<u32>>()
        .len();
    let visible_note = if visible_queried > 0 {
        format!(
            "；含 {} 個握著不在連線表的 socket 的一般行程{}",
            visible_queried,
            if k.visible_capped {
                "，候選行程太多，只查了前面一部分"
            } else {
                ""
            }
        )
    } else {
        String::new()
    };
    let pt = if k.ptrace_ran {
        let errs: Vec<String> = k
            .peer_queries
            .iter()
            .filter_map(|q| {
                q.error
                    .as_ref()
                    .filter(|e| !e.contains("errno 107"))
                    .cloned()
            })
            .collect();
        let dialing_without_record = k.peer_queries.iter().any(|q| q.state == Some(2));
        if errs.is_empty() && dialing_without_record {
            format!(
                "暫時查詢行程（有執行；看到 socket 正在連出去（狀態 2），但連線追蹤表與旁聽封包都沒有它的紀錄{}）",
                visible_note
            )
        } else if errs.is_empty() {
            format!("暫時查詢行程（有執行，沒有取得位址{}）", visible_note)
        } else {
            format!("暫時查詢行程（失敗：{}{}）", errs.join("；"), visible_note)
        }
    } else {
        "暫時查詢行程（沒有適合查詢的使用者行程，或沒有執行）".to_string()
    };
    let tm = if k.metrics_ran {
        "TCP 目的地記憶（有執行，只能給位址候選，且只記 TCP）"
    } else {
        "TCP 目的地記憶（沒有執行或讀不到，且只記 TCP）"
    };
    format!("{}、{}、{}、{}", ct, cap, pt, tm)
}

fn methods_text(obs: &Observation) -> String {
    let k = &obs.conn;
    let ct = if k.conntrack_present {
        format!(
            "連線追蹤表：有這個功能，取得 {} 列相關紀錄",
            k.conntrack_lines.len()
        )
    } else {
        "連線追蹤表：這台機器沒有載入這個功能".to_string()
    };
    let cap = if k.capture_ran {
        format!(
            "旁聽封包：{} 秒，看到 {} 對相關的往來",
            k.capture_secs,
            k.capture_pairs.len()
        )
    } else {
        "旁聽封包：沒有執行".to_string()
    };
    let visible: std::collections::BTreeSet<u32> = k.visible_held.iter().map(|h| h.pid).collect();
    let asked: std::collections::BTreeSet<u32> = k.peer_queries.iter().map(|q| q.pid).collect();
    let general = asked.iter().filter(|p| visible.contains(p)).count();
    let answered = k
        .peer_queries
        .iter()
        .filter(|q| q.local != "-" && q.error.as_deref().is_none_or(|e| e.contains("errno 107")))
        .count();
    let with_peer = k
        .peer_queries
        .iter()
        .filter(|q| q.local != "-" && crate::judge::is_ip_endpoint(&q.peer))
        .count();
    let pt = if k.ptrace_ran {
        format!(
            "暫時查詢行程：查了 {} 個行程（其中 {} 個是一般行程{}），得到 {} 筆本機端位址（每筆是一個行程握的一個 socket），其中 {} 筆連對方位址也讀到了",
            asked.len(),
            general,
            if k.visible_capped {
                "，候選太多只查了前面一部分"
            } else {
                ""
            },
            answered,
            with_peer
        )
    } else {
        "暫時查詢行程：沒有執行".to_string()
    };
    let tm = if k.metrics_ran {
        format!(
            "TCP 目的地記憶：讀到 {} 個位址（只對 TCP）",
            k.tcp_metrics.len()
        )
    } else {
        "TCP 目的地記憶：沒有執行或讀不到（只對 TCP）".to_string()
    };
    format!("{}；{}；{}；{}", ct, cap, pt, tm)
}

fn ports_list(c: &ConnJudgement, ports: &[PortKey], with_binding: bool) -> String {
    let mut parts = Vec::new();
    for proto in [Proto::Tcp, Proto::Udp] {
        let mine: Vec<&PortKey> = ports.iter().filter(|k| k.proto == proto).collect();
        if mine.is_empty() {
            continue;
        }
        let list: Vec<String> = mine.iter().map(|k| k.port.to_string()).collect();
        let addrs: Vec<String> = c
            .port_addrs
            .iter()
            .filter(|(k, a)| with_binding && mine.contains(&k) && !a.is_empty())
            .map(|(k, a)| format!("{} 綁在 {}", k.port, a.join("、")))
            .collect();
        if addrs.is_empty() {
            parts.push(format!("{} {}", proto.name(), list.join("、")));
        } else {
            parts.push(format!(
                "{} {}（{}）",
                proto.name(),
                list.join("、"),
                addrs.join("；")
            ));
        }
    }
    parts.join("；")
}

fn ports_text(c: &ConnJudgement, ports: &[PortKey]) -> String {
    ports_list(c, ports, true)
}

fn address_lines(
    obs: &Observation,
    c: &ConnJudgement,
    endpoints: &[crate::judge::Endpoint],
    listeners: &[Listener],
    unresolved: &[PortKey],
    out: &mut String,
) {
    for e in endpoints {
        kv_app(
            out,
            "位址",
            &format!(
                "{}  {}  ↔  {}（{}{}）",
                e.proto.name(),
                e.a,
                e.b,
                sources_text(&e.sources),
                state_text(e)
            ),
        );
    }
    for l in listeners {
        match l.proto {
            Proto::Tcp if l.bound_only => kv_app(
                out,
                "尚未連線",
                &format!("TCP  {}（只綁定了埠，還沒開始連線，沒有遠端位址）", l.addr),
            ),
            Proto::Tcp => kv_app(
                out,
                "監聽端",
                &format!("TCP  {}（等待連入，沒有另一端）", l.addr),
            ),
            Proto::Udp => kv_app(
                out,
                "收發端",
                &format!("UDP  {}（沒有對特定對象連線，本來就沒有遠端位址）", l.addr),
            ),
        }
    }
    if !unresolved.is_empty() {
        kv_app(
            out,
            "沒有位址的埠",
            &format!(
                "{}；已嘗試：{}。",
                ports_list(c, unresolved, false),
                attempts_text(obs)
            ),
        );
    }
}

fn evidence_for(c: &ConnJudgement, g: &crate::judge::ConnGroup) -> Vec<&'static str> {
    if g.ports.is_empty() {
        return c.evidence.clone();
    }
    let tcp = g.ports.iter().any(|k| k.proto == Proto::Tcp);
    let udp = g.ports.iter().any(|k| k.proto == Proto::Udp);
    let mut v = Vec::new();
    if tcp && c.gap_fired {
        v.push("核心登記的 TCP 數量比連線表多");
    }
    if udp && c.udp_gap_fired {
        v.push("核心登記的 UDP 數量比連線表多");
    }
    if !g.holders.is_empty() {
        v.push("有行程握著不在任何連線表的 socket");
    }
    if tcp {
        v.push("有 TCP 埠號被占用卻沒有列在連線表");
    }
    if udp {
        v.push("有 UDP 埠號被占用卻沒有列在連線表");
    }
    v
}

fn holders_text(holders: &[crate::judge::Holder]) -> String {
    if holders.is_empty() {
        return "無法取得".to_string();
    }
    let mut groups: Vec<(String, Vec<u32>)> = Vec::new();
    for h in holders {
        let name = if h.comm.is_empty() {
            "無法取得".to_string()
        } else {
            h.comm.clone()
        };
        match groups.iter_mut().find(|(n, _)| *n == name) {
            Some((_, pids)) => pids.push(h.pid),
            None => groups.push((name, vec![h.pid])),
        }
    }
    groups
        .iter()
        .map(|(name, pids)| {
            format!(
                "{}（編號 {}）",
                name,
                pids.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join("、")
            )
        })
        .collect::<Vec<_>>()
        .join("、")
}

fn state_text(e: &crate::judge::Endpoint) -> String {
    let mut parts = Vec::new();
    if let Some(s) = &e.state {
        let meaning = match s.as_str() {
            "SYN_SENT" => "正在嘗試連線，還沒連上",
            "ESTABLISHED" => "已連上",
            "SYN_RECV" => "對方要求連線，還沒完成",
            "FIN_WAIT" | "CLOSE_WAIT" | "LAST_ACK" | "TIME_WAIT" | "CLOSE" => "正在結束或已結束",
            _ => "",
        };
        parts.push(if meaning.is_empty() {
            format!("狀態 {}", s)
        } else {
            format!("狀態 {}：{}", s, meaning)
        });
    }
    if e.unreplied {
        parts.push("對方至今沒有回應".to_string());
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("；{}", parts.join("；"))
    }
}

fn conn_item(
    i: usize,
    obs: &Observation,
    c: &ConnJudgement,
    g: &crate::judge::ConnGroup,
    out: &mut String,
) {
    out.push_str(&format!(
        "[{}] 被藏的連線　持有者：{}\n",
        i,
        holders_text(&g.holders)
    ));
    kv_app(
        out,
        "怎麼知道的",
        &format!("{}。", evidence_for(c, g).join("；")),
    );
    if !g.holders.is_empty() {
        let distinct: std::collections::BTreeSet<u64> = g
            .holders
            .iter()
            .flat_map(|h| h.inodes.iter().copied())
            .collect();
        let n = if distinct.is_empty() {
            g.holders.iter().map(|h| h.sockets).sum()
        } else {
            distinct.len()
        };
        if g.holders.len() == 1 {
            kv_app(out, "握著", &format!("{} 個不在任何連線表的 socket。", n));
        } else {
            kv_app(
                out,
                "握著",
                &format!(
                    "這 {} 個行程握的 socket 有共用（行程複製出子行程時，子行程繼承同一個 socket），算同一條連線；合計 {} 個不在任何連線表的 socket。",
                    g.holders.len(),
                    n
                ),
            );
        }
        if g.holders.iter().any(|h| h.from_visible) {
            kv_app(
                out,
                "持有者說明",
                if g.holders.len() == 1 {
                    "這個行程在 /proc 清單裡看得到（沒有被藏）；被藏的是它握著的連線。\n是暫時查詢「握著不在連線表的 socket 的一般行程」，本機端對上被藏的埠才認出它。"
                } else {
                    "持有者裡有行程在 /proc 清單裡看得到（沒有被藏）；被藏的是它們握著的連線。\n是暫時查詢「握著不在連線表的 socket 的一般行程」，本機端對上被藏的埠才認出來。"
                },
            );
        }
    }
    if !g.ports.is_empty() {
        kv_app(out, "被占用的埠", &ports_text(c, &g.ports));
    }
    let shared_exists = !c.shared_ports.is_empty()
        || !c.shared_endpoints.is_empty()
        || !c.shared_listeners.is_empty();
    if g.ports.is_empty() && shared_exists {
        kv_app(
            out,
            "位址",
            "無法對應到這個持有者，見下方「其他被藏連線位址」。",
        );
    } else if g.endpoints.is_empty() && g.listeners.is_empty() {
        kv_app(out, "位址", "遠端位址無法取得。");
    }
    address_lines(obs, c, &g.endpoints, &g.listeners, &g.unresolved_ports, out);
    out.push('\n');
}

fn shared_block(obs: &Observation, c: &ConnJudgement, out: &mut String) {
    if c.shared_ports.is_empty() && c.shared_endpoints.is_empty() && c.shared_listeners.is_empty() {
        return;
    }
    out.push_str("其他被藏連線位址（有多個持有者，這些位址無法逐一對應到持有者）\n");
    if !c.shared_ports.is_empty() {
        kv_app(out, "被占用的埠", &ports_text(c, &c.shared_ports));
    }
    let unresolved: Vec<PortKey> = c
        .unresolved_ports
        .iter()
        .filter(|p| c.shared_ports.contains(p))
        .copied()
        .collect();
    address_lines(
        obs,
        c,
        &c.shared_endpoints,
        &c.shared_listeners,
        &unresolved,
        out,
    );
    out.push('\n');
}

#[derive(Clone, Debug, Default)]
pub struct RunInfo {
    pub rec_sha256: Option<String>,
    pub rec_text: Option<String>,
}

fn disp_width(s: &str) -> usize {
    s.chars()
        .map(|c| match c {
            '…' | '─' | '·' => 1,
            c if (c as u32) < 0x80 => 1,
            _ => 2,
        })
        .sum()
}

fn pad(s: &str, width: usize) -> String {
    let w = disp_width(s);
    let mut out = s.to_string();
    out.push_str(&" ".repeat(width.saturating_sub(w)));
    out
}

const APP_W: usize = 100;
const COL1_W: usize = 20;
const COL2_W: usize = 8;
const KV_LABEL_W: usize = 14;

fn has_full_hash(l: &str) -> bool {
    l.split(|c: char| !c.is_ascii_hexdigit())
        .any(|w| w.len() >= 64)
}

fn app_lines(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.split('\n') {
        if has_full_hash(l) {
            out.push(l.to_string());
        } else {
            out.extend(plain::wrap(l, width));
        }
    }
    out
}

fn kv_app(out: &mut String, label: &str, text: &str) {
    kv_app_w(out, label, text, KV_LABEL_W);
}

fn kv_app_w(out: &mut String, label: &str, text: &str, label_w: usize) {
    let w = APP_W.saturating_sub(4 + label_w);
    for (n, l) in app_lines(text, w).iter().enumerate() {
        if n == 0 {
            out.push_str(&format!("    {}{}\n", plain::pad_cjk(label, label_w), l));
        } else {
            out.push_str(&format!("    {}{}\n", plain::blank_cjk(label_w), l));
        }
    }
}

fn split_label(label: &str) -> (&str, Option<&'static str>) {
    match label {
        "/proc 目錄清單" => ("程式目錄清單", Some("/proc 目錄清單")),
        "cgroup 工作清單" => ("群組工作清單", Some("cgroup 工作清單")),
        "問核心 kill(編號,0)" => ("問核心", Some("kill(編號,0)")),
        "問檔案資訊（fstat）" => ("問檔案資訊", Some("fstat")),
        "問檔案資訊（lstat）" => ("問檔案資訊", Some("lstat")),
        "打開 /proc/編號/exe" => ("打開程式檔", Some("/proc/編號/exe")),
        "排程表 sched_debug" => ("排程表", Some("sched_debug")),
        "計時器表 timer_list" => ("計時器表", Some("timer_list")),
        "環境變數 SSH_CONNECTION" => ("環境變數", Some("SSH_CONNECTION")),
        _ => (label, None),
    }
}

fn card(rows: &[(String, String, String)]) -> String {
    let mut out = format!(
        "    {}{}原始值\n",
        plain::pad_cjk("觀察角度", COL1_W),
        plain::pad_cjk("結果", COL2_W)
    );
    for (a, b, c) in rows {
        let (label, tech) = split_label(a);
        let result = if b.is_empty() || b == "-" {
            "－"
        } else {
            b.as_str()
        };
        let mut raw = match (tech, c.as_str()) {
            (Some(t), "-") | (Some(t), "") => t.to_string(),
            (Some(t), c) => format!("{}：{}", t, c),
            (None, c) => c.to_string(),
        };
        let label = if label == "SHA-256" {
            raw = format!("SHA-256 {}", raw);
            "內容指紋"
        } else {
            label
        };
        for (n, l) in app_lines(&raw, APP_W - 4 - COL1_W - COL2_W)
            .iter()
            .enumerate()
        {
            if n == 0 {
                out.push_str(&format!(
                    "    {}{}{}\n",
                    plain::pad_cjk(label, COL1_W),
                    plain::pad_cjk(result, COL2_W),
                    l
                ));
            } else {
                out.push_str(&format!("    {}{}\n", plain::blank_cjk(COL1_W + COL2_W), l));
            }
        }
    }
    out
}

fn row(a: &str, b: &str, c: &str) -> (String, String, String) {
    (a.to_string(), b.to_string(), c.to_string())
}

fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn born_abs(h: &HiddenProc, meta: &crate::model::Meta) -> String {
    if h.info.starttime == 0 || meta.btime == 0 {
        return born(h, meta.clk_tck);
    }
    let clk = meta.clk_tck.max(1);
    let secs = (h.info.starttime * 2 + clk) / (2 * clk);
    format!(
        "{} UTC+8（{}）",
        fmt_tw_sec(meta.btime + secs),
        born(h, meta.clk_tck)
    )
}

fn identity_text(e: &ProcEvidence) -> Option<String> {
    let id = |v: Option<(u32, u32)>, name: &str| {
        v.map(|(r, ef)| {
            if r == ef {
                format!("{} {}", name, r)
            } else {
                format!("{} {}（有效 {}）", name, r, ef)
            }
        })
    };
    let mut parts: Vec<String> = Vec::new();
    parts.extend(id(e.uid, "帳號編號"));
    parts.extend(id(e.gid, "群組編號"));
    if let Some(t) = e.tracer_pid {
        parts.push(if t == 0 {
            "沒有被追蹤".to_string()
        } else {
            format!("被行程 {} 追蹤", t)
        });
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("；"))
    }
}

fn raw_fact<'a>(obs: &'a Observation, path: &str) -> Option<&'a RawFileFact> {
    obs.origin.raw_files.iter().find(|r| r.path == path)
}

fn raw_file_text(f: &RawFile) -> String {
    format!(
        "編號 {}；大小 {} 位元組\n{}",
        f.ino,
        thousands(f.size),
        time_lines(f.crtime, f.mtime, f.ctime)
    )
}

fn time_lines(crtime: Option<i64>, mtime: i64, ctime: i64) -> String {
    let mut groups: Vec<(i64, Vec<&str>)> = Vec::new();
    let mut add = |name: &'static str, t: i64| match groups.iter_mut().find(|(x, _)| *x == t) {
        Some((_, names)) => names.push(name),
        None => groups.push((t, vec![name])),
    };
    if let Some(t) = crtime {
        add("建立", t);
    }
    add("內容修改", mtime);
    add("狀態變更", ctime);
    let mut lines: Vec<String> = Vec::new();
    if crtime.is_none() {
        lines.push("沒有建立時間（舊格式）".to_string());
    }
    for (t, names) in groups {
        lines.push(format!(
            "{}　{} UTC+8",
            names.join("、"),
            fmt_tw_sec(t.max(0) as u64)
        ));
    }
    lines.join("\n")
}

fn unit_rows(unit: &str, f: &OriginFacts, obs: &Observation) -> Vec<Row> {
    let facts: Vec<&RawFileFact> = UNIT_DIRS
        .iter()
        .filter_map(|d| raw_fact(obs, &format!("{}/{}", d, unit)))
        .collect();
    let dirs = UNIT_DIRS.join("、");
    if facts.is_empty() {
        return if f.unit_files.is_empty() {
            vec![row("服務單元檔", "找不到", &format!("{} 都沒有", dirs))]
        } else {
            vec![row("服務單元檔", "有", &f.unit_files.join("、"))]
        };
    }
    let found: Vec<(&RawFileFact, &RawFile)> = facts
        .iter()
        .filter_map(|x| match &x.raw {
            RawLookup::Found(r) => Some((*x, r)),
            _ => None,
        })
        .collect();
    let mut rows = Vec::new();
    if let Some((fact, rf)) = found.first() {
        let verr = fact.vfs_error.as_deref();
        match verr {
            Some(e) => rows.push(row(
                "服務單元檔",
                "不一致",
                &format!("磁碟上有、檔案系統說沒有（{}）：{}", e, fact.path),
            )),
            None => rows.push(row("服務單元檔", "有", &fact.path)),
        }
        rows.push(row("單元檔的磁碟資料", "-", &raw_file_text(rf)));
        if let Some(t) = &rf.link_target {
            rows.push(row("連結目標", "-", t));
        }
        return rows;
    }
    let visible: Vec<&str> = facts
        .iter()
        .filter(|x| x.vfs_error.is_none())
        .map(|x| x.path.as_str())
        .collect();
    let why: Option<&String> = facts.iter().find_map(|x| match &x.raw {
        RawLookup::Unavailable(w) => Some(w),
        _ => None,
    });
    match (visible.is_empty(), why) {
        (false, None) => rows.push(row(
            "服務單元檔",
            "不一致",
            &format!("檔案系統說有、磁碟上沒有：{}", visible.join("、")),
        )),
        (false, Some(w)) => rows.push(row(
            "服務單元檔",
            "有",
            &format!("{}（磁碟對照不可用：{}）", visible.join("、"), w),
        )),
        (true, None) => rows.push(row(
            "服務單元檔",
            "找不到",
            &format!("檔案系統與磁碟上都沒有：{}", dirs),
        )),
        (true, Some(w)) => rows.push(row(
            "服務單元檔",
            "找不到",
            &format!(
                "檔案系統回答 {} 都沒有；磁碟對照不可用（{}），所以不能排除檔案被藏",
                dirs, w
            ),
        )),
    }
    rows
}

fn printable(line: &str) -> String {
    line.chars()
        .map(|c| match c {
            '\t' => ' ',
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

fn unit_content_block(o: &OriginJudgement, obs: &Observation) -> String {
    let OriginKind::Service { unit } = &o.kind else {
        return String::new();
    };
    let mut out = String::new();
    let mut shown: Vec<u64> = Vec::new();
    for d in UNIT_DIRS {
        let path = format!("{}/{}", d, unit);
        let Some(fact) = raw_fact(obs, &path) else {
            continue;
        };
        let (text, truncated, source, ino) = match &fact.raw {
            RawLookup::Found(r) if r.content.is_some() => (
                r.content.clone().unwrap_or_default(),
                r.content_truncated,
                "直接讀磁碟",
                Some(r.ino),
            ),
            _ => match &fact.vfs_content {
                Some(t) => (t.clone(), fact.vfs_content_truncated, "從檔案系統讀", None),
                None => continue,
            },
        };
        if let Some(i) = ino {
            if shown.contains(&i) {
                continue;
            }
            shown.push(i);
        }
        let size = match &fact.raw {
            RawLookup::Found(r) => format!("{} 位元組", thousands(r.size)),
            _ => format!("{} 位元組", text.len()),
        };
        out.push_str(&format!(
            "    服務單元檔內容（{}；{}；{}）\n",
            path, size, source
        ));
        let mut lines = 0usize;
        for l in text.lines().take(60) {
            out.push_str(&format!("        {}\n", printable(l)));
            lines += 1;
        }
        if text.lines().count() > lines || truncated {
            out.push_str("        …（內容較長，只列前面一部分）\n");
        }
        if text.is_empty() {
            out.push_str("        （空檔案）\n");
        }
        if let (RawLookup::Found(r), Some(v)) = (&fact.raw, &fact.vfs_content) {
            if r.content.as_deref().is_some_and(|c| c != v) {
                out.push_str("        注意：檔案系統給的內容和磁碟上的不一樣。\n");
            }
        }
    }
    out
}

type Row = (String, String, String);

fn origin_rows(o: &OriginJudgement, obs: &Observation) -> Vec<Row> {
    let f = &o.facts;
    let cgroup = f.cgroup.as_deref().unwrap_or("讀不到");
    let mut rows: Vec<Row> = Vec::new();
    match &o.kind {
        OriginKind::Unreadable => {
            rows.push(row(
                "啟動來源",
                "讀不到",
                "行程在讀取當下已經結束，或沒有權限",
            ));
        }
        OriginKind::Neither => {
            rows.push(row("啟動來源", "不明", "沒有登入身分，也不屬於任何服務"));
            rows.push(row("登入身分", "無", "loginuid 是「未設定」"));
            rows.push(row("所屬單元", "-", cgroup));
        }
        OriginKind::Service { unit } => {
            rows.push(row(
                "啟動來源",
                "服務",
                &format!("{}（由服務管理員 systemd 啟動）", unit),
            ));
            rows.push(row("登入身分", "無", "loginuid、sessionid 都是「未設定」"));
            if f.unit_checked {
                rows.extend(unit_rows(unit, f, obs));
            }
        }
        OriginKind::Login { uid, ses } => {
            let ses_text = ses.map_or("未設定".to_string(), |n| n.to_string());
            rows.push(row(
                "啟動來源",
                "登入",
                &format!("帳號編號 {}、登入編號 {}", uid, ses_text),
            ));
            rows.push(row("所屬單元", "-", cgroup));
            if let (Some(scope), Some(n)) = (f.scope_session(), ses) {
                if scope != *n {
                    rows.push(row(
                        "登入編號比對",
                        "不一致",
                        &format!(
                            "所屬單元是 session-{}.scope，但系統記的登入編號是 {}",
                            scope, n
                        ),
                    ));
                }
            }
            if let Some(sf) = &f.session_file {
                let mut parts = Vec::new();
                if let Some(t) = sf.realtime_us {
                    parts.push(format!("登入時間 {} UTC+8", fmt_tw_sec(t / 1_000_000)));
                }
                if let Some(v) = &sf.service {
                    parts.push(format!("登入服務 {}", v));
                }
                if let Some(v) = &sf.user {
                    parts.push(format!("帳號 {}", v));
                }
                if let Some(v) = &sf.remote_host {
                    parts.push(format!("遠端 {}", v));
                }
                if let Some(v) = &sf.tty {
                    parts.push(format!("終端機 {}", v));
                }
                if let Some(v) = &sf.state {
                    parts.push(format!("狀態 {}", v));
                }
                rows.push(row("登入管理員紀錄", "有", &parts.join("；")));
            }
            if let Some(a) = &o.audit {
                rows.push(row(
                    "稽核登入事件",
                    "有",
                    &format!(
                        "{} UTC+8；執行檔 {}；來源位址 {}；主機名稱 {}；終端機 {}",
                        fmt_tw_sec(a.epoch),
                        a.exe,
                        a.addr,
                        a.hostname,
                        a.terminal
                    ),
                ));
            }
            if let Some(c) = &f.ssh_connection {
                let p: Vec<&str> = c.split_whitespace().collect();
                let text = if p.len() == 4 {
                    format!("從 {} 埠 {} 連到本機 {} 埠 {}", p[0], p[1], p[2], p[3])
                } else {
                    c.clone()
                };
                rows.push(row("環境變數 SSH_CONNECTION", "有", &text));
            }
            if f.session_file.is_none() && o.audit.is_none() && f.ssh_connection.is_none() {
                let cov = &obs.origin;
                let audit_text = if !cov.audit_ran || cov.audit_files == 0 {
                    "沒有讀到稽核紀錄".to_string()
                } else if let Some(min) = cov.audit_min_epoch {
                    format!(
                        "稽核紀錄讀了 {} 個檔，最早的事件是 {} UTC+8，裡面沒有這個登入編號的成功登入事件",
                        cov.audit_files,
                        fmt_tw_sec(min)
                    )
                } else {
                    format!(
                        "稽核紀錄讀了 {} 個檔，沒有這個登入編號的成功登入事件",
                        cov.audit_files
                    )
                };
                rows.push(row(
                    "對應的登入紀錄",
                    "找不到",
                    &format!("登入管理員沒有這個工作階段檔；{}", audit_text),
                ));
            }
        }
    }
    rows
}

fn exe_disk_rows(exe: &str, obs: &Observation, ev: Option<&ProcEvidence>) -> Vec<Row> {
    let path = exe.strip_suffix(" (deleted)").unwrap_or(exe);
    let Some(fact) = raw_fact(obs, path) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    match &fact.raw {
        RawLookup::Found(rf) => {
            match &fact.vfs_error {
                Some(e) => rows.push(row(
                    "執行檔（磁碟）",
                    "不一致",
                    &format!("磁碟上有、檔案系統說沒有（{}）", e),
                )),
                None => rows.push(row("執行檔（磁碟）", "有", "檔案系統與磁碟都有")),
            }
            let mut text = raw_file_text(rf);
            if let (Some(disk), Some(run)) = (&rf.sha256, ev.and_then(|e| e.exe_sha256.as_ref())) {
                text.push_str(if disk == run {
                    "\n內容指紋與上面執行中的 SHA-256 相同"
                } else {
                    "\n內容指紋與上面執行中的 SHA-256 不同（磁碟上的檔案在行程啟動後被換過）"
                });
            }
            rows.push(row("執行檔的磁碟資料", "-", &text));
        }
        RawLookup::NotFound => rows.push(row(
            "執行檔（磁碟）",
            if fact.vfs_error.is_none() {
                "不一致"
            } else {
                "找不到"
            },
            if fact.vfs_error.is_none() {
                "檔案系統說有、磁碟上沒有"
            } else {
                "檔案系統與磁碟上都沒有（執行中的檔案可能已被刪除）"
            },
        )),
        RawLookup::Unavailable(why) => rows.push(row(
            "執行檔（磁碟）",
            "-",
            &format!("磁碟對照不可用：{}", why),
        )),
    }
    rows
}

fn proc_key(h: &HiddenProc, ev: Option<&ProcEvidence>, o: Option<&OriginJudgement>) -> String {
    let mut e = ev.cloned();
    if let Some(x) = e.as_mut() {
        x.pid = 0;
    }
    let mut oo = o.cloned();
    if let Some(x) = oo.as_mut() {
        x.pid = 0;
        x.facts.pid = 0;
    }
    format!("{:?}|{:?}|{:?}|{:?}", h.info.exe, h.info.cmdline, e, oo)
}

fn exe_evidence_rows(e: &ProcEvidence) -> Vec<Row> {
    let mut rows: Vec<Row> = Vec::new();
    match (&e.exe_open_error, e.exe_bytes) {
        (Some(err), _) => rows.push(row("打開 /proc/編號/exe", "失敗", err)),
        (None, Some(n)) => rows.push(row(
            "打開 /proc/編號/exe",
            "成功",
            &format!("讀到 {} 位元組", thousands(n)),
        )),
        (None, None) => rows.push(row(
            "打開 /proc/編號/exe",
            "成功",
            e.exe_read_error.as_deref().unwrap_or("沒有讀到內容"),
        )),
    }
    if let Some(hex) = &e.exe_sha256 {
        rows.push(row("SHA-256", "", hex));
    }
    let opened = e.exe_open_error.is_none();
    match &e.exe_info {
        Some(FileInfo::Ok {
            size,
            mtime,
            ctime,
            nlink,
        }) => rows.push(row(
            "問檔案資訊（fstat）",
            "成功",
            &format!(
                "大小 {}；內容修改 {} UTC+8；狀態變更 {} UTC+8；連結數 {}",
                thousands(*size),
                fmt_tw_sec((*mtime).max(0) as u64),
                fmt_tw_sec((*ctime).max(0) as u64),
                nlink
            ),
        )),
        Some(FileInfo::Err(err)) => rows.push(row(
            "問檔案資訊（fstat）",
            "失敗",
            &if opened && e.exe_bytes.is_some() {
                format!("{}（上面打開並讀取卻成功）", err)
            } else {
                err.clone()
            },
        )),
        None => {}
    }
    if let Some(t) = identity_text(e) {
        rows.push(row("行程身分", "-", &t));
    }
    rows
}

fn size_diff_text(vfs: u64, raw: u64) -> String {
    match vfs.cmp(&raw) {
        std::cmp::Ordering::Equal => "兩邊大小相同，內容不同".to_string(),
        std::cmp::Ordering::Less => {
            format!("一般方式讀到的比磁碟上少 {} 位元組", thousands(raw - vfs))
        }
        std::cmp::Ordering::Greater => {
            format!("一般方式讀到的比磁碟上多 {} 位元組", thousands(vfs - raw))
        }
    }
}

fn content_items(idx: &mut usize, ct: &ContentJudgement, s: &mut String) {
    for m in &ct.items {
        s.push_str(&format!("[{}] 內容被動過的檔案　路徑：{}\n", *idx, m.path));
        let diff = match m.first_diff {
            Some(at) => format!(
                "{}；第一個不同的位置在第 {} 個位元組",
                size_diff_text(m.vfs_size, m.raw_size),
                thousands(at)
            ),
            None => format!(
                "{}（檔案較大，沒有找出第一個不同的位置）",
                size_diff_text(m.vfs_size, m.raw_size)
            ),
        };
        let rows = vec![
            row(
                "一般方式讀到的內容",
                "-",
                &format!("大小 {} 位元組；SHA-256 {}", thousands(m.vfs_size), m.vfs_sha256),
            ),
            row(
                "直接讀磁碟的內容",
                "-",
                &format!("大小 {} 位元組；SHA-256 {}", thousands(m.raw_size), m.raw_sha256),
            ),
            row("差異", "不一致", &diff),
            row(
                "重驗",
                "-",
                &format!("重驗 {} 輪，兩邊的指紋都沒變", crate::collect_content::RECHECK_ROUNDS),
            ),
            row(
                "說明",
                "-",
                "同一個檔案，一般方式讀和直接讀磁碟看到的內容不同：有東西在讀取的路徑上動了手腳（報告不顯示檔案內容）",
            ),
        ];
        s.push_str(&card(&rows));
        s.push('\n');
        *idx += 1;
    }
}

fn cover_items(idx: &mut usize, f: &FileJudgement, s: &mut String) {
    for c in &f.proc_covers {
        s.push_str(&format!(
            "[{}] 被蓋住的行程　位置：{}\n",
            *idx, c.mount_point
        ));
        let rows = vec![
            row(
                "系統的掛載清單",
                "有",
                &format!(
                    "{} 上掛了一個 {}（來源 {}）",
                    c.mount_point, c.fstype, c.source
                ),
            ),
            row(
                "問核心 kill(編號,0)",
                if c.alive { "存在" } else { "不存在" },
                &format!("編號 {}", c.pid),
            ),
            row(
                "說明",
                "-",
                "正常的系統不會在 /proc/行程編號 上掛東西；掛上去之後，ps 之類讀 /proc 的工具就讀不到這個行程",
            ),
        ];
        s.push_str(&card(&rows));
        s.push('\n');
        *idx += 1;
    }
}

fn exe_items(idx: &mut usize, x: &ExeJudgement, obs: &Observation, s: &mut String) {
    for c in &x.items {
        let name = if c.comm.is_empty() {
            "無法取得"
        } else {
            &c.comm
        };
        s.push_str(&format!(
            "[{}] 程式檔被藏的行程　名字：{}（編號 {}）\n",
            *idx, name, c.pid
        ));
        let mut rows = exe_evidence_rows(&c.evidence);
        let h = HiddenProc {
            info: crate::model::Unlisted {
                pid: c.pid,
                starttime: c.starttime,
                ppid: c.ppid,
                comm: c.comm.clone(),
                ..Default::default()
            },
            via_kill: false,
            via_cgroup: false,
            via_sched: false,
            via_timer: false,
            is_kernel_thread: false,
        };
        let mut birth = born_abs(&h, &obs.meta);
        if let Some(pp) = c.ppid {
            birth.push_str(&format!("；父行程 {}", pp));
        }
        rows.push(row("啟動時間", "-", &birth));
        rows.push(row("執行檔路徑", "-", &c.exe));
        if !c.cmdline.is_empty() && c.cmdline != c.exe {
            rows.push(row("啟動指令", "-", &c.cmdline));
        }
        rows.push(row(
            "說明",
            "-",
            "這個行程在 /proc 看得到，但它的程式檔問不到檔案資訊：有東西在攔截問檔案資訊這條路，程式檔的名字被藏了",
        ));
        s.push_str(&card(&rows));
        s.push('\n');
        *idx += 1;
    }
}

fn process_card(
    h: &HiddenProc,
    obs: &Observation,
    ev: Option<&ProcEvidence>,
    origin: Option<&OriginJudgement>,
    same_as: Option<usize>,
) -> String {
    let meta = &obs.meta;
    let mut rows = vec![row(
        "問核心 kill(編號,0)",
        if h.via_kill { "存在" } else { "沒回答" },
        if h.via_kill {
            "-"
        } else {
            "逐號詢問可能被攔截"
        },
    )];
    rows.push(row(
        "cgroup 工作清單",
        if h.via_cgroup { "有" } else { "沒有" },
        "-",
    ));
    if obs.proc_samples.last().is_some_and(|s| s.sched_trusted) {
        rows.push(row(
            "排程表 sched_debug",
            if h.via_sched { "有" } else { "沒有" },
            if h.via_sched {
                "-"
            } else {
                "這個來源只列正在跑或排隊的工作，沒有不代表不存在"
            },
        ));
        if h.via_timer {
            rows.push(row("計時器表 timer_list", "有", "-"));
        }
    }
    rows.push(row("/proc 目錄清單", "沒有", "-"));
    if same_as.is_none() {
        if let Some(e) = ev {
            rows.extend(exe_evidence_rows(e));
        }
    }
    let mut birth = born_abs(h, meta);
    if let Some(pp) = h.info.ppid {
        birth.push_str(&format!("；父行程 {}", pp));
    }
    rows.push(row("啟動時間", "-", &birth));
    if h.is_kernel_thread {
        rows.push(row("特徵", "-", "由核心的 2 號行程啟動、沒有執行檔"));
    } else if let Some(n) = same_as {
        rows.push(row(
            "其餘",
            "-",
            &format!(
                "與 [{}] 完全相同：執行檔（含 SHA-256）、行程身分、啟動來源",
                n
            ),
        ));
    } else {
        if let Some(exe) = &h.info.exe {
            rows.push(row("執行檔路徑", "-", exe));
            rows.extend(exe_disk_rows(exe, obs, ev));
        }
        if !h.info.cmdline.is_empty() && h.info.exe.as_deref() != Some(h.info.cmdline.as_str()) {
            rows.push(row("啟動指令", "-", &h.info.cmdline));
        }
        if let Some(o) = origin {
            rows.extend(origin_rows(o, obs));
        }
    }
    let mut out = card(&rows);
    if same_as.is_none() {
        if let Some(o) = origin {
            let block = unit_content_block(o, obs);
            if !block.is_empty() {
                out.push('\n');
                out.push_str(&block);
            }
        }
    }
    out
}

fn attempts_note(attempts: u32) -> String {
    if attempts > 1 {
        format!(
            "；只湊到一類證據，共收集 {} 輪（輪與輪之間隔約 {} 秒）",
            attempts,
            crate::CONN_EXTRA_GAP_MS / 1000
        )
    } else {
        String::new()
    }
}

fn patrol_line(k: &crate::model::ConnFacts) -> Option<String> {
    if !k.patrol_ran {
        return None;
    }
    Some(format!(
        "巡邏上限 {} 秒、實際 {} 毫秒；取樣 {} 份；看到跡象後完整收集 {} 輪；結果：{}",
        k.patrol_limit_secs,
        k.patrol_ms,
        k.patrol_samples,
        k.patrol_rounds,
        if k.patrol_caught {
            "湊齊兩類證據，採用那一輪的資料"
        } else {
            "沒有湊齊兩類證據"
        }
    ))
}

fn realign_scope(text: &str) -> String {
    const LABEL_W: usize = 12;
    let mut out = String::new();
    let mut cur: Option<(String, String)> = None;
    fn flush(cur: &mut Option<(String, String)>, out: &mut String) {
        if let Some((l, t)) = cur.take() {
            kv_app_w(out, &l, &t, LABEL_W);
        }
    }
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("        ") {
            if let Some((_, t)) = cur.as_mut() {
                t.push('\n');
                t.push_str(rest);
                continue;
            }
        }
        if let Some(rest) = line.strip_prefix("    ") {
            if !rest.starts_with(' ') {
                if let Some((label, body)) = rest.split_once("  ") {
                    flush(&mut cur, &mut out);
                    cur = Some((label.to_string(), body.to_string()));
                    continue;
                }
            }
        }
        flush(&mut cur, &mut out);
        out.push_str(line);
        out.push('\n');
    }
    flush(&mut cur, &mut out);
    out
}

fn coverage_block(obs: &Observation, p: &ProcJudgement, m: &ModJudgement) -> String {
    let mut out = String::from("掃描範圍（這次問了什麼）\n");
    if let Some(l) = obs.proc_samples.last() {
        out.push_str(&format!(
            "    行程  逐號問核心 1 至 {} 號：存在 {}；cgroup 清單 {}；/proc 清單 {}；取樣 {} 份\n",
            obs.meta.pid_max, l.n_alive, l.n_cgroup, l.n_listed, p.samples
        ));
        if l.sched_trusted {
            out.push_str(&format!(
                "        另外讀排程表 sched_debug 看到 {} 個、計時器表 timer_list 看到 {} 個\n",
                l.n_sched, l.n_timer
            ));
        } else if l.sched_read {
            out.push_str(
                "        排程表 sched_debug 讀到了，但表裡找不到掃描器自己的編號（編號的算法與這裡不一致，例如在容器裡執行），沒有採用\n",
            );
        }
    }
    if !obs.mod_samples.is_empty() {
        let last = obs.mod_samples.last();
        out.push_str(&format!(
            "    模組  目錄取樣 {} 份（穩定 {}）{}\n",
            m.total,
            m.stable,
            last.map_or(String::new(), |l| format!(
                "；連結數 {}、列出 {}",
                l.nl_mid, l.n_sub
            ))
        ));
    }
    if !obs.conn_samples.is_empty() {
        out.push_str(&format!(
            "    連線  數量取樣 {} 份；逐埠綁定得 {} 個被占用的埠；連線表 {} 個本機埠{}\n",
            obs.conn_samples.len(),
            obs.conn.inuse_ports_pass2.len(),
            obs.conn.listed_ports_after.len(),
            attempts_note(obs.conn.attempts)
        ));
        if let Some(l) = patrol_line(&obs.conn) {
            out.push_str(&format!("        {}\n", l));
        }
    }
    if !obs.logs.is_empty() {
        let parts: Vec<String> = obs
            .logs
            .iter()
            .map(|c| {
                let label = source_label(&c.source);
                if !c.readable {
                    format!("{} 讀不到", label)
                } else if c.files > 0 && c.source == "journal" {
                    format!("{} {} 個檔、約 {} KB", label, c.files, c.records)
                } else if c.files > 0 {
                    format!("{} {} 個檔、{} 筆", label, c.files, c.records)
                } else {
                    format!("{} {} 筆", label, c.records)
                }
            })
            .collect();
        out.push_str(&format!("    紀錄  {}\n", parts.join("；")));
    }
    if let Some(l) = disk_coverage_line(obs) {
        out.push_str(&l);
    }
    if obs.content_scan.ran {
        let c = &obs.content_scan;
        let shown: Vec<&str> = c.roots.iter().take(6).map(|r| r.as_str()).collect();
        let more = if c.roots.len() > shown.len() {
            format!("等 {} 個資料夾", c.roots.len())
        } else {
            String::new()
        };
        out.push_str(&format!(
            "    檔案內容  比對 {} 個檔案（{}{}與執行中行程的程式檔）；略過：剛修改過 {}、太大 {}、一般方式讀不到 {}；候選 {} 個、重驗 {} 輪後消失 {} 個\n",
            c.checked,
            shown.join("、"),
            if more.is_empty() { "、".to_string() } else { format!("{}、", more) },
            c.skipped_recent,
            c.skipped_big,
            c.skipped_unreadable,
            c.candidates,
            crate::collect_content::RECHECK_ROUNDS,
            c.vanished
        ));
    }
    if obs.exe_scan.ran {
        out.push_str(&format!(
            "    程式檔  檢查 {} 個看得到的行程：能打開卻問不到檔案資訊的候選 {} 個、重驗 {} 輪後消失 {} 個\n",
            obs.exe_scan.checked,
            obs.exe_scan.candidates,
            crate::collect_exe::RECHECK_ROUNDS,
            obs.exe_scan.vanished
        ));
    }
    out
}

fn kind_word(k: char) -> &'static str {
    match k {
        'f' => "一般檔",
        'd' => "資料夾",
        'l' => "符號連結",
        _ => "其他",
    }
}

fn pid_list(pids: &[u32]) -> String {
    let v: Vec<String> = pids.iter().map(|p| p.to_string()).collect();
    format!("編號 {}", v.join("、"))
}

fn file_relation(
    path: &str,
    p: &ProcJudgement,
    origins: &[OriginJudgement],
    x: &ExeJudgement,
) -> Option<String> {
    let exe_pids: Vec<u32> = p
        .confirmed
        .iter()
        .filter(|h| !h.is_kernel_thread)
        .filter(|h| {
            let exe = h
                .info
                .exe
                .as_deref()
                .map(|e| e.strip_suffix(" (deleted)").unwrap_or(e));
            exe == Some(path)
        })
        .map(|h| h.info.pid)
        .collect();
    let visible_exe_pids: Vec<u32> = x
        .items
        .iter()
        .filter(|c| c.exe.strip_suffix(" (deleted)").unwrap_or(&c.exe) == path)
        .map(|c| c.pid)
        .collect();
    let unit_pids: Vec<u32> = origins
        .iter()
        .filter(|o| match &o.kind {
            OriginKind::Service { unit } => {
                UNIT_DIRS.iter().any(|d| format!("{}/{}", d, unit) == path)
            }
            _ => false,
        })
        .map(|o| o.pid)
        .collect();
    let mut rel = Vec::new();
    if !exe_pids.is_empty() {
        rel.push(format!("被藏行程（{}）的執行檔", pid_list(&exe_pids)));
    }
    if !visible_exe_pids.is_empty() {
        rel.push(format!(
            "程式檔被藏的行程（{}）的執行檔",
            pid_list(&visible_exe_pids)
        ));
    }
    if !unit_pids.is_empty() {
        rel.push(format!(
            "被藏行程（{}）所屬服務的單元檔",
            pid_list(&unit_pids)
        ));
    }
    if rel.is_empty() {
        None
    } else {
        Some(rel.join("；"))
    }
}

fn hidden_file_summary(h: &HiddenFile) -> String {
    format!(
        "{}；編號 {}；大小 {} 位元組；連結數 {}\n{}",
        kind_word(h.raw.kind),
        h.raw.ino,
        thousands(h.raw.size),
        h.raw.links,
        time_lines(h.raw.crtime, h.raw.mtime, h.raw.ctime)
    )
}

const FILE_CARDS_MAX: usize = 30;

fn file_items(
    idx: &mut usize,
    f: &FileJudgement,
    p: &ProcJudgement,
    origins: &[OriginJudgement],
    x: &ExeJudgement,
    s: &mut String,
) {
    let files = sorted_files(f, p, origins, x);
    for (n, h) in files.iter().enumerate() {
        if n >= FILE_CARDS_MAX {
            if n == FILE_CARDS_MAX {
                s.push_str(&format!(
                    "    以下 {} 個被藏的檔案只列一行（證據的格式與上面相同）：\n",
                    f.confirmed.len() - FILE_CARDS_MAX
                ));
            }
            s.push_str(&format!(
                "    • {}　{}\n",
                h.path,
                hidden_file_summary(h).replace('\n', "；")
            ));
            continue;
        }
        s.push_str(&format!("[{}] 被藏的檔案　路徑：{}\n", *idx, h.path));
        let mut rows = vec![
            row(
                "磁碟上的資料夾清單",
                "有",
                &format!("直接讀磁碟，{} 的內容裡有這個名字", h.dir),
            ),
            row(
                "檔案系統的列目錄",
                "沒有",
                &format!("列出 {} 時沒有這個名字（重驗幾輪都一樣）", h.dir),
            ),
        ];
        match &h.lstat_error {
            Some(e) => rows.push(row("問檔案資訊（lstat）", "失敗", e)),
            None => rows.push(row(
                "問檔案資訊（lstat）",
                "成功",
                "查得到這個路徑，只是列目錄時沒列出來",
            )),
        }
        rows.push(row("磁碟上的資料", "-", &hidden_file_summary(h)));
        if let Some(sha) = &h.raw.sha256 {
            rows.push(row("內容指紋", "-", &format!("SHA-256 {}", sha)));
        }
        if let Some(t) = &h.raw.link_target {
            rows.push(row("連結目標", "-", t));
        }
        if h.raw.kind == 'd' {
            let shown = if h.children.is_empty() {
                "（空資料夾，或讀不出內容）".to_string()
            } else {
                h.children.join("、")
            };
            let more = if h.children_total > h.children.len() {
                format!("…（共 {} 個）", h.children_total)
            } else {
                String::new()
            };
            rows.push(row("裡面的名字", "-", &format!("{}{}", shown, more)));
        }
        if let Some(r) = file_relation(&h.path, p, origins, x) {
            rows.push(row("關聯", "-", &r));
        }
        s.push_str(&card(&rows));
        s.push('\n');
        *idx += 1;
    }
    if f.total > f.confirmed.len() {
        s.push_str(&format!(
            "    另有 {} 個被藏的檔案沒有列出（報告最多列 {} 個）。\n",
            f.total - f.confirmed.len(),
            crate::model::HIDDEN_FILES_MAX
        ));
    }
}

fn disk_notes(obs: &Observation, f: &FileJudgement) -> Vec<String> {
    let mut v = Vec::new();
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for u in &obs.content_scan.unavailable {
        let (path, why) = u.split_once('：').unwrap_or((u.as_str(), ""));
        match groups.iter_mut().find(|(w, _)| w == why) {
            Some((_, paths)) => paths.push(path.to_string()),
            None => groups.push((why.to_string(), vec![path.to_string()])),
        }
    }
    for (why, paths) in groups {
        if why.is_empty() {
            v.push(format!("檔案內容比對沒有做：{}", paths.join("、")));
        } else if paths.len() > 1 {
            v.push(format!(
                "檔案內容比對沒有做：{}：{}",
                paths.join("、"),
                why.replacen("這個路徑", "這幾個路徑", 1)
            ));
        } else {
            v.push(format!("檔案內容比對沒有做：{}：{}", paths[0], why));
        }
    }
    if !obs.disk.ran {
        return v;
    }
    for (mp, fstype, why) in &f.unavailable {
        v.push(format!(
            "磁碟對照沒有做：{}（{}）。{}",
            if mp.is_empty() { "?" } else { mp },
            if fstype.is_empty() { "?" } else { fstype },
            why
        ));
    }
    for d in &obs.disk.devices {
        if let DiskStatus::Walked(w) = &d.status {
            if w.truncated {
                v.push(format!(
                    "磁碟對照在時間上限（{} 秒）內沒有走完 {}，沒走到的資料夾沒有對照。",
                    crate::collect_disk::WALK_MAX_SECS,
                    d.mount_point
                ));
            }
            if w.dir_errors > 0 {
                v.push(format!(
                    "{} 有 {} 個資料夾因為磁碟或檔案系統讀不了，沒有對照。{}",
                    d.mount_point,
                    w.dir_errors,
                    if d.fstype == "xfs" {
                        "XFS 的資料夾剛被修改時，磁碟上的內容可能還沒寫完整，讀到不合理的資料也算在這裡。"
                    } else {
                        ""
                    }
                ));
            }
            if w.unsettled > 0 {
                let dirs = if obs.disk.unsettled_dirs.is_empty() {
                    String::new()
                } else {
                    format!("（例如 {}）", obs.disk.unsettled_dirs.join("、"))
                };
                v.push(format!(
                    "{} 有 {} 個名字「磁碟上有、列目錄卻沒有」，但它們所在的資料夾最近 {} 秒內被修改過{}。XFS 把資料夾的變動寫回磁碟會慢，這時磁碟上讀到的是舊名單，不能當成檔案被藏，所以這次不判斷；等資料夾安靜下來再掃一次就能判斷。",
                    d.mount_point,
                    w.unsettled,
                    obs.disk.cold_secs,
                    dirs
                ));
            }
        }
    }
    v
}

fn disk_appendix(obs: &Observation) -> String {
    if !obs.disk.ran {
        return String::new();
    }
    let mut s = format!(
        "磁碟對照：候選 {} 個，重驗 {} 輪後消失 {} 個，穩定的 {} 個\n",
        obs.disk.candidates, obs.disk.rounds, obs.disk.vanished, obs.disk.hidden_total
    );
    s.push_str(&format!(
        "蓋住型：掛在 /proc/<行程編號> 上的 {} 個；底下有東西的掛載點 {} 個\n",
        obs.disk.proc_covers.len(),
        obs.disk.dir_covers.len()
    ));
    for d in &obs.disk.devices {
        match &d.status {
            DiskStatus::Walked(w) => s.push_str(&format!(
                "  {}（{}，{}）：走訪 {} 個資料夾、{} 個名字；檔案系統有、磁碟沒有的名字 {} 個；跳過掛著別的裝置的資料夾 {} 個；讀不了的資料夾 {} 個{}\n",
                d.mount_point,
                d.source,
                d.fstype,
                thousands(w.dirs),
                thousands(w.entries),
                w.fs_only,
                w.skipped_mounts,
                w.dir_errors,
                if w.truncated { "；時間到了沒走完" } else { "" }
            )),
            DiskStatus::Unavailable(why) => s.push_str(&format!(
                "  {}（{}，{}）：不能對照：{}\n",
                d.mount_point, d.source, d.fstype, why
            )),
        }
    }
    s
}

fn disk_coverage_line(obs: &Observation) -> Option<String> {
    if !obs.disk.ran {
        return None;
    }
    let mut dirs = 0u64;
    let mut entries = 0u64;
    let mut walked: Vec<(String, String)> = Vec::new();
    let mut skipped = Vec::new();
    let mut unsettled = 0u64;
    for d in &obs.disk.devices {
        match &d.status {
            DiskStatus::Walked(w) => {
                dirs += w.dirs;
                entries += w.entries;
                unsettled += w.unsettled;
                walked.push((d.mount_point.clone(), d.fstype.clone()));
            }
            DiskStatus::Unavailable(_) => skipped.push(format!(
                "{}（{}）",
                if d.mount_point.is_empty() {
                    "?"
                } else {
                    &d.mount_point
                },
                if d.fstype.is_empty() { "?" } else { &d.fstype }
            )),
        }
    }
    let mut line = if walked.is_empty() {
        "    磁碟  沒有能對照的裝置（只支援 ext4 和 XFS）".to_string()
    } else {
        format!(
            "    磁碟  對照 {} 個 {} 裝置（{}）：走訪 {} 個資料夾、{} 個名字；候選 {} 個、重驗 {} 輪後消失 {} 個",
            walked.len(),
            plain::fs_kinds(&walked),
            walked
                .iter()
                .map(|(m, _)| m.as_str())
                .collect::<Vec<_>>()
                .join("、"),
            thousands(dirs),
            thousands(entries),
            obs.disk.candidates,
            obs.disk.rounds,
            obs.disk.vanished
        )
    };
    let mut skipped_mounts = 0u64;
    for d in &obs.disk.devices {
        if let DiskStatus::Walked(w) = &d.status {
            skipped_mounts += w.skipped_mounts;
        }
    }
    if skipped_mounts > 0 {
        line.push_str(&format!(
            "；掛著別的裝置的資料夾 {} 個（其中底下原本有東西的 {} 個）",
            skipped_mounts,
            obs.disk.dir_covers.len()
        ));
    }
    if unsettled > 0 {
        line.push_str(&format!(
            "；XFS 有 {} 個名字因為所在的資料夾剛被修改、磁碟上的資料可能還沒更新而不判斷",
            unsettled
        ));
    }
    if !skipped.is_empty() {
        line.push_str(&format!("；不能對照：{}", skipped.join("、")));
    }
    line.push('\n');
    Some(line)
}

mod plain;

pub(crate) struct Items<'a> {
    pub modules: Vec<(usize, &'a NamedModule)>,
    pub threads: Vec<(usize, &'a HiddenProc)>,
    pub procs: Vec<(usize, &'a HiddenProc)>,
    pub exes: Vec<(usize, &'a crate::model::ExeContradiction)>,
    pub covers: Vec<(usize, &'a crate::model::ProcCover)>,
    pub conns: Vec<(usize, &'a crate::judge::ConnGroup)>,
    pub files: Vec<(usize, &'a HiddenFile)>,
    pub contents: Vec<(usize, &'a crate::model::ContentMismatch)>,
    pub deleted: Vec<(usize, &'a crate::judge::DeletedItem)>,
    pub total: usize,
}

impl<'a> Items<'a> {
    pub(crate) fn empty() -> Items<'static> {
        Items {
            modules: Vec::new(),
            threads: Vec::new(),
            procs: Vec::new(),
            exes: Vec::new(),
            covers: Vec::new(),
            conns: Vec::new(),
            files: Vec::new(),
            contents: Vec::new(),
            deleted: Vec::new(),
            total: 0,
        }
    }

    pub(crate) fn build(j: &Findings<'a>) -> Items<'a> {
        let (p, m, c, f, x, ct) = (j.procs, j.mods, j.conns, j.files, j.exes, j.contents);
        let mut idx = 1usize;
        let mut next = || {
            let i = idx;
            idx += 1;
            i
        };
        let modules: Vec<_> = m.named.iter().map(|x| (next(), x)).collect();
        let threads: Vec<_> = p
            .confirmed
            .iter()
            .filter(|h| h.is_kernel_thread)
            .map(|h| (next(), h))
            .collect();
        let procs: Vec<_> = p
            .confirmed
            .iter()
            .filter(|h| !h.is_kernel_thread)
            .map(|h| (next(), h))
            .collect();
        let exes: Vec<_> = x.items.iter().map(|e| (next(), e)).collect();
        let covers: Vec<_> = f.proc_covers.iter().map(|e| (next(), e)).collect();
        let conns: Vec<_> = if c.confirmed {
            c.groups.iter().map(|g| (next(), g)).collect()
        } else {
            Vec::new()
        };
        let files: Vec<_> = sorted_files(f, p, j.origins, x)
            .into_iter()
            .take(FILE_CARDS_MAX)
            .map(|h| (next(), h))
            .collect();
        let contents: Vec<_> = ct.items.iter().map(|e| (next(), e)).collect();
        let deleted: Vec<_> = j
            .deleted
            .confirmed
            .iter()
            .take(plain::deleted::CONFIRMED_MAX)
            .map(|e| (next(), e))
            .collect();
        let total = p.confirmed.len()
            + m.named.len()
            + conn_items(c)
            + f.total
            + x.items.len()
            + f.proc_covers.len()
            + ct.items.len();
        Items {
            modules,
            threads,
            procs,
            exes,
            covers,
            conns,
            files,
            contents,
            deleted,
            total,
        }
    }
}

fn sorted_files<'a>(
    f: &'a FileJudgement,
    p: &ProcJudgement,
    origins: &[OriginJudgement],
    x: &ExeJudgement,
) -> Vec<&'a HiddenFile> {
    use plain::{file_role, FileRole};
    let mut v: Vec<&HiddenFile> = f.confirmed.iter().collect();
    v.sort_by_key(|h| match file_role(h, p, origins, x) {
        FileRole::Exe => 0,
        FileRole::Unit => 1,
        FileRole::Link => 2,
        FileRole::Other => 3,
    });
    v
}

pub struct Findings<'a> {
    pub procs: &'a ProcJudgement,
    pub mods: &'a ModJudgement,
    pub conns: &'a ConnJudgement,
    pub files: &'a FileJudgement,
    pub exes: &'a ExeJudgement,
    pub contents: &'a ContentJudgement,
    pub deleted: &'a crate::judge::DeletedJudgement,
    pub origins: &'a [OriginJudgement],
}

pub fn render(obs: &Observation, j: &Findings, run: &RunInfo, version: &str) -> String {
    let (p, m, c, f, x, origins) = (j.procs, j.mods, j.conns, j.files, j.exes, j.origins);
    let ct = j.contents;
    let meta = &obs.meta;
    let items = Items::build(j);
    let mut s = plain::render_plain(obs, j, run, &items);

    let heavy = "=".repeat(60);
    s.push_str(&format!(
        "{}\n  附錄　技術細節（給資安人員看）\n{}\n",
        heavy, heavy
    ));
    s.push_str("這裡放原本報告裡的證據表、原始數字與規則版本，內容不變，只是從正文搬過來。\n\n");
    s.push_str(&format!(
        "{}\nA　每一項的證據表（編號和正文「找到的東西」一樣）\n{}\n",
        LINE, LINE
    ));
    if items.total == 0 && items.deleted.is_empty() && j.deleted.pending.is_empty() {
        s.push_str("無\n");
    }
    let mut idx = 1;
    for nm in &m.named {
        module_item(idx, nm, m.gap, &mut s);
        idx += 1;
    }
    for h in p.confirmed.iter().filter(|h| h.is_kernel_thread) {
        s.push_str(&format!(
            "[{}] 被藏的核心執行緒　名字：{}（編號 {}）\n",
            idx,
            name_of(h),
            h.info.pid
        ));
        s.push_str(&process_card(h, obs, None, None, None));
        s.push('\n');
        idx += 1;
    }
    let mut seen: Vec<(String, usize)> = Vec::new();
    for h in p.confirmed.iter().filter(|h| !h.is_kernel_thread) {
        s.push_str(&format!(
            "[{}] 被藏的行程　名字：{}（編號 {}）\n",
            idx,
            name_of(h),
            h.info.pid
        ));
        let ev = obs.origin.evidence.iter().find(|e| e.pid == h.info.pid);
        let origin = origins.iter().find(|o| o.pid == h.info.pid);
        let key = proc_key(h, ev, origin);
        let same = seen.iter().find(|(k, _)| *k == key).map(|(_, i)| *i);
        if same.is_none() {
            seen.push((key, idx));
        }
        s.push_str(&process_card(h, obs, ev, origin, same));
        s.push('\n');
        idx += 1;
    }
    exe_items(&mut idx, x, obs, &mut s);
    cover_items(&mut idx, f, &mut s);
    if c.confirmed {
        for g in &c.groups {
            conn_item(idx, obs, c, g, &mut s);
            idx += 1;
        }
        shared_block(obs, c, &mut s);
    }
    file_items(&mut idx, f, p, origins, x, &mut s);
    content_items(&mut idx, ct, &mut s);
    s.push_str(&plain::deleted::appendix_all(&items.deleted, j.deleted));

    s.push('\n');
    s.push_str(&format!("{}\nB　掃描範圍的原始數字\n{}\n", LINE, LINE));
    let mut cov = coverage_block(obs, p, m);
    if j.deleted.ran {
        cov.push_str(&format!(
            "    刪檔程式  {}\n",
            plain::deleted::appendix_scope(j.deleted)
        ));
    }
    s.push_str(&realign_scope(&cov));
    s.push('\n');
    s.push_str(&format!("\n{}\nC　取樣數字與規則版本\n{}\n", LINE, LINE));
    s.push_str(&format!(
        "掃描器版本 {}\n",
        version
    ));
    s.push_str(&format!(
        "行程：取樣 {} 份，編號範圍 1 至 {}（pid_max）\n",
        p.samples, meta.pid_max
    ));
    for (i, smp) in obs.proc_samples.iter().enumerate() {
        let keys: Vec<String> = smp
            .unlisted
            .iter()
            .map(|u| format!("{}@{}", u.pid, u.starttime))
            .collect();
        s.push_str(&format!(
            "  第 {} 份（{} 毫秒）：核心說存在 {} 個、cgroup 列出 {} 個、{}/proc 清單列出 {} 個、存在但沒列出 {} 個 [{}]\n",
            i + 1,
            smp.t_ms,
            smp.n_alive,
            smp.n_cgroup,
            if smp.sched_trusted {
                format!("排程表列出 {} 個、", smp.n_sched)
            } else {
                String::new()
            },
            smp.n_listed,
            smp.unlisted.len(),
            keys.join(" ")
        ));
    }
    s.push_str("  判定：同一個「編號@啟動時間」連續 2 份樣本都在，才算確定發現\n");
    s.push_str(&format!(
        "模組：目錄取樣 {} 份，其中穩定 {} 份；最近 3 份穩定樣本缺口都 >= 1 才算數比對異常（缺口 = 連結數 - 2 - 子目錄數）\n",
        m.total, m.stable
    ));
    if let Some(l) = obs.mod_samples.last() {
        s.push_str(&format!(
            "  最後一份：連結數 {}、列出 {}、子目錄 {}、剛好消失 {}\n",
            l.nl_after, l.n_list2, l.n_sub, l.vanished
        ));
    }
    for c in &m.coverage {
        s.push_str(&format!(
            "  紀錄涵蓋 {}：{}（{}）\n",
            source_label(&c.source),
            if c.covered { "涵蓋" } else { "不涵蓋" },
            c.reason
        ));
    }
    for lg in &obs.logs {
        if lg.source == "journal" {
            s.push_str(&format!(
                "  systemd 日誌：讀了 {} 個檔、約 {} KB，略過 {} 個讀不了的檔\n",
                lg.files, lg.records, lg.skipped
            ));
        } else if lg.source == "messages" {
            s.push_str(&format!(
                "  系統紀錄檔：讀了 {} 個檔、{} 行，略過 {} 個讀不了的檔、{} 個太大或沒讀完的檔\n",
                lg.files, lg.records, lg.skipped, lg.unread
            ));
        } else {
            s.push_str(&format!(
                "  {}：讀了 {} 筆\n",
                source_label(&lg.source),
                lg.records
            ));
        }
    }
    if obs.conn.attempts > 1 {
        s.push_str(&format!(
            "連線證據收集了 {} 輪：第 1 輪只湊到一類證據，之後每輪間隔約 {} 秒再完整收集一次（最多多收集 {} 輪）；以下是最後採用的那一輪的資料（湊齊兩類證據的那一輪；都湊不齊就是第 1 輪）\n",
            obs.conn.attempts,
            crate::CONN_EXTRA_GAP_MS / 1000,
            crate::CONN_EXTRA_ATTEMPTS
        ));
    }
    if let Some(l) = patrol_line(&obs.conn) {
        s.push_str(&format!("連線巡邏：{}\n", l));
    }
    s.push_str(&format!(
        "連線：數量取樣 {} 份，最近 3 份 TCP 缺口 {:?}（缺口 = IPv4 inuse + IPv6 inuse + tw - 兩張連線表列數）；缺口規則{}\n",
        obs.conn_samples.len(),
        c.gaps,
        if c.gap_fired { "成立" } else { "不成立" }
    ));
    s.push_str(&format!(
        "  UDP：穩定樣本 {} 份（共 {} 份；讀表前後登記數相同才算穩定），最近 3 份穩定樣本缺口 {:?}（缺口 = UDP、UDPLITE、UDP6、UDPLITE6 的 inuse 合計 - 四張表列數合計）；缺口規則{}\n",
        c.udp_stable,
        c.udp_total,
        c.udp_gaps,
        if c.udp_gap_fired { "成立" } else { "不成立" }
    ));
    s.push_str(&format!(
        "  逐埠綁定兩輪各得 {} 與 {} 個被占用的埠；連線表前後各列出 {} 與 {} 個本機埠；兩輪都占用、第一次列表沒有的候選埠再重驗 {} 次、重驗時消失了 {} 個；最後兩輪都占用、重驗沒消失、連線表前後都沒有的：{:?}\n",
        obs.conn.inuse_ports_pass1.len(),
        obs.conn.inuse_ports_pass2.len(),
        obs.conn.listed_ports_before.len(),
        obs.conn.listed_ports_after.len(),
        obs.conn.recheck_rounds,
        obs.conn.recheck_vanished.len(),
        c.hidden_ports
        .iter()
        .map(|k| format!("{}{}", k.proto.name(), k.port))
        .collect::<Vec<_>>()
    ));
    for h in &obs.conn.held {
        s.push_str(&format!(
            "  握著不在連線表的 socket：行程 {}（{}）fd {} inode {}\n",
            h.pid,
            if h.comm.is_empty() { "?" } else { &h.comm },
            h.fd,
            h.inode
        ));
    }
    if !obs.conn.visible_held.is_empty() || obs.conn.visible_capped {
        let pids: std::collections::BTreeSet<u32> =
            obs.conn.visible_held.iter().map(|h| h.pid).collect();
        s.push_str(&format!(
            "  一般行程候選：{} 個行程握著 {} 個不在連線表的 socket{}\n",
            pids.len(),
            obs.conn.visible_held.len(),
            if obs.conn.visible_capped {
                "（超過上限，只查了前面一部分）"
            } else {
                ""
            }
        ));
    }
    if !c.hidden_ports.is_empty() {
        s.push_str(&format!("  位址辦法的執行情況：{}\n", methods_text(obs)));
    }
    s.push_str(&disk_appendix(obs));
    if obs.content_scan.ran {
        let c = &obs.content_scan;
        s.push_str(&format!(
            "檔案內容比對：比對 {} 個，略過（剛修改過 {}、太大 {}、一般方式讀不到 {}），候選 {} 個，重驗 {} 輪後消失 {} 個，穩定的 {} 個\n  資料夾：{}\n",
            c.checked,
            c.skipped_recent,
            c.skipped_big,
            c.skipped_unreadable,
            c.candidates,
            crate::collect_content::RECHECK_ROUNDS,
            c.vanished,
            ct.items.len(),
            c.roots.join("、")
        ));
    }
    if obs.exe_scan.ran {
        s.push_str(&format!(
            "程式檔檢查：檢查 {} 個行程，候選 {} 個，重驗 {} 輪後消失 {} 個，穩定的 {} 個\n",
            obs.exe_scan.checked,
            obs.exe_scan.candidates,
            crate::collect_exe::RECHECK_ROUNDS,
            obs.exe_scan.vanished,
            x.items.len()
        ));
    }
    if j.deleted.ran {
        s.push_str(&plain::deleted::appendix_rule(j.deleted));
    }
    for nc in &obs.name_checks {
        s.push_str(&format!(
            "  用名字問核心 {}：{}\n",
            nc.name,
            if nc.stat_ok { "查得到" } else { "查不到" }
        ));
    }
    if let Some(rec) = &run.rec_text {
        s.push_str(
            "\n錄製檔全文（掃描器讀到的原始資料；下面兩條標記線之間逐字就是錄製檔，它的 SHA-256 見上方「核對用資料」；\n用 --replay 指定這份報告，就能不碰系統、重做一次判斷與報告）\n",
        );
        s.push_str(crate::recording::EMBED_BEGIN);
        s.push('\n');
        s.push_str(rec);
        if !rec.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(crate::recording::EMBED_END);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::judge::{judge_modules, judge_processes};
    use crate::model::{Meta, ModSample, ProcSample, Unlisted};
    use crate::recording::tests::sample_observation;

    fn clean_obs() -> Observation {
        let s = ProcSample {
            t_ms: 10,
            n_listed: 100,
            n_alive: 100,
            n_cgroup: 100,
            unlisted: vec![],
            ..Default::default()
        };
        let ms = ModSample {
            nl_before: 120,
            nl_mid: 120,
            nl_after: 120,
            n_list1: 118,
            n_list2: 118,
            n_sub: 118,
            ..Default::default()
        };
        Observation {
            meta: Meta {
                hostname: "centos7-web".into(),
                kernel: "3.10.0-1160.el7.x86_64".into(),
                os: "CentOS Linux release 7.9.2009 (Core)".into(),
                epoch: 1_791_982_917,
                btime: 1_791_982_853,
                clk_tck: 100,
                is_root: true,
                pid_max: 32768,
                uptime_s: 80.0,
                elapsed_ms: 1_500,
                scanner_sha256: None,
            },
            proc_samples: vec![s.clone(), s],
            mod_samples: vec![ms; 5],
            ..Default::default()
        }
    }

    fn squash(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn has(report: &str, needle: &str) -> bool {
        squash(report).contains(&squash(needle))
    }

    fn render_of(o: &Observation) -> String {
        render_run(o, &RunInfo::default())
    }

    fn render_run(o: &Observation, run: &RunInfo) -> String {
        let p = judge_processes(&o.proc_samples);
        let m = judge_modules(o, &p);
        let c = crate::judge::judge_connections(o, &p);
        let origins = crate::judge::judge_origins(o, &p);
        let deleted = crate::judge::judge_deleted(o, &p);
        render(
            o,
            &Findings {
                procs: &p,
                mods: &m,
                conns: &c,
                files: &crate::judge::judge_files(o),
                exes: &crate::judge::judge_exe(o, &p),
                contents: &crate::judge::judge_content(o),
                deleted: &deleted,
                origins: &origins,
            },
            run,
            "0.3.0",
        )
    }

    fn walked_device(mount: &str, dirs: u64) -> crate::model::DiskDevice {
        crate::model::DiskDevice {
            mount_point: mount.into(),
            source: "/dev/sda".into(),
            fstype: "ext4".into(),
            status: DiskStatus::Walked(crate::model::DiskWalk {
                dirs,
                entries: dirs * 20,
                ..Default::default()
            }),
        }
    }

    fn hidden(path: &str, kind: char) -> HiddenFile {
        let (dir, name) = path.rsplit_once('/').unwrap();
        HiddenFile {
            path: path.into(),
            dir: if dir.is_empty() {
                "/".into()
            } else {
                dir.into()
            },
            name: name.into(),
            lstat_error: Some("ENOENT".into()),
            raw: RawFile {
                ino: 48613,
                kind,
                size: if kind == 'd' { 4096 } else { 1_983_716 },
                links: 1,
                mode: 0o755,
                mtime: 1_772_323_210,
                ctime: 1_772_323_210,
                crtime: Some(1_773_022_830),
                sha256: if kind == 'f' {
                    Some("ab".repeat(32))
                } else {
                    None
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn disk_comparison_with_nothing_hidden_is_listed_as_excluded_and_in_coverage() {
        let mut o = clean_obs();
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![walked_device("/", 52_117)],
            rounds: 3,
            candidates: 2,
            vanished: 2,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(r.contains("○ 沒有發現被藏起來的東西"), "{}", r);
        assert!(
            has(&r, "磁碟  對照 1 個 ext4 裝置（/）：走訪 52,117 個資料夾"),
            "{}",
            r
        );
        assert!(has(&r, "候選 2 個、重驗 3 輪後消失 2 個"), "{}", r);
        assert!(
            has(
                &r,
                "硬碟上的資料夾清單，和檔案系統列出的一致：走訪 52,117 個資料夾"
            ),
            "{}",
            r
        );
        assert!(!r.contains("被藏的檔案"), "{}", r);
    }

    #[test]
    fn hidden_files_count_as_findings_and_get_evidence_cards() {
        let mut o = clean_obs();
        let mut dir = hidden("/var/lib/.cache", 'd');
        dir.lstat_error = None;
        dir.children = vec!["a.sh".into(), "b.so".into()];
        dir.children_total = 25;
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![walked_device("/", 100)],
            rounds: 3,
            candidates: 2,
            hidden: vec![hidden("/usr/bin/exampled-svc", 'f'), dir],
            hidden_total: 2,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(r.contains("● 找到 2 個被藏起來的東西"), "{}", r);
        assert!(r.contains("找到的 2 個東西"), "{}", r);
        assert!(
            r.contains("[1] 被藏的檔案　路徑：/usr/bin/exampled-svc"),
            "{}",
            r
        );
        assert!(r.contains("[2] 被藏的檔案　路徑：/var/lib/.cache"), "{}", r);
        assert!(
            r.contains("直接讀磁碟，/usr/bin 的內容裡有這個名字"),
            "{}",
            r
        );
        assert!(has(&r, "問檔案資訊失敗lstat：ENOENT"), "{}", r);
        assert!(
            r.contains("查得到這個路徑，只是列目錄時沒列出來"),
            "第二個的 lstat 成功：{}",
            r
        );
        assert!(
            has(&r, "一般檔；編號 48613；大小 1,983,716 位元組"),
            "{}",
            r
        );
        assert!(r.contains(&format!("SHA-256 {}", "ab".repeat(32))), "{}", r);
        assert!(r.contains("裡面的名字"), "{}", r);
        assert!(r.contains("a.sh、b.so…（共 25 個）"), "{}", r);
        assert!(
            !r.contains("磁碟上的資料夾清單與檔案系統列出的一致"),
            "有發現時不得說一致：{}",
            r
        );
    }

    #[test]
    fn many_hidden_files_collapse_into_one_line_each_after_thirty_cards() {
        let mut o = clean_obs();
        let list: Vec<HiddenFile> = (0..45)
            .map(|i| hidden(&format!("/opt/x/f{:02}", i), 'f'))
            .collect();
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![walked_device("/", 10)],
            rounds: 3,
            hidden: list,
            hidden_total: 250,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(r.contains("● 找到 250 個被藏起來的東西"), "{}", r);
        assert!(r.contains("[30] 被藏的檔案　路徑：/opt/x/f29"), "{}", r);
        assert!(
            !r.contains("[31] 被藏的檔案"),
            "第 31 個起不再列卡片：{}",
            r
        );
        assert!(r.contains("以下 15 個被藏的檔案只列一行"), "{}", r);
        assert!(r.contains("    • /opt/x/f44　一般檔；編號 48613"), "{}", r);
        assert!(
            r.contains("另有 205 個被藏的檔案沒有列出（報告最多列 200 個）"),
            "{}",
            r
        );
    }

    fn with_sched(trusted: bool) -> Observation {
        let mut o = service_obs();
        for s in o.proc_samples.iter_mut() {
            s.sched_read = true;
            s.sched_trusted = trusted;
            s.n_sched = 118;
            s.n_timer = 21;
            for u in s.unlisted.iter_mut() {
                if trusted {
                    u.via_sched = u.comm != "ktestwork";
                    u.via_timer = u.comm == "python2";
                }
            }
        }
        o
    }

    fn line_with<'a>(r: &'a str, key: &str) -> &'a str {
        r.lines().find(|l| l.contains(key)).unwrap_or("")
    }

    #[test]
    fn sched_source_shows_up_in_cards_coverage_appendix_and_blind_spots() {
        let r = render_of(&with_sched(true));
        assert!(has(&r, "排程表有sched_debug"), "{}", r);
        assert!(has(&r, "計時器表有timer_list"), "{}", r);
        assert!(
            r.contains("另外讀排程表 sched_debug 看到 118 個、計時器表 timer_list 看到 21 個"),
            "{}",
            r
        );
        assert!(r.contains("排程表列出 118 個、/proc 清單列出"), "{}", r);
        let kt = r.split("[2] 被藏的核心執行緒").nth(1).unwrap_or("");
        assert!(line_with(kt, "sched_debug").contains("沒有"), "{}", r);
        assert!(r.contains("沒有不代表不存在"), "{}", r);
    }

    #[test]
    fn sched_table_that_cannot_be_trusted_is_reported_and_not_used() {
        let r = render_of(&with_sched(false));
        assert!(r.contains("表裡找不到掃描器自己的編號"), "{}", r);
        assert!(r.contains("沒有採用"), "{}", r);
        assert!(
            !r.contains("排程表 sched_debug  "),
            "不可採用時證據卡不列這一列：{}",
            r
        );
    }

    #[test]
    fn old_recordings_without_the_sched_source_do_not_mention_it() {
        let r = render_of(&service_obs());
        assert!(!r.contains("排程表"), "{}", r);
    }

    fn exe_contradiction(pid: u32, name: &str, exe: &str) -> crate::model::ExeContradiction {
        crate::model::ExeContradiction {
            pid,
            comm: name.into(),
            ppid: Some(1),
            starttime: 5000,
            exe: exe.into(),
            cmdline: format!("{} --serve", exe),
            evidence: crate::model::ProcEvidence {
                pid,
                uid: Some((0, 0)),
                gid: Some((0, 0)),
                tracer_pid: Some(0),
                exe_bytes: Some(4096),
                exe_sha256: Some("cd".repeat(32)),
                exe_info: Some(crate::model::FileInfo::Err("ENOENT".into())),
                ..Default::default()
            },
        }
    }

    #[test]
    fn visible_process_with_hidden_program_file_is_a_finding_with_a_card() {
        let mut o = clean_obs();
        o.exe_scan = crate::model::ExeScan {
            ran: true,
            checked: 113,
            candidates: 2,
            vanished: 1,
            items: vec![exe_contradiction(4321, "xmr", "/usr/lib/.x/xmr")],
        };
        o.meta.btime = 1_772_323_200;
        let r = render_of(&o);
        assert!(r.contains("● 找到 1 個被藏起來的東西"), "{}", r);
        assert!(r.contains("找到的 1 個東西"), "{}", r);
        assert!(
            r.contains("[1] 程式檔被藏的行程　名字：xmr（編號 4321）"),
            "{}",
            r
        );
        assert!(
            has(&r, "打開程式檔成功/proc/編號/exe：讀到 4,096 位元組"),
            "{}",
            r
        );
        assert!(r.contains("ENOENT（上面打開並讀取卻成功）"), "{}", r);
        assert!(has(&r, "執行檔路徑－/usr/lib/.x/xmr"), "{}", r);
        assert!(has(&r, "啟動指令－/usr/lib/.x/xmr --serve"), "{}", r);
        assert!(has(&r, "程式檔　檢查 113 個看得到的行程：能打開卻問不到檔案資訊的候選 2 個、重驗 3 輪後消失 1 個"), "{}", r);
        assert!(
            r.contains("程式檔檢查：檢查 113 個行程，候選 2 個"),
            "{}",
            r
        );
        assert!(
            !r.contains("程式檔打開之後都問得到檔案資訊"),
            "有發現時不得說都正常：{}",
            r
        );
    }

    #[test]
    fn exe_check_with_nothing_wrong_is_listed_as_excluded() {
        let mut o = clean_obs();
        o.exe_scan = crate::model::ExeScan {
            ran: true,
            checked: 113,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(r.contains("○ 沒有發現被藏起來的東西"), "{}", r);
        assert!(r.contains("看得到的 113 個程式，程式檔都正常"), "{}", r);
        assert!(
            !render_of(&clean_obs()).contains("程式檔"),
            "舊格式不提程式檔檢查"
        );
    }

    #[test]
    fn hidden_file_that_is_the_executable_of_a_visible_process_is_cross_referenced() {
        let mut o = clean_obs();
        o.exe_scan = crate::model::ExeScan {
            ran: true,
            checked: 10,
            items: vec![exe_contradiction(4321, "xmr", "/usr/lib/.x/xmr")],
            ..Default::default()
        };
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![walked_device("/", 10)],
            rounds: 3,
            hidden: vec![hidden("/usr/lib/.x/xmr", 'f')],
            hidden_total: 1,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(r.contains("程式檔被藏的行程（編號 4321）的執行檔"), "{}", r);
        assert!(r.contains("● 找到 2 個被藏起來的東西"), "{}", r);
    }

    fn disk_with_skipped(skipped: u64) -> crate::model::DiskScan {
        let mut dev = walked_device("/", 100);
        if let DiskStatus::Walked(w) = &mut dev.status {
            w.skipped_mounts = skipped;
        }
        crate::model::DiskScan {
            ran: true,
            devices: vec![dev],
            rounds: 3,
            ..Default::default()
        }
    }

    #[test]
    fn nothing_covered_is_listed_as_excluded() {
        let mut o = clean_obs();
        o.disk = disk_with_skipped(4);
        let r = render_of(&o);
        assert!(r.contains("○ 沒有發現被藏起來的東西"), "{}", r);
        assert!(r.contains("沒有東西蓋在 /proc 的程式資料夾上"), "{}", r);
        let flat = r.replace("\n    ", "");
        assert!(
            flat.contains(
                "4 個掛了別的裝置的資料夾，底下原本都是空的（裝置檔、具名管道、通訊端除外）"
            ),
            "{}",
            r
        );
        assert!(
            r.contains("掛著別的裝置的資料夾 4 個（其中底下原本有東西的 0 個）"),
            "{}",
            r
        );
        assert!(
            r.contains("蓋住型：掛在 /proc/<行程編號> 上的 0 個；底下有東西的掛載點 0 個"),
            "{}",
            r
        );
    }

    #[test]
    fn a_mount_on_a_process_directory_is_a_finding_with_a_card() {
        let mut o = clean_obs();
        o.disk = disk_with_skipped(4);
        o.disk.proc_covers = vec![crate::model::ProcCover {
            mount_point: "/proc/4321".into(),
            pid: 4321,
            fstype: "tmpfs".into(),
            source: "tmpfs".into(),
            alive: true,
        }];
        let r = render_of(&o);
        assert!(r.contains("● 找到 1 個被藏起來的東西"), "{}", r);
        assert!(r.contains("找到的 1 個東西"), "{}", r);
        assert!(r.contains("[1] 被蓋住的行程　位置：/proc/4321"), "{}", r);
        assert!(
            r.contains("/proc/4321 上掛了一個 tmpfs（來源 tmpfs）"),
            "{}",
            r
        );
        assert!(has(&r, "問核心存在kill(編號,0)：編號 4321"), "{}", r);
        assert!(has(&r, "ps 之類讀 /proc 的工具就讀不到這個行程"), "{}", r);
        assert!(
            !r.contains("沒有東西蓋在 /proc 的程式資料夾上"),
            "有發現時不得說沒有：{}",
            r
        );
    }

    #[test]
    fn a_covered_directory_is_pending_not_a_finding() {
        let mut o = clean_obs();
        o.disk = disk_with_skipped(5);
        o.disk.dir_covers = vec![crate::model::DirCover {
            path: "/usr/lib/foo".into(),
            fstype: "tmpfs".into(),
            source: "tmpfs".into(),
            total: 12,
            names: vec!["a.so".into(), "b.so".into()],
        }];
        let r = render_of(&o);
        assert!(r.contains("△ 另有 1 個有跡象、但還不能確定的項目"), "{}", r);
        assert!(r.contains("○ 沒有發現被藏起來的東西"), "{}", r);
        assert!(r.contains("有跡象但還不能確定的項目（1 個）"), "{}", r);
        assert!(has(&r, "△ 被蓋住的資料夾"), "{}", r);
        assert!(has(&r, "資料夾 /usr/lib/foo"), "{}", r);
        assert!(has(&r, "蓋在上面的是 tmpfs（來源 tmpfs）；硬碟上這個資料夾裡原本有 12 個名字（前幾個：a.so、b.so…）"), "{}", r);
        assert!(
            r.contains("掛著別的裝置的資料夾 5 個（其中底下原本有東西的 1 個）"),
            "{}",
            r
        );
        assert!(
            !r.contains("底下原本都是空的"),
            "有被蓋住的就不能說都是空的：{}",
            r
        );
    }

    fn mismatch(path: &str, vfs: u64, raw: u64, at: Option<u64>) -> crate::model::ContentMismatch {
        crate::model::ContentMismatch {
            path: path.into(),
            vfs_size: vfs,
            vfs_sha256: "ab".repeat(32),
            raw_size: raw,
            raw_sha256: "cd".repeat(32),
            first_diff: at,
        }
    }

    fn content_scan_with(items: Vec<crate::model::ContentMismatch>) -> crate::model::ContentScan {
        crate::model::ContentScan {
            ran: true,
            checked: 1688,
            skipped_recent: 3,
            skipped_big: 1,
            skipped_unreadable: 2,
            candidates: items.len() + 2,
            vanished: 2,
            roots: vec!["/etc".into(), "/root".into()],
            unavailable: Vec::new(),
            items,
        }
    }

    #[test]
    fn altered_file_content_is_a_finding_with_sizes_fingerprints_and_position_but_no_content() {
        let mut o = clean_obs();
        o.content_scan = content_scan_with(vec![
            mismatch("/etc/passwd", 2041, 2098, Some(1204)),
            mismatch("/usr/local/bin/x", 100, 100, None),
        ]);
        let r = render_of(&o);
        assert!(r.contains("● 找到 2 個被藏起來的東西"), "{}", r);
        assert!(
            r.contains("[1] 內容被動過的檔案　路徑：/etc/passwd"),
            "{}",
            r
        );
        assert!(
            r.contains(&format!("大小 2,041 位元組；SHA-256 {}", "ab".repeat(32))),
            "{}",
            r
        );
        assert!(
            r.contains(&format!("大小 2,098 位元組；SHA-256 {}", "cd".repeat(32))),
            "{}",
            r
        );
        assert!(
            has(
                &r,
                "一般方式讀到的比磁碟上少 57 位元組；第一個不同的位置在第 1,204 個位元組"
            ),
            "{}",
            r
        );
        assert!(
            r.contains("兩邊大小相同，內容不同（檔案較大，沒有找出第一個不同的位置）"),
            "{}",
            r
        );
        assert!(r.contains("重驗 3 輪，兩邊的指紋都沒變"), "{}", r);
        assert!(r.contains("報告不顯示檔案內容"), "{}", r);
        assert!(has(&r, "檔案內容  比對 1688 個檔案（/etc、/root、與執行中行程的程式檔）；略過：剛修改過 3、太大 1、一般方式讀不到 2；候選 4 個、重驗 3 輪後消失 2 個"), "{}", r);
        assert!(!r.contains("內容完全一致"), "有發現時不得說都一致：{}", r);
    }

    #[test]
    fn consistent_content_is_listed_as_excluded_and_unavailable_roots_are_noted() {
        let mut o = clean_obs();
        let mut c = content_scan_with(vec![]);
        c.unavailable =
            vec!["/usr/local/bin：這個路徑放在 xfs 檔案系統，原始磁碟解析目前只支援 ext4".into()];
        o.content_scan = c;
        let r = render_of(&o);
        assert!(r.contains("○ 沒有發現被藏起來的東西"), "{}", r);
        assert!(has(&r, "1,688 個檔案，兩種讀法讀到的內容完全一致"), "{}", r);
        assert!(
            has(
                &r,
                "檔案內容比對沒有做：/usr/local/bin：這個路徑放在 xfs 檔案系統"
            ),
            "{}",
            r
        );
        let old = render_of(&clean_obs());
        assert!(!old.contains("檔案內容"), "{}", old);
    }

    #[test]
    fn unavailable_content_roots_with_the_same_reason_are_one_note() {
        let mut o = clean_obs();
        let why = "這個路徑放在 xfs 檔案系統，原始磁碟解析目前只支援 ext4";
        o.content_scan = crate::model::ContentScan {
            ran: true,
            checked: 10,
            roots: vec!["/etc".into(), "/root".into(), "/boot".into()],
            unavailable: vec![
                format!("/etc：{}", why),
                format!("/root：{}", why),
                "/boot：打不開裝置".to_string(),
            ],
            ..Default::default()
        };
        let r = render_of(&o);
        let body = body_of(&r);
        assert_eq!(
            squash(body).matches("檔案內容比對沒有做").count(),
            2,
            "相同原因合成一條，不同原因另一條：{}",
            body
        );
        assert!(
            has(
                body,
                "檔案內容比對沒有做：/etc、/root：這幾個路徑放在 xfs 檔案系統"
            ),
            "{}",
            body
        );
        assert!(
            has(body, "檔案內容比對沒有做：/boot：打不開裝置"),
            "{}",
            body
        );
    }

    #[test]
    fn process_numbers_in_the_relation_are_merged_into_one_phrase() {
        assert_eq!(pid_list(&[1455]), "編號 1455");
        assert_eq!(pid_list(&[1455, 1605, 1606]), "編號 1455、1605、1606");
    }

    #[test]
    fn hidden_file_that_is_a_hidden_process_executable_is_cross_referenced() {
        let mut o = service_obs();
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![walked_device("/", 10)],
            rounds: 3,
            hidden: vec![
                hidden("/usr/bin/python2.7", 'f'),
                hidden("/etc/systemd/system/exampled-svc.service", 'f'),
            ],
            hidden_total: 2,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(r.contains("被藏行程（編號 "), "{}", r);
        assert!(r.contains("）的執行檔"), "{}", r);
        assert!(r.contains("所屬服務的單元檔"), "{}", r);
    }

    #[test]
    fn unsupported_filesystem_and_truncated_walk_are_stated_as_notes() {
        let mut o = clean_obs();
        let mut dev = walked_device("/", 10);
        if let DiskStatus::Walked(w) = &mut dev.status {
            w.truncated = true;
            w.dir_errors = 4;
        }
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![
                dev,
                crate::model::DiskDevice {
                    mount_point: "/boot".into(),
                    source: "/dev/sda1".into(),
                    fstype: "xfs".into(),
                    status: DiskStatus::Unavailable(
                        "xfs 檔案系統，原始磁碟解析目前只支援 ext4".into(),
                    ),
                },
            ],
            rounds: 3,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(
            has(
                &r,
                "磁碟對照沒有做：/boot（xfs）。xfs 檔案系統，原始磁碟解析目前只支援 ext4"
            ),
            "{}",
            r
        );
        assert!(has(&r, "磁碟對照在時間上限（180 秒）內沒有走完 /"), "{}", r);
        assert!(
            r.contains("/ 有 4 個資料夾因為磁碟或檔案系統讀不了，沒有對照"),
            "{}",
            r
        );
        assert!(r.contains("不能對照：/boot（xfs）"), "{}", r);
        assert!(
            !r.contains("磁碟上的資料夾清單與檔案系統列出的一致"),
            "沒走完時不得說一致，沒走完的裝置也要算進來：{}",
            r
        );
    }

    #[test]
    fn xfs_names_not_judged_because_the_directory_was_just_modified_are_said_everywhere() {
        let mut o = clean_obs();
        let mut dev = walked_device("/", 10);
        dev.fstype = "xfs".into();
        if let DiskStatus::Walked(w) = &mut dev.status {
            w.unsettled = 3;
        }
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![dev],
            rounds: 3,
            unsettled_dirs: vec!["/var/tmp/xc".into(), "/tmp".into()],
            cold_secs: 60,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(has(&r, "掃了 1 顆 XFS 硬碟（/）"), "{}", r);
        assert!(
            has(&r, "XFS 有 3 個名字所在的資料夾剛被修改，這次不判斷"),
            "{}",
            r
        );
        assert!(
            has(&r, "/ 有 3 個名字「磁碟上有、列目錄卻沒有」，但它們所在的資料夾最近 60 秒內被修改過（例如 /var/tmp/xc、/tmp）"),
            "{}",
            r
        );
        assert!(has(&r, "不能當成檔案被藏，所以這次不判斷"), "{}", r);
        assert!(has(&r, "對照 1 個 XFS 裝置（/）"), "{}", r);
        assert!(has(&r, "XFS 有 3 個名字因為所在的資料夾剛被修改"), "{}", r);
        assert!(
            r.contains("○ 沒有發現被藏起來的東西"),
            "不判斷的名字不算發現：{}",
            r
        );
    }

    #[test]
    fn mixed_ext4_and_xfs_disks_name_both_kinds() {
        let mut o = clean_obs();
        let mut x = walked_device("/data", 5);
        x.fstype = "xfs".into();
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![walked_device("/", 10), x],
            rounds: 3,
            ..Default::default()
        };
        let r = render_of(&o);
        assert!(has(&r, "掃了 2 顆 ext4 和 XFS 硬碟（/、/data）"), "{}", r);
        assert!(has(&r, "對照 2 個 ext4 和 XFS 裝置（/、/data）"), "{}", r);
    }

    #[test]
    fn clean_report_says_nothing_found_and_lists_blind_spots() {
        let r = render_of(&clean_obs());
        assert!(r.contains("○ 沒有發現被藏起來的東西"));
        assert!(r.contains("有跡象但還不能確定的項目：沒有"));
        assert!(
            !r.contains("這份報告查不到的地方"),
            "盲點不寫進報告"
        );
        assert!(r.contains("兩邊完全相同"));
        assert!(r.contains("模組目錄的計數與列出的個數相同（118 個）"));
        assert!(!r.contains("被藏的連線"));
        assert!(!r.contains("建議"), "規則禁止寫建議下一步");
        assert!(!r.contains("多出來的"), "沒有發現時不得說多出來的就是發現");
    }

    #[test]
    fn infected_report_names_every_hidden_object() {
        let o = sample_observation();
        let mut o = o;
        o.mod_samples = vec![
            ModSample {
                nl_before: 121,
                nl_mid: 121,
                nl_after: 121,
                n_list1: 118,
                n_list2: 118,
                n_sub: 118,
                ..Default::default()
            };
            5
        ];
        o.proc_samples = vec![o.proc_samples[0].clone(), o.proc_samples[0].clone()];
        let r = render_of(&o);
        assert!(r.contains("● 找到 4 個被藏起來的東西"), "{}", r);
        assert!(r.contains("被藏的模組　名字：testmod"));
        assert!(r.contains("被藏的核心執行緒　名字：ktestwork（編號 7652）"));
        assert!(r.contains("被藏的行程　名字：python2（編號 7655）"));
        assert!(r.contains("與被藏的核心執行緒 ktestwork 的啟動時間只差 1 秒"));
        assert!(r.contains("被標為外來模組、沒有簽章"));
        assert!(r.contains("核心訊息緩衝（紀錄完整）、系統紀錄檔（紀錄完整）各有載入紀錄。"));
        assert!(r.contains("有跡象但還不能確定的項目：沒有"));
        assert!(r.contains("被藏的連線　持有者：python2（編號 7655）"));
        assert!(r.contains("127.0.0.1:36552  ↔  127.0.0.1:42149（旁聽封包、暫時查詢行程"));
        assert!(!r.contains("遠端位址無法取得"));
        assert!(has(
            &r,
            "被占用的埠  TCP 36552、42149（36552 綁在 127.0.0.1）"
        ));
    }

    #[test]
    fn connection_without_any_address_says_so_and_lists_attempts() {
        let mut o = sample_observation();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries.clear();
        o.conn.ptrace_ran = false;
        let r = render_of(&o);
        assert!(r.contains("遠端位址無法取得"));
        assert!(has(&r, "沒有位址的埠  TCP 36552、42149；已嘗試："));
        assert!(r.contains("連線追蹤表（這台機器沒有載入這個功能）"));
    }

    #[test]
    fn hidden_udp_connection_is_reported_with_protocol_and_explains_missing_remote() {
        use crate::model::{ConnSample, PeerQuery};
        let mut o = sample_observation();
        o.conn_samples = vec![
            ConnSample {
                su4: 5,
                su6: 3,
                su_after: 8,
                ru4: 3,
                ru6: 3,
                ..Default::default()
            };
            5
        ];
        o.conn.inuse_ports_pass1 = vec![PortKey::udp(34091), PortKey::udp(49240)];
        o.conn.inuse_ports_pass2 = o.conn.inuse_ports_pass1.clone();
        o.conn.listed_ports_before = vec![];
        o.conn.listed_ports_after = vec![];
        o.conn.port_local_addrs = vec![(PortKey::udp(49240), vec!["127.0.0.1".into()])];
        o.conn.capture_pairs.clear();
        o.conn.peer_queries = vec![
            PeerQuery {
                pid: 7655,
                fd: 3,
                local: "127.0.0.1:49240".into(),
                peer: "-".into(),
                error: Some("errno 107".into()),
                state: None,
            },
            PeerQuery {
                pid: 7655,
                fd: 4,
                local: "127.0.0.1:34091".into(),
                peer: "127.0.0.1:49240".into(),
                error: None,
                state: None,
            },
        ];
        let r = render_of(&o);
        assert!(has(&r, "網路連線"), "{}", r);
        assert!(r.contains("核心登記的 UDP 數量比連線表多"), "{}", r);
        assert!(
            has(&r, "被占用的埠  UDP 34091、49240（49240 綁在 127.0.0.1）"),
            "{}",
            r
        );
        assert!(
            has(
                &r,
                "位址        UDP  127.0.0.1:34091  ↔  127.0.0.1:49240（暫時查詢行程"
            ),
            "{}",
            r
        );
        assert!(
            has(
                &r,
                "收發端      UDP  127.0.0.1:49240（沒有對特定對象連線，本來就沒有遠端位址）"
            ),
            "{}",
            r
        );
        assert!(!r.contains("遠端位址無法取得"));
        assert!(!r.contains("位址候選    "), "UDP 沒有目的地記憶可用");
    }

    #[test]
    fn evidence_lines_of_an_item_only_name_its_own_protocols() {
        use crate::judge::ConnGroup;
        let c = ConnJudgement {
            gap_fired: true,
            udp_gap_fired: true,
            evidence: vec!["全部"],
            ..Default::default()
        };
        let holder = Some(crate::judge::Holder {
            pid: 1,
            comm: "x".into(),
            exe: None,
            sockets: 1,
            inodes: vec![1],
            is_kernel_thread: false,
            from_visible: false,
        });
        let udp_only = ConnGroup {
            holders: holder.clone().into_iter().collect(),
            ports: vec![PortKey::udp(1)],
            ..Default::default()
        };
        let v = evidence_for(&c, &udp_only);
        assert!(v.iter().any(|e| e.contains("UDP")));
        assert!(!v.iter().any(|e| e.contains("TCP")), "{:?}", v);
        let both = ConnGroup {
            ports: vec![PortKey::tcp(1), PortKey::udp(2)],
            holders: holder.into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(evidence_for(&c, &both).len(), 5);
        assert_eq!(
            evidence_for(&c, &ConnGroup::default()),
            vec!["全部"],
            "沒有埠可對照時列全部"
        );
    }

    fn visible_holder_obs() -> Observation {
        use crate::model::{ConnSample, HeldSocket, PeerQuery};
        let mut o = sample_observation();
        o.conn_samples = vec![
            ConnSample {
                su4: 5,
                su6: 3,
                su_after: 8,
                ru4: 3,
                ru6: 3,
                ..Default::default()
            };
            8
        ];
        o.conn.inuse_ports_pass1 = vec![PortKey::udp(34091), PortKey::udp(49240)];
        o.conn.inuse_ports_pass2 = o.conn.inuse_ports_pass1.clone();
        o.conn.listed_ports_before = vec![];
        o.conn.listed_ports_after = vec![];
        o.conn.port_local_addrs = vec![];
        o.conn.held.clear();
        o.conn.capture_pairs.clear();
        let held = |pid, comm: &str, fd| HeldSocket {
            pid,
            comm: comm.into(),
            exe: Some(format!("/usr/bin/{}", comm)),
            fd,
            inode: 500 + fd as u64,
        };
        o.conn.visible_held = vec![
            held(623, "dbus-daemon", 5),
            held(8100, "python2", 3),
            held(8100, "python2", 4),
        ];
        o.conn.peer_queries = vec![
            PeerQuery {
                pid: 623,
                fd: 5,
                local: "family=16".into(),
                peer: "family=16".into(),
                error: None,
                state: None,
            },
            PeerQuery {
                pid: 8100,
                fd: 3,
                local: "127.0.0.1:49240".into(),
                peer: "-".into(),
                error: Some("errno 107".into()),
                state: None,
            },
            PeerQuery {
                pid: 8100,
                fd: 4,
                local: "127.0.0.1:34091".into(),
                peer: "127.0.0.1:49240".into(),
                error: None,
                state: None,
            },
        ];
        o
    }

    #[test]
    fn a_visible_holder_is_named_and_explained() {
        let r = render_of(&visible_holder_obs());
        assert!(has(&r, "網路連線"), "{}", r);
        assert!(
            r.contains("被藏的連線　持有者：python2（編號 8100）"),
            "{}",
            r
        );
        assert!(
            has(&r, "持有者說明  這個行程在 /proc 清單裡看得到（沒有被藏）"),
            "{}",
            r
        );
        assert!(
            has(
                &r,
                "位址        UDP  127.0.0.1:34091  ↔  127.0.0.1:49240（暫時查詢行程"
            ),
            "{}",
            r
        );
        assert!(!r.contains("遠端位址無法取得"), "{}", r);
        assert!(
            !r.contains("dbus-daemon"),
            "正常服務的其他種類 socket 不能出現在報告的發現裡：{}",
            r
        );
        assert!(
            r.contains("一般行程候選：2 個行程握著 3 個不在連線表的 socket"),
            "{}",
            r
        );
    }

    #[test]
    fn attempts_mention_how_many_ordinary_processes_were_asked_when_nothing_matched() {
        let mut o = visible_holder_obs();
        o.conn.peer_queries.retain(|q| q.pid == 623);
        let r = render_of(&o);
        assert!(r.contains("持有者：無法取得"), "{}", r);
        assert!(
            has(&r, "含 1 個握著不在連線表的 socket 的一般行程"),
            "{}",
            r
        );
        o.conn.visible_capped = true;
        let r = render_of(&o);
        assert!(r.contains("候選行程太多，只查了前面一部分"), "{}", r);
    }

    #[test]
    fn the_attempts_say_when_a_socket_was_dialing_but_no_record_of_it_was_found() {
        use crate::model::PeerQuery;
        let mut o = sample_observation();
        o.conn.capture_pairs.clear();
        o.conn.ptrace_ran = true;
        o.conn.peer_queries = vec![PeerQuery {
            pid: 7655,
            fd: 3,
            local: "127.0.0.1:36552".into(),
            peer: "-".into(),
            error: Some("errno 107".into()),
            state: Some(2),
        }];
        let r = render_of(&o);
        assert!(
            has(
                &r,
                "看到 socket 正在連出去（狀態 2），但連線追蹤表與旁聽封包都沒有它的紀錄"
            ),
            "{}",
            r
        );
        let mut o2 = sample_observation();
        o2.conn.capture_pairs.clear();
        o2.conn.peer_queries.clear();
        o2.conn.ptrace_ran = true;
        let r2 = render_of(&o2);
        assert!(!r2.contains("正在連出去（狀態 2）"), "{}", r2);
    }

    #[test]
    fn a_listening_socket_answering_not_connected_still_counts_as_a_local_address_obtained() {
        use crate::model::PeerQuery;
        let mut o = visible_holder_obs();
        o.conn.peer_queries = vec![
            PeerQuery {
                pid: 1443,
                fd: 3,
                local: "198.51.100.20:43636".into(),
                peer: "-".into(),
                error: Some("errno 107".into()),
                state: None,
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
        let r = render_of(&o);
        assert!(r.contains("得到 1 筆本機端位址"), "{}", r);
    }

    #[test]
    fn the_remote_port_of_a_dialing_socket_is_not_reported_as_an_occupied_port() {
        use crate::model::PeerQuery;
        let mut o = sample_observation();
        o.conn.capture_pairs.clear();
        o.conn.conntrack_lines.clear();
        o.conn.ptrace_ran = true;
        o.conn.peer_queries = vec![PeerQuery {
            pid: 7655,
            fd: 3,
            local: "127.0.0.1:36552".into(),
            peer: "198.51.100.200:18443".into(),
            error: None,
            state: Some(2),
        }];
        let r = render_of(&o);
        assert!(r.contains("198.51.100.200"), "{}", r);
        assert!(!r.contains("18443 號埠被占用"), "{}", r);
        assert!(!r.contains("、18443"), "{}", r);
        assert!(!r.contains("TCP 18443"), "{}", r);
        assert!(r.contains("36552"), "{}", r);
        assert!(has(&r, "其中 1 筆連對方位址也讀到了"), "{}", r);
    }

    #[test]
    fn appendix_describes_the_address_methods_without_assuming_failure() {
        let mut o = visible_holder_obs();
        o.conn.visible_capped = false;
        let r = render_of(&o);
        assert!(r.contains("位址辦法的執行情況："), "{}", r);
        assert!(
            r.contains(
                "暫時查詢行程：查了 2 個行程（其中 2 個是一般行程），得到 3 筆本機端位址（每筆是一個行程握的一個 socket），其中 1 筆連對方位址也讀到了"
            ),
            "{}",
            r
        );
        assert!(r.contains("連線追蹤表：這台機器沒有載入這個功能"), "{}", r);
        let appendix = &r[r.find("附錄").unwrap()..];
        assert!(
            !appendix.contains("沒有取得位址"),
            "附錄不得預設位址沒取到：{}",
            appendix
        );
    }

    fn appendix_a(r: &str) -> &str {
        let a = r.find("A　每一項的證據表").expect("有附錄 A");
        let b = r.find("B　掃描範圍").expect("有附錄 B");
        &r[a..b]
    }

    fn tables(a: &str) -> Vec<Vec<&str>> {
        let mut out: Vec<Vec<&str>> = Vec::new();
        let mut cur: Option<Vec<&str>> = None;
        for l in a.lines() {
            if l.starts_with("    觀察角度") {
                cur = Some(vec![l]);
            } else if l.trim().is_empty() {
                if let Some(t) = cur.take() {
                    out.push(t);
                }
            } else if let Some(t) = cur.as_mut() {
                t.push(l);
            }
        }
        if let Some(t) = cur {
            out.push(t);
        }
        out
    }

    #[test]
    fn evidence_table_label_and_result_columns_are_chinese_only_so_every_font_aligns_them() {
        for o in [
            rich_obs(),
            with_sched(true),
            sample_observation(),
            with_evidence(Default::default()),
        ] {
            let r = render_of(&o);
            let a = appendix_a(&r);
            let ts = tables(a);
            for t in ts {
                for l in t {
                    let rest = &l[4..];
                    let mut w = 0;
                    for c in rest.chars() {
                        if w >= COL1_W + COL2_W {
                            break;
                        }
                        assert!(
                            !c.is_ascii(),
                            "前兩欄混了半形字元 {:?}（會讓後面的欄位在某些字型裡歪掉）：{}",
                            c,
                            l
                        );
                        w += disp_width(&c.to_string());
                    }
                    assert_eq!(w, COL1_W + COL2_W, "前兩欄不是剛好 28 欄寬：{}", l);
                }
            }
        }
    }

    #[test]
    fn at_least_one_scenario_really_has_evidence_tables_to_check() {
        let r = render_of(&rich_obs());
        assert!(tables(appendix_a(&r)).len() >= 3, "{}", appendix_a(&r));
    }

    #[test]
    fn technical_names_move_to_the_raw_value_column_and_are_not_lost() {
        let r = render_of(&rich_obs());
        let a = appendix_a(&r);
        for kept in [
            "kill(編號,0)",
            "cgroup 工作清單",
            "/proc 目錄清單",
            "/proc/編號/exe",
            "fstat",
            "lstat",
        ] {
            assert!(a.contains(kept), "技術名稱「{}」要留在附錄：{}", kept, a);
        }
        assert!(has(a, "問核心存在kill(編號,0)"), "{}", a);
        assert!(has(a, "群組工作清單有cgroup 工作清單"), "{}", a);
        assert!(has(a, "程式目錄清單沒有/proc 目錄清單"), "{}", a);
        assert!(has(a, "問檔案資訊失敗fstat："), "{}", a);
        let r2 = render_of(&with_sched(true));
        assert!(
            has(appendix_a(&r2), "排程表有sched_debug"),
            "{}",
            appendix_a(&r2)
        );
    }

    #[test]
    fn evidence_table_has_no_duplicate_label_and_no_empty_result_marker_in_ascii() {
        for o in [rich_obs(), with_sched(true)] {
            let r = render_of(&o);
            for t in tables(appendix_a(&r)) {
                let mut seen: Vec<String> = Vec::new();
                for l in t.iter().skip(1) {
                    let label: String = l[4..]
                        .chars()
                        .take_while(|c| !c.is_ascii())
                        .take(COL1_W / 2)
                        .collect();
                    let label = label.trim_matches('\u{3000}').to_string();
                    if label.is_empty() {
                        continue;
                    }
                    assert!(
                        !seen.contains(&label),
                        "同一張表裡「{}」出現兩次：{:?}",
                        label,
                        t
                    );
                    seen.push(label);
                }
            }
        }
    }

    #[test]
    fn long_appendix_values_are_wrapped_but_fingerprints_stay_on_one_line() {
        for o in [rich_obs(), with_sched(true), sample_observation()] {
            let r = render_of(&o);
            for l in appendix_a(&r).lines() {
                if has_full_hash(l) {
                    continue;
                }
                assert!(
                    disp_width(l) <= APP_W + 2,
                    "附錄 A 有一行超過 {} 欄（{} 欄）：{}",
                    APP_W,
                    disp_width(l),
                    l
                );
            }
        }
        let r = render_of(&rich_obs());
        assert!(
            appendix_a(&r).lines().any(|l| l.contains(&"cd".repeat(32))),
            "{}",
            r
        );
    }

    #[test]
    fn identical_times_are_written_once_and_different_ones_get_their_own_line() {
        let t = "2026-03-09 10:20:30";
        let epoch = 1_773_022_830;
        assert_eq!(
            time_lines(Some(epoch), epoch, epoch),
            format!("建立、內容修改、狀態變更\u{3000}{} UTC+8", t)
        );
        let later = epoch + 10_000_000;
        let l = time_lines(Some(epoch), later, later);
        assert_eq!(l.lines().count(), 2, "{}", l);
        assert!(
            l.lines().next().unwrap().starts_with("建立\u{3000}"),
            "{}",
            l
        );
        assert!(l.contains("內容修改、狀態變更\u{3000}"), "{}", l);
        let old = time_lines(None, epoch, epoch);
        assert!(
            old.starts_with("沒有建立時間（舊格式）\n內容修改、狀態變更\u{3000}"),
            "{}",
            old
        );
        assert_eq!(
            time_lines(Some(epoch), epoch, epoch)
                .matches("UTC+8")
                .count(),
            1
        );
    }

    #[test]
    fn key_value_blocks_in_the_appendix_use_full_width_padding_too() {
        let r = render_of(&sample_observation());
        let a = appendix_a(&r);
        let line = a
            .lines()
            .find(|l| l.contains("怎麼知道的"))
            .expect("有「怎麼知道的」");
        assert!(line.starts_with("    怎麼知道的\u{3000}"), "{:?}", line);
        let cont = a
            .lines()
            .find(|l| l.starts_with("    握著"))
            .expect("有「握著」");
        assert!(cont.starts_with("    握著\u{3000}"), "{:?}", cont);
        let b = &r[r.find("B　掃描範圍").unwrap()..r.find("C　取樣數字").unwrap()];
        assert!(b.contains("    行程\u{3000}"), "{}", b);
        assert!(!b.contains("    行程  "), "{}", b);
    }

    fn deleted_sock(remote: &str) -> crate::model::ProcSocket {
        crate::model::ProcSocket {
            proto: Proto::Tcp,
            v6: false,
            local_ip: "10.9.9.1".into(),
            local_port: 35946,
            remote_ip: remote.into(),
            remote_port: 18443,
            state: "02".into(),
            local_port_listening: false,
        }
    }

    fn hacker_proc() -> crate::model::DeletedProc {
        crate::model::DeletedProc {
            pid: 7585,
            ppid: 7564,
            uid: Some(0),
            comm: "systemd-fakemal".into(),
            argv0: "/usr/bin/systemd-fakemal".into(),
            cmdline: "/usr/bin/systemd-fakemal /root/fakemal.py - 1".into(),
            exe_link: "/usr/bin/systemd-fakemal (deleted)".into(),
            starttime: 5000,
            fstat_ok: true,
            ino: 8409410,
            dev: 64513,
            nlink: 0,
            size: 7144,
            mtime: 1_793_692_774,
            ctime: 1_793_692_779,
            sha256: Some("ee".repeat(32)),
            crtime: Some(1_793_692_774),
            argv0_path: "/usr/bin/systemd-fakemal".into(),
            argv0_now: crate::model::PathNow::Missing,
            link_now: crate::model::PathNow::Missing,
            same_ns: true,
            sockets: vec![deleted_sock("203.0.113.50")],
            ..Default::default()
        }
    }

    fn deleted_obs(items: Vec<crate::model::DeletedProc>) -> Observation {
        let mut o = clean_obs();
        o.meta.clk_tck = 100;
        o.meta.btime = 1_793_692_774 - 50;
        o.deleted_scan = crate::model::DeletedScan {
            ran: true,
            checked: 90,
            items,
            ..Default::default()
        };
        o
    }

    #[test]
    fn confirmed_deleted_program_gets_its_own_result_line_list_and_card() {
        let r = render_of(&deleted_obs(vec![hacker_proc()]));
        let body = body_of(&r);
        assert!(has(body, "○ 沒有發現被藏起來的東西"), "{}", body);
        assert!(
            has(body, "● 另有 1 個「程式檔被刪掉、還在執行」的可疑程式"),
            "{}",
            body
        );
        assert!(
            has(body, "程式檔被刪掉、還在執行的可疑程式（1 個）"),
            "{}",
            body
        );
        assert!(
            has(body, "● [1] 刪檔程式 systemd-fakemal（編號 7585）"),
            "{}",
            body
        );
        assert!(
            has(
                body,
                "連到 203.0.113.50:18443（已送出連線請求，還沒收到回應）"
            ),
            "{}",
            body
        );
        assert!(
            has(body, "[1] 刪檔程式　systemd-fakemal（編號 7585）"),
            "{}",
            body
        );
        assert!(
            has(body, &format!("SHA-256 {}", "ee".repeat(32))),
            "{}",
            body
        );
        assert!(has(body, "檔案建立　2026-"), "{}", body);
        assert!(has(body, "檔案刪除　2026-"), "{}", body);
        assert!(has(body, "（程式啟動後 5 秒）"), "{}", body);
        assert!(
            has(body, "三個線索都對得上") || has(body, "四個線索都對得上"),
            "{}",
            body
        );
        assert!(
            has(
                body,
                "啟動指令裡的路徑 /usr/bin/systemd-fakemal，現在沒有任何檔案"
            ),
            "{}",
            body
        );
        assert!(
            has(body, "本機 10.9.9.1:35946 → 203.0.113.50:18443"),
            "{}",
            body
        );
        assert!(has(body, "請趁程式還在執行時複製它的程式檔"), "{}", body);
        assert!(
            has(
                body,
                "刪檔程式　檢查 90 個程式，1 個的程式檔已被刪除（1 個確定可疑）"
            ),
            "{}",
            body
        );
        let appendix = &r[r.find("附錄").unwrap()..];
        assert!(
            has(
                appendix,
                "[1] 刪檔程式（確定可疑）　名字：systemd-fakemal（編號 7585）"
            ),
            "{}",
            appendix
        );
        assert!(has(appendix, "連結數 0"), "{}", appendix);
        assert!(has(appendix, &"ee".repeat(32)), "{}", appendix);
        assert!(has(appendix, "掃描器版本"), "{}", appendix);
        assert!(!has(appendix, "docs/spec"), "{}", appendix);
        assert!(!has(appendix, "規則："), "{}", appendix);
        assert!(
            has(
                appendix,
                "刪檔程式　檢查 90 個有程式檔的行程（在別的掛載空間而略過 0 個）"
            ),
            "{}",
            appendix
        );
        assert!(
            has(
                appendix,
                "刪檔程式檢查：檢查 90 個行程，確定可疑 1 個、待確認 0 個"
            ),
            "{}",
            appendix
        );
        assert!(
            appendix.contains(
                "\n  判定：程式檔已刪（連結數 0）、原本的路徑上沒有啟動之後才出現的新檔案"
            ),
            "{}",
            appendix
        );
        for l in body.lines() {
            if l.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 64 {
                continue;
            }
            assert!(disp_width(l) <= 66, "{} 欄：{}", disp_width(l), l);
        }
    }

    #[test]
    fn deleted_program_numbers_continue_after_the_hidden_items_and_total_is_not_changed() {
        let mut o = rich_obs();
        o.meta.clk_tck = 100;
        o.meta.btime = 1_793_692_774 - 50;
        o.deleted_scan = crate::model::DeletedScan {
            ran: true,
            checked: 10,
            items: vec![hacker_proc()],
            ..Default::default()
        };
        let r = render_of(&o);
        let body = body_of(&r);
        let hidden_total: usize = body
            .lines()
            .find_map(|l| l.split("● 找到 ").nth(1))
            .and_then(|t| t.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .expect("有「找到 N 個」");
        let want = format!("[{}] 刪檔程式", hidden_total + 1);
        assert!(has(body, &want), "{}", body);
        assert!(has(
            &r[r.find("附錄").unwrap()..],
            &format!("[{}] 刪檔程式（確定可疑）", hidden_total + 1)
        ));
    }

    #[test]
    fn pending_deleted_program_is_listed_as_not_certain_with_the_reason() {
        let mut p = hacker_proc();
        p.sockets.clear();
        let r = render_of(&deleted_obs(vec![p]));
        let body = body_of(&r);
        assert!(
            has(body, "○ 沒有「程式檔被刪掉、還在執行」的可疑程式"),
            "{}",
            body
        );
        assert!(
            has(body, "△ 另有 1 個有跡象、但還不能確定的項目"),
            "{}",
            body
        );
        assert!(
            has(body, "△ 刪檔程式　systemd-fakemal（編號 7585）"),
            "{}",
            body
        );
        assert!(has(body, "沒有看到它主動連到外面的網路"), "{}", body);
        assert!(!has(body, "● [1] 刪檔程式"), "{}", body);
        let appendix = &r[r.find("附錄").unwrap()..];
        assert!(has(appendix, "△ 刪檔程式（待確認）"), "{}", appendix);
    }

    #[test]
    fn updated_and_quiet_programs_are_only_notes_not_findings() {
        let mut upd = hacker_proc();
        upd.pid = 100;
        upd.comm = "mydaemon".into();
        upd.argv0 = "/usr/local/bin/mydaemon".into();
        upd.exe_link = "/usr/local/bin/mydaemon;5fa0c1d2 (deleted)".into();
        upd.ctime = 1_793_692_774 + 86_400 * 9;
        upd.argv0_now = crate::model::PathNow::File {
            ino: 1,
            dev: 64513,
            ctime: 1_793_692_774 + 86_400 * 9,
            mtime: 1_793_692_774 + 86_400 * 9,
        };
        let mut quiet = hacker_proc();
        quiet.pid = 200;
        quiet.comm = "olddaemon".into();
        quiet.argv0 = "/usr/sbin/olddaemon".into();
        quiet.exe_link = "/usr/sbin/olddaemon (deleted)".into();
        quiet.ctime = 1_793_692_774 + 86_400 * 3;
        quiet.sockets.clear();
        let r = render_of(&deleted_obs(vec![upd, quiet]));
        let body = body_of(&r);
        assert!(has(body, "○ 沒有發現被藏起來的東西"), "{}", body);
        assert!(
            has(body, "○ 沒有「程式檔被刪掉、還在執行」的可疑程式"),
            "{}",
            body
        );
        assert!(
            has(body, "已經被新版檔案取代（軟體更新後還沒重新啟動）"),
            "{}",
            body
        );
        assert!(has(body, "mydaemon"), "{}", body);
        assert!(has(body, "沒有可疑跡象"), "{}", body);
        assert!(has(body, "olddaemon"), "{}", body);
        assert!(has(body, "○ 沒有「有跡象但還不能確定」的項目"), "{}", body);
        assert!(has(body, "刪檔程式　檢查 90 個程式，2 個的程式檔已被刪除（1 個是更新後還沒重新啟動、1 個沒有可疑跡象）"), "{}", body);
    }

    #[test]
    fn nothing_deleted_says_so_in_scope_and_ok_lines_and_old_recordings_say_nothing() {
        let r = render_of(&deleted_obs(vec![]));
        let body = body_of(&r);
        assert!(
            has(body, "刪檔程式　檢查 90 個程式，沒有程式檔被刪除"),
            "{}",
            body
        );
        assert!(
            has(
                body,
                "檢查了 90 個程式的程式檔，沒有發現「程式檔被刪掉、還在執行」的可疑程式。"
            ),
            "{}",
            body
        );
        assert!(
            has(body, "○ 沒有「程式檔被刪掉、還在執行」的可疑程式"),
            "{}",
            body
        );
        let mut old = clean_obs();
        old.deleted_scan = Default::default();
        let r2 = render_of(&old);
        assert!(!has(&r2, "刪檔程式") && !has(&r2, "程式檔被刪掉"), "{}", r2);
    }

    #[test]
    fn deleted_card_survives_extreme_lengths() {
        let mut p = hacker_proc();
        p.comm = "x".repeat(15);
        p.argv0 = format!("/{}", "很長的資料夾名字/".repeat(30));
        p.cmdline = format!("{} {}", p.argv0, "參數".repeat(200));
        p.exe_link = format!("{} (deleted)", p.argv0);
        p.argv0_path = p.argv0.clone();
        p.sockets = (0..8)
            .map(|n| deleted_sock(&format!("203.0.113.{}", n + 1)))
            .collect();
        let r = render_of(&deleted_obs(vec![p]));
        let body = body_of(&r);
        for l in body.lines() {
            if l.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 64 {
                continue;
            }
            assert!(disp_width(l) <= 66, "{} 欄：{}", disp_width(l), l);
        }
        assert!(has(body, "另有 5 條連線沒有列出，見附錄。"), "{}", body);
    }

    #[test]
    fn patrol_that_caught_the_connection_says_so_in_scope_card_and_appendix() {
        let mut o = sample_observation();
        let plain = render_of(&o);
        assert!(!has(&plain, "巡邏"), "沒巡邏就不提巡邏：{}", plain);
        o.conn.patrol_ran = true;
        o.conn.patrol_limit_secs = 150;
        o.conn.patrol_ms = 23_456;
        o.conn.patrol_samples = 47;
        o.conn.patrol_rounds = 1;
        o.conn.patrol_caught = true;
        let r = render_of(&o);
        let body = body_of(&r);
        assert!(
            has(body, "一開始沒看到被藏的連線，巡邏約 23 秒後看到了"),
            "{}",
            body
        );
        assert!(
            has(
                body,
                "巡邏　一開始掃描時沒看到這條連線，巡邏約 23 秒後才看到"
            ),
            "{}",
            body
        );
        assert!(!has(body, "巡邏約 23 秒都沒看到"), "{}", body);
        let appendix = &r[r.find("附錄").unwrap()..];
        assert!(
            has(appendix, "巡邏上限 150 秒、實際 23456 毫秒；取樣 47 份；看到跡象後完整收集 1 輪；結果：湊齊兩類證據"),
            "{}",
            appendix
        );
    }

    #[test]
    fn patrol_that_found_nothing_is_listed_as_a_limit_not_as_clean() {
        let mut o = rich_obs();
        o.conn_samples = vec![crate::model::ConnSample::default(); 8];
        o.conn.patrol_ran = true;
        o.conn.patrol_limit_secs = 150;
        o.conn.patrol_ms = 150_020;
        o.conn.patrol_samples = 290;
        let r = render_of(&o);
        let body = body_of(&r);
        assert!(
            has(
                body,
                "已確認有被藏的程式卻沒看到被藏的連線，又巡邏了約 150 秒，仍然沒看到"
            ),
            "{}",
            body
        );
        assert!(has(body, "找到"), "{}", body);
        assert!(!has(body, "巡邏約 150 秒後看到了"), "{}", body);
        let appendix = &r[r.find("附錄").unwrap()..];
        assert!(has(appendix, "結果：沒有湊齊兩類證據"), "{}", appendix);
    }

    #[test]
    fn patrol_lines_never_exceed_the_report_width() {
        let mut o = sample_observation();
        o.conn.patrol_ran = true;
        o.conn.patrol_limit_secs = 3600;
        o.conn.patrol_ms = 3_600_000;
        o.conn.patrol_samples = 99_999;
        o.conn.patrol_rounds = 6;
        let r = render_of(&o);
        for l in body_of(&r).lines() {
            if l.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 64 {
                continue;
            }
            assert!(disp_width(l) <= 66, "{} 欄：{}", disp_width(l), l);
        }
    }

    #[test]
    fn connection_with_one_evidence_class_is_pending_not_a_finding() {
        let mut o = clean_obs();
        o.conn_samples = vec![
            crate::model::ConnSample {
                inuse4: 8,
                inuse6: 3,
                e4: 5,
                e6: 3,
                ..Default::default()
            };
            5
        ];
        let r = render_of(&o);
        assert!(r.contains("△ 另有 1 個有跡象、但還不能確定的項目"), "{}", r);
        assert!(has(&r, "△ 網路連線"), "{}", r);
        assert!(
            has(&r, "只有一個線索：核心登記的連線數，比連線清單多"),
            "{}",
            r
        );
        assert!(r.contains("○ 沒有發現被藏起來的東西"));
        assert!(!r.contains("已重試"), "只收集一輪時不提重試：{}", r);
        o.conn.attempts = 5;
        let r2 = render_of(&o);
        assert!(
            has(
                &r2,
                "已重試　連線證據共收集了 5 輪（輪與輪之間隔約 1 秒），每一輪都只有一個線索"
            ),
            "{}",
            r2
        );
        assert!(has(&r2, "建議隔一段時間再掃一次"), "{}", r2);
    }

    #[test]
    fn single_source_says_has_not_each_has() {
        let mut o = sample_observation();
        o.conn = Default::default();
        o.conn_samples.clear();
        o.logs[1].load_lines.clear();
        o.mod_samples = vec![
            ModSample {
                nl_before: 121,
                nl_mid: 121,
                nl_after: 121,
                n_list1: 118,
                n_list2: 118,
                n_sub: 118,
                ..Default::default()
            };
            5
        ];
        let r = render_of(&o);
        assert!(r.contains("核心訊息緩衝（紀錄完整）有載入紀錄。"));
        assert!(!r.contains("各有載入紀錄"));
    }

    #[test]
    fn unnamed_gap_is_reported_as_pending_not_as_finding() {
        let mut o = sample_observation();
        o.conn = Default::default();
        o.conn_samples.clear();
        o.proc_samples.clear();
        o.logs.clear();
        o.name_checks.clear();
        o.mod_samples = vec![
            ModSample {
                nl_before: 121,
                nl_mid: 121,
                nl_after: 121,
                n_list1: 118,
                n_list2: 118,
                n_sub: 118,
                ..Default::default()
            };
            4
        ];
        let r = render_of(&o);
        assert!(r.contains("△ 另有 1 個有跡象、但還不能確定的項目"));
        assert!(r.contains("有跡象但還不能確定的項目（1 個）"));
        assert!(r.contains("△ 核心模組（名字拿不到）"));
        assert!(r.contains("○ 沒有發現被藏起來的東西"));
    }

    fn infected_with_origin(
        facts: crate::model::OriginFacts,
        logins: Vec<crate::model::AuditLogin>,
    ) -> Observation {
        let mut o = sample_observation();
        o.proc_samples = vec![o.proc_samples[0].clone(), o.proc_samples[0].clone()];
        o.meta.btime = 1_000;
        let pid = o.proc_samples[0]
            .unlisted
            .iter()
            .find(|u| u.comm == "python2")
            .map(|u| u.pid)
            .expect("樣本裡有 python2 行程");
        let mut facts = facts;
        facts.pid = pid;
        o.origin = crate::model::OriginData {
            ran: true,
            items: vec![facts],
            audit_ran: true,
            audit_files: 2,
            audit_min_epoch: Some(5_000),
            audit_logins: logins,
            ..Default::default()
        };
        o
    }

    #[test]
    fn login_started_hidden_process_shows_login_facts() {
        let facts = crate::model::OriginFacts {
            loginuid: Some(0),
            sessionid: Some(2),
            cgroup: Some("/user.slice/user-0.slice/session-2.scope".into()),
            ssh_connection: Some("203.0.113.7 51776 10.0.0.1 22".into()),
            session_file: Some(crate::model::SessionFile {
                service: Some("sshd".into()),
                user: Some("root".into()),
                remote_host: Some("203.0.113.7".into()),
                realtime_us: Some(1_793_086_267_544_472),
                state: Some("closing".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let login = crate::model::AuditLogin {
            ses: 2,
            epoch: 1_793_086_267,
            exe: "/usr/sbin/sshd".into(),
            addr: "203.0.113.7".into(),
            hostname: "203.0.113.7".into(),
            terminal: "ssh".into(),
            ..Default::default()
        };
        let r = render_of(&infected_with_origin(facts, vec![login]));
        assert!(r.contains("帳號編號 0、登入編號 2"), "{}", r);
        assert!(
            r.contains("/user.slice/user-0.slice/session-2.scope"),
            "{}",
            r
        );
        assert!(
            has(
                &r,
                "登入時間 2026-10-27 15:31:07 UTC+8；登入服務 sshd；帳號 root；遠端 203.0.113.7"
            ),
            "{}",
            r
        );
        assert!(
            has(
                &r,
                "2026-10-27 15:31:07 UTC+8；執行檔 /usr/sbin/sshd；來源位址 203.0.113.7"
            ),
            "{}",
            r
        );
        assert!(
            r.contains("從 203.0.113.7 埠 51776 連到本機 10.0.0.1 埠 22"),
            "{}",
            r
        );
        assert!(!r.contains("建議"));
    }

    #[test]
    fn service_started_hidden_process_says_no_login_and_unit_file_missing() {
        let facts = crate::model::OriginFacts {
            loginuid: Some(crate::model::ID_UNSET),
            sessionid: Some(crate::model::ID_UNSET),
            cgroup: Some("/system.slice/exampled-svc.service".into()),
            unit_checked: true,
            ..Default::default()
        };
        let r = render_of(&infected_with_origin(facts, vec![]));
        assert!(
            r.contains("exampled-svc.service（由服務管理員 systemd 啟動）"),
            "{}",
            r
        );
        assert!(r.contains("loginuid、sessionid 都是「未設定」"), "{}", r);
        assert!(has(&r, "/etc/systemd/system、/usr/lib/systemd/system、/lib/systemd/system、/run/systemd/system 都沒有"), "{}", r);
        assert!(
            r.contains("開機時間\u{3000}1970-01-01 08:16（已連續開機"),
            "{}",
            r
        );
        assert!(!r.contains("隨上一次關機消失"), "不得斷言有重開機");
    }

    fn service_obs() -> Observation {
        let facts = crate::model::OriginFacts {
            loginuid: Some(crate::model::ID_UNSET),
            sessionid: Some(crate::model::ID_UNSET),
            cgroup: Some("/system.slice/exampled-svc.service".into()),
            unit_checked: true,
            ..Default::default()
        };
        infected_with_origin(facts, vec![])
    }

    fn unit_path(dir: &str) -> String {
        format!("{}/exampled-svc.service", dir)
    }

    fn disk_unit(ino: u64, content: &str) -> RawLookup {
        RawLookup::Found(RawFile {
            ino,
            kind: 'f',
            size: content.len() as u64,
            links: 1,
            mode: 0o644,
            mtime: 1_772_323_210,
            ctime: 1_772_323_210,
            crtime: Some(1_773_022_830),
            content: Some(content.to_string()),
            ..Default::default()
        })
    }

    fn absent(dir: &str, vfs: Option<&str>, raw: RawLookup) -> RawFileFact {
        RawFileFact {
            path: unit_path(dir),
            vfs_error: vfs.map(str::to_string),
            raw,
            ..Default::default()
        }
    }

    #[test]
    fn unit_file_hidden_from_filesystem_but_present_on_disk_is_shown_with_its_content() {
        let mut o = service_obs();
        let body = "[Unit]\nDescription=範例\n\n[Service]\nExecStart=/usr/bin/example --run\n";
        o.origin.raw_files = vec![
            absent(
                "/etc/systemd/system",
                Some("ENOENT"),
                disk_unit(48614, body),
            ),
            absent(
                "/usr/lib/systemd/system",
                Some("ENOENT"),
                RawLookup::NotFound,
            ),
            absent("/lib/systemd/system", Some("ENOENT"), RawLookup::NotFound),
            absent("/run/systemd/system", Some("ENOENT"), RawLookup::NotFound),
        ];
        let r = render_of(&o);
        assert!(has(&r, "單元檔的磁碟資料"), "{}", r);
        assert!(
            has(
                &r,
                "磁碟上有、檔案系統說沒有（ENOENT）：/etc/systemd/system/exampled-svc.service"
            ),
            "{}",
            r
        );
        assert!(r.contains("不一致"), "{}", r);
        let unit_line = r.lines().find(|l| l.contains("服務單元檔 ")).unwrap_or("");
        assert!(!unit_line.contains("找不到"), "不能再寫找不到：{}", r);
        assert!(r.contains("編號 48614；大小 "), "{}", r);
        assert!(has(&r, "建立 2026-03-09 10:20:30 UTC+8"), "{}", r);
        assert!(
            r.contains("服務單元檔內容（/etc/systemd/system/exampled-svc.service；"),
            "{}",
            r
        );
        assert!(r.contains("直接讀磁碟）"), "{}", r);
        assert!(
            r.contains("        ExecStart=/usr/bin/example --run\n"),
            "{}",
            r
        );
        assert!(r.contains("        Description=範例\n"), "{}", r);
    }

    #[test]
    fn unit_file_visible_everywhere_is_plain_yes() {
        let mut o = service_obs();
        o.origin.raw_files = vec![
            absent("/etc/systemd/system", None, disk_unit(7, "[Unit]\n")),
            absent("/usr/lib/systemd/system", None, RawLookup::NotFound),
            absent("/lib/systemd/system", None, RawLookup::NotFound),
            absent("/run/systemd/system", None, RawLookup::NotFound),
        ];
        for f in o.origin.raw_files.iter_mut().skip(1) {
            f.vfs_error = Some("ENOENT".into());
        }
        let r = render_of(&o);
        assert!(r.contains("服務單元檔"), "{}", r);
        assert!(!r.contains("不一致"), "{}", r);
        assert!(
            r.contains("/etc/systemd/system/exampled-svc.service"),
            "{}",
            r
        );
    }

    #[test]
    fn unit_file_on_unsupported_filesystem_uses_filesystem_content_and_says_disk_check_unavailable()
    {
        let mut o = service_obs();
        let why = "這個路徑放在 xfs 檔案系統，原始磁碟解析目前只支援 ext4";
        o.origin.raw_files = vec![
            RawFileFact {
                path: unit_path("/etc/systemd/system"),
                vfs_error: None,
                vfs_content: Some("[Service]\nExecStart=/opt/app\n".into()),
                raw: RawLookup::Unavailable(why.into()),
                ..Default::default()
            },
            absent(
                "/usr/lib/systemd/system",
                Some("ENOENT"),
                RawLookup::Unavailable(why.into()),
            ),
            absent(
                "/lib/systemd/system",
                Some("ENOENT"),
                RawLookup::Unavailable(why.into()),
            ),
            absent(
                "/run/systemd/system",
                Some("ENOENT"),
                RawLookup::Unavailable(why.into()),
            ),
        ];
        let r = render_of(&o);
        assert!(has(&r, "磁碟對照不可用：這個路徑放在 xfs"), "{}", r);
        assert!(r.contains("從檔案系統讀）"), "{}", r);
        assert!(r.contains("        ExecStart=/opt/app\n"), "{}", r);
    }

    #[test]
    fn unit_file_absent_on_both_sides_and_unavailable_disk_are_worded_differently() {
        let mut o = service_obs();
        o.origin.raw_files = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
        ]
        .iter()
        .map(|d| absent(d, Some("ENOENT"), RawLookup::NotFound))
        .collect();
        let r = render_of(&o);
        assert!(r.contains("檔案系統與磁碟上都沒有："), "{}", r);
        assert!(!r.contains("不能排除檔案被藏"), "{}", r);
        let mut o2 = service_obs();
        o2.origin.raw_files = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
            "/run/systemd/system",
        ]
        .iter()
        .map(|d| {
            absent(
                d,
                Some("ENOENT"),
                RawLookup::Unavailable("不是 ext4".into()),
            )
        })
        .collect();
        let r2 = render_of(&o2);
        assert!(
            has(&r2, "磁碟對照不可用（不是 ext4），所以不能排除檔案被藏"),
            "{}",
            r2
        );
        let r3 = render_of(&service_obs());
        assert!(r3.contains("都沒有"), "{}", r3);
        assert!(!r3.contains("磁碟"), "舊格式不提磁碟：{}", r3);
    }

    #[test]
    fn disagreeing_content_between_filesystem_and_disk_is_called_out() {
        let mut o = service_obs();
        o.origin.raw_files = vec![
            RawFileFact {
                path: unit_path("/etc/systemd/system"),
                vfs_error: None,
                vfs_content: Some("A\n".into()),
                raw: disk_unit(9, "B\n"),
                ..Default::default()
            },
            absent(
                "/usr/lib/systemd/system",
                Some("ENOENT"),
                RawLookup::NotFound,
            ),
            absent("/lib/systemd/system", Some("ENOENT"), RawLookup::NotFound),
            absent("/run/systemd/system", Some("ENOENT"), RawLookup::NotFound),
        ];
        let r = render_of(&o);
        assert!(
            r.contains("注意：檔案系統給的內容和磁碟上的不一樣。"),
            "{}",
            r
        );
        assert!(r.contains("        B\n"), "以磁碟上的為準：{}", r);
    }

    #[test]
    fn same_unit_file_reached_through_lib_symlink_is_listed_once_and_control_chars_are_neutralised()
    {
        let mut o = service_obs();
        let body = "[Service]\nExecStart=/bin/x\u{1b}[31m\n";
        o.origin.raw_files = vec![
            absent("/etc/systemd/system", Some("ENOENT"), RawLookup::NotFound),
            absent("/usr/lib/systemd/system", None, disk_unit(11, body)),
            absent("/lib/systemd/system", None, disk_unit(11, body)),
            absent("/run/systemd/system", Some("ENOENT"), RawLookup::NotFound),
        ];
        let r = render_of(&o);
        assert_eq!(r.matches("服務單元檔內容（").count(), 1, "{}", r);
        assert!(!r.contains('\u{1b}'), "控制字元不得原樣輸出");
        assert!(r.contains("ExecStart=/bin/x?[31m"), "{}", r);
    }

    #[test]
    fn long_unit_file_is_cut_after_sixty_lines() {
        let mut o = service_obs();
        let body: String = (0..100).map(|i| format!("Line{}=x\n", i)).collect();
        o.origin.raw_files = vec![
            absent("/etc/systemd/system", Some("ENOENT"), disk_unit(5, &body)),
            absent(
                "/usr/lib/systemd/system",
                Some("ENOENT"),
                RawLookup::NotFound,
            ),
            absent("/lib/systemd/system", Some("ENOENT"), RawLookup::NotFound),
            absent("/run/systemd/system", Some("ENOENT"), RawLookup::NotFound),
        ];
        let r = render_of(&o);
        assert!(r.contains("Line59=x"), "{}", r);
        assert!(!r.contains("Line60=x"), "{}", r);
        assert!(r.contains("只列前面一部分"), "{}", r);
    }

    #[test]
    fn executable_on_disk_is_compared_with_the_running_image() {
        let mut o = with_evidence(crate::model::ProcEvidence {
            exe_bytes: Some(10),
            exe_sha256: Some("ab".repeat(32)),
            exe_info: Some(crate::model::FileInfo::Err("ENOENT".into())),
            ..Default::default()
        });
        let disk = |sha: &str| {
            RawLookup::Found(RawFile {
                ino: 48613,
                kind: 'f',
                size: 1_983_716,
                links: 1,
                mode: 0o755,
                mtime: 1_773_022_830,
                ctime: 1_773_022_830,
                crtime: Some(1_773_022_830),
                sha256: Some(sha.to_string()),
                ..Default::default()
            })
        };
        o.origin.raw_files = vec![RawFileFact {
            path: "/usr/bin/python2.7".into(),
            vfs_error: Some("ENOENT".into()),
            raw: disk(&"ab".repeat(32)),
            ..Default::default()
        }];
        let r = render_of(&o);
        assert!(has(&r, "執行檔的磁碟資料"), "{}", r);
        assert!(r.contains("執行檔（磁碟）"), "{}", r);
        assert!(r.contains("磁碟上有、檔案系統說沒有（ENOENT）"), "{}", r);
        assert!(r.contains("內容指紋與上面執行中的 SHA-256 相同"), "{}", r);
        o.origin.raw_files[0].raw = disk(&"cd".repeat(32));
        let r2 = render_of(&o);
        assert!(has(&r2, "不同（磁碟上的檔案在行程啟動後被換過）"), "{}", r2);
    }

    #[test]
    fn login_without_any_record_reports_what_was_searched() {
        let facts = crate::model::OriginFacts {
            loginuid: Some(0),
            sessionid: Some(9),
            cgroup: Some("/user.slice/user-0.slice/session-9.scope".into()),
            ..Default::default()
        };
        let r = render_of(&infected_with_origin(facts, vec![]));
        assert!(r.contains("對應的登入紀錄"), "{}", r);
        assert!(has(&r, "登入管理員沒有這個工作階段檔；稽核紀錄讀了 2 個檔，最早的事件是 1970-01-01 09:23:20 UTC+8，裡面沒有這個登入編號的成功登入事件"), "{}", r);
    }

    #[test]
    fn origin_section_is_absent_without_data_and_never_changes_the_count() {
        let o = {
            let mut o = sample_observation();
            o.proc_samples = vec![o.proc_samples[0].clone(), o.proc_samples[0].clone()];
            o
        };
        let without = render_of(&o);
        assert!(!without.contains("啟動來源"), "{}", without);
        let facts = crate::model::OriginFacts {
            loginuid: Some(crate::model::ID_UNSET),
            sessionid: Some(crate::model::ID_UNSET),
            cgroup: Some("/".into()),
            ..Default::default()
        };
        let with = render_of(&infected_with_origin(facts, vec![]));
        let head = |t: &str| {
            t.lines()
                .find(|l| l.contains("找到 ") || l.contains("沒有發現被藏起來的東西"))
                .unwrap()
                .to_string()
        };
        assert_eq!(head(&without), head(&with), "啟動來源不得改變發現數量");
        assert!(with.contains("沒有登入身分，也不屬於任何服務"), "{}", with);
    }

    #[test]
    fn mismatched_session_numbers_are_stated() {
        let facts = crate::model::OriginFacts {
            loginuid: Some(0),
            sessionid: Some(4),
            cgroup: Some("/user.slice/user-0.slice/session-9.scope".into()),
            ..Default::default()
        };
        let r = render_of(&infected_with_origin(facts, vec![]));
        assert!(r.contains("登入編號比對"), "{}", r);
        assert!(
            r.contains("所屬單元是 session-9.scope，但系統記的登入編號是 4"),
            "{}",
            r
        );
    }

    fn with_evidence(ev: crate::model::ProcEvidence) -> Observation {
        let facts = crate::model::OriginFacts {
            loginuid: Some(crate::model::ID_UNSET),
            sessionid: Some(crate::model::ID_UNSET),
            cgroup: Some("/system.slice/exampled-svc.service".into()),
            unit_checked: true,
            ..Default::default()
        };
        let mut o = infected_with_origin(facts, vec![]);
        let mut ev = ev;
        ev.pid = o.origin.items[0].pid;
        o.origin.evidence = vec![ev];
        o.meta.scanner_sha256 = Some("ab".repeat(32));
        o
    }

    #[test]
    fn hidden_process_card_lists_each_view_with_raw_values() {
        let o = with_evidence(crate::model::ProcEvidence {
            uid: Some((0, 0)),
            gid: Some((0, 0)),
            tracer_pid: Some(0),
            exe_bytes: Some(1_983_716),
            exe_sha256: Some(
                "92f136731d2f8c678fd7b5f3fbd8f80fbc5ac60f9d4eccf7279f17de993caabe".into(),
            ),
            exe_info: Some(crate::model::FileInfo::Err("ENOENT".into())),
            ..Default::default()
        });
        let r = render_of(&o);
        assert!(r.contains("觀察角度"), "{}", r);
        assert!(has(&r, "問核心存在kill(編號,0)"), "{}", r);
        assert!(r.contains("cgroup 工作清單"), "{}", r);
        assert!(has(&r, "打開程式檔成功/proc/編號/exe：讀到"), "{}", r);
        assert!(r.contains("讀到 1,983,716 位元組"), "{}", r);
        assert!(
            r.contains("92f136731d2f8c678fd7b5f3fbd8f80fbc5ac60f9d4eccf7279f17de993caabe"),
            "{}",
            r
        );
        assert!(r.contains("ENOENT（上面打開並讀取卻成功）"), "{}", r);
        assert!(r.contains("帳號編號 0；群組編號 0；沒有被追蹤"), "{}", r);
        assert!(r.contains("UTC+8（開機後"), "{}", r);
    }

    #[test]
    fn card_shows_file_info_when_the_system_answers() {
        let o = with_evidence(crate::model::ProcEvidence {
            exe_bytes: Some(10),
            exe_sha256: Some("cd".repeat(32)),
            exe_info: Some(crate::model::FileInfo::Ok {
                size: 10,
                mtime: 1_773_022_830,
                ctime: 1_773_022_830,
                nlink: 1,
            }),
            ..Default::default()
        });
        let r = render_of(&o);
        assert!(
            has(&r, "大小 10；內容修改 2026-03-09 10:20:30 UTC+8；狀態變更 2026-03-09 10:20:30 UTC+8；連結數 1"),
            "{}",
            r
        );
        assert!(!r.contains("上面打開並讀取卻成功"), "{}", r);
    }

    #[test]
    fn card_without_evidence_still_lists_the_three_basic_views() {
        let facts = crate::model::OriginFacts {
            loginuid: Some(0),
            sessionid: Some(1),
            cgroup: Some("/".into()),
            ..Default::default()
        };
        let o = infected_with_origin(facts, vec![]);
        let r = render_of(&o);
        assert!(has(&r, "問核心存在kill(編號,0)"), "{}", r);
        assert!(r.contains("/proc 目錄清單"), "{}", r);
        assert!(
            !r.lines().any(|l| l.trim_start().starts_with("SHA-256")),
            "舊格式錄製檔沒有指紋，不顯示這一列"
        );
    }

    #[test]
    fn kernel_thread_card_has_no_exe_rows() {
        let o = with_evidence(Default::default());
        let r = render_of(&o);
        let kt = r
            .split("被藏的核心執行緒")
            .nth(1)
            .and_then(|t| t.split("被藏的行程").next())
            .unwrap_or("");
        assert!(kt.contains("由核心的 2 號行程啟動、沒有執行檔"), "{}", r);
        assert!(!kt.contains("SHA-256"), "{}", r);
    }

    #[test]
    fn coverage_and_fingerprint_blocks_are_present() {
        let o = with_evidence(Default::default());
        let r = render_of(&o);
        assert!(r.contains("這次檢查了什麼"), "{}", r);
        assert!(has(&r, "問核心 1 到 32768 號"), "{}", r);
        assert!(
            r.contains("掃描範圍（這次問了什麼）"),
            "附錄 B 保留原始數字：{}",
            r
        );
        assert!(r.contains("逐號問核心 1 至 32768 號"), "{}", r);
        assert!(r.contains("核對用資料（事後確認報告沒被改過）"), "{}", r);
        assert!(r.contains(&"ab".repeat(32)), "{}", r);
        assert!(r.contains("錄製檔指紋　沒有"), "測試沒給錄製檔指紋時寫沒有");
        let scope = r.find("這次檢查了什麼").expect("有檢查範圍");
        let fp = r
            .find("核對用資料（事後確認報告沒被改過）")
            .expect("有核對用資料");
        let found = r.find("每一項的說明").expect("有每一項的說明");
        assert!(scope < fp && fp < found, "{}", r);
        assert!(
            r[fp..found].contains("開始～結束"),
            "核對資料三行都在每一項的說明之前：{}",
            r
        );
        assert!(
            r.matches("核對用資料（事後確認報告沒被改過）").count() == 1,
            "只出現一次，不在報告最後重複"
        );
        assert!(
            !r.contains(crate::recording::EMBED_BEGIN),
            "沒給錄製檔全文時，報告不附錄製檔"
        );
    }

    #[test]
    fn retried_connection_evidence_is_explained_in_the_report() {
        let o = with_evidence(Default::default());
        let r = render_of(&o);
        assert!(!r.contains("共收集"), "{}", r);
        assert!(!r.contains("已重試"), "{}", r);
        let mut o2 = with_evidence(Default::default());
        o2.conn.attempts = 5;
        let r2 = render_of(&o2);
        assert!(
            has(&r2, "只湊到一類證據，共收集 5 輪（輪與輪之間隔約 1 秒）"),
            "{}",
            r2
        );
        assert!(r2.contains("連線證據收集了 5 輪"), "{}", r2);
    }

    #[test]
    fn header_lists_every_ipv4_address_with_kind_and_interface() {
        use crate::model::{LocalAddr, LocalAddrs};
        let mut o = with_evidence(Default::default());
        o.local_addrs = LocalAddrs {
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
        let r = render_of(&o);
        assert!(
            r.contains(
                "網路位址\u{3000}198.51.100.20（公開位址，網卡 eth0）\n  \u{3000}\u{3000}\u{3000}\u{3000}\u{3000}192.168.250.20（內網位址，網卡 eth0:1）\n"
            ),
            "{}",
            r
        );
        let sys = r.find("系統\u{3000}\u{3000}\u{3000}").unwrap();
        let ip = r.find("網路位址\u{3000}").unwrap();
        let when = r.find("掃描時間\u{3000}").unwrap();
        assert!(sys < ip && ip < when, "{}", r);
    }

    #[test]
    fn header_says_so_when_no_addresses_were_obtained() {
        use crate::model::LocalAddrs;
        let o = with_evidence(Default::default());
        let r = render_of(&o);
        assert!(r.contains("網路位址\u{3000}沒有取得（"), "{}", r);
        let mut o2 = with_evidence(Default::default());
        o2.local_addrs = LocalAddrs {
            ran: true,
            items: vec![],
        };
        let r2 = render_of(&o2);
        assert!(
            r2.contains("網路位址\u{3000}沒有 IPv4 位址（只有本機迴路）"),
            "{}",
            r2
        );
    }

    fn rich_obs() -> Observation {
        let mut o = with_evidence(crate::model::ProcEvidence {
            exe_bytes: Some(1_983_716),
            exe_sha256: Some("cd".repeat(32)),
            exe_info: Some(FileInfo::Err("ENOENT".into())),
            uid: Some((0, 0)),
            ..Default::default()
        });
        for smp in &mut o.proc_samples {
            for u in &mut smp.unlisted {
                if u.pid == 7655 {
                    u.exe = Some("/usr/bin/exampled-svc".into());
                }
            }
        }
        let mut link = hidden(
            "/etc/systemd/system/multi-user.target.wants/exampled-svc.service",
            'l',
        );
        link.raw.link_target = Some("/etc/systemd/system/exampled-svc.service".into());
        o.disk = crate::model::DiskScan {
            ran: true,
            devices: vec![walked_device("/", 100)],
            rounds: 3,
            candidates: 3,
            hidden: vec![
                link,
                hidden("/etc/systemd/system/exampled-svc.service", 'f'),
                hidden("/usr/bin/exampled-svc", 'f'),
            ],
            hidden_total: 3,
            ..Default::default()
        };
        o
    }

    fn body_of(r: &str) -> &str {
        &r[..r.find("附錄　技術細節（給資安人員看）").expect("有附錄")]
    }

    #[test]
    fn hidden_files_are_listed_program_then_service_file_then_boot_link() {
        let r = render_of(&rich_obs());
        let list: Vec<&str> = body_of(&r)
            .lines()
            .filter(|l| l.starts_with("  ● [") && l.contains("檔案"))
            .collect();
        assert_eq!(list.len(), 3, "{}", r);
        assert!(list[0].contains("/usr/bin/exampled-svc"), "{:?}", list);
        assert!(list[1].contains("/etc/systemd/system/"), "{:?}", list);
        assert!(!list[1].contains(".wants"), "{:?}", list);
        assert!(has(list[2], "multi-user.target.wants/"), "{:?}", list);
        assert!(has(&r, "執行的就是檔案"), "{}", r);
        assert!(has(&r, "它們是由服務設定檔"), "{}", r);
        assert!(has(&r, "是開機自動啟動的連結"), "{}", r);
        assert!(
            has(&r, "連結，指向 [") && has(&r, "讓服務開機自動啟動"),
            "{}",
            r
        );
    }

    #[test]
    fn numbers_in_the_body_and_the_appendix_point_at_the_same_things() {
        let r = render_of(&rich_obs());
        let body = body_of(&r);
        let in_body: Vec<String> = body
            .lines()
            .filter(|l| l.starts_with("  ● ["))
            .map(|l| {
                l.trim_start_matches("  ● ")
                    .split(']')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let appendix = &r[body.len()..];
        let in_appendix: Vec<String> = appendix
            .lines()
            .filter(|l| l.starts_with('[') && l.contains("] 被藏的"))
            .map(|l| l.split(']').next().unwrap().to_string())
            .collect();
        assert!(!in_body.is_empty(), "{}", r);
        assert_eq!(
            in_body, in_appendix,
            "正文的 [n] 和附錄證據表的 [n] 必須一一對應：{}",
            r
        );
        let first_file = appendix
            .lines()
            .find(|l| l.contains("] 被藏的檔案　路徑："))
            .unwrap();
        assert!(
            first_file.contains("/usr/bin/exampled-svc"),
            "{}",
            first_file
        );
    }

    #[test]
    fn body_lines_fit_a_normal_terminal_and_utc_plus_8_is_stated_once() {
        let r = render_of(&rich_obs());
        let body = body_of(&r);
        for l in body.lines() {
            if l.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 64 {
                continue;
            }
            assert!(disp_width(l) <= 66, "太寬（{} 欄）：{}", disp_width(l), l);
        }
        assert_eq!(body.matches("UTC+8").count(), 1, "{}", body);
        assert!(
            body.contains("時間\u{3000}\u{3000}\u{3000}本報告的時間都是 UTC+8"),
            "{}",
            body
        );
        assert!(
            !body.contains("台灣時間"),
            "只寫 UTC+8，不再加「台灣時間」：{}",
            body
        );
    }

    fn extreme_obs(distinct_processes: bool) -> Observation {
        let mut o = rich_obs();
        for n in 0..24u32 {
            add_twin_process(&mut o, 9000 + n, true);
        }
        if distinct_processes {
            for (i, ev) in o.origin.evidence.iter_mut().enumerate() {
                ev.exe_sha256 = Some(format!("{:064x}", i + 1));
            }
        }
        o.meta.hostname = format!("{}.example.internal", "very-long-host-name".repeat(2));
        let modname = "m".repeat(56);
        for nc in &mut o.name_checks {
            nc.name = modname.clone();
        }
        for lg in &mut o.logs {
            for ll in &mut lg.load_lines {
                ll.name = modname.clone();
            }
        }
        let long_exe = format!(
            "/opt/{}/bin/{}",
            "deeply-nested-directory/".repeat(6),
            "x".repeat(40)
        );
        let long_cmd = format!(
            "{} --config={} {}",
            long_exe,
            "y".repeat(120),
            "z ".repeat(40)
        );
        for smp in &mut o.proc_samples {
            for u in &mut smp.unlisted {
                if u.comm == "python2" {
                    u.comm = "abcdefghijklmno".into();
                    u.exe = Some(long_exe.clone());
                    u.cmdline = long_cmd.clone();
                }
                if u.exe.is_none() {
                    u.comm = "kworker/u8:99-x".into();
                }
            }
        }
        let mut files = Vec::new();
        for n in 0..40 {
            files.push(hidden(
                &format!(
                    "/srv/{}/file-{}-{}",
                    "very-long-folder-name/".repeat(5),
                    n,
                    "q".repeat(30)
                ),
                'f',
            ));
        }
        o.disk.hidden = files;
        o.disk.hidden_total = 40;
        o.disk.proc_covers = vec![crate::model::ProcCover {
            mount_point: "/proc/4321".into(),
            pid: 4321,
            fstype: "tmpfs".into(),
            source: "tmpfs".into(),
            alive: true,
        }];
        o.disk.dir_covers = vec![crate::model::DirCover {
            path: format!("/usr/lib/{}", "covered-folder-name/".repeat(4)),
            fstype: "tmpfs".into(),
            source: "tmpfs".into(),
            total: 99,
            names: vec!["a-very-long-file-name-number-one.so".into(), "b.so".into()],
        }];
        o
    }

    #[test]
    fn hostile_names_cannot_forge_lines_or_drive_the_terminal() {
        let mut o = rich_obs();
        o.meta.hostname = "host\n  結果      ○ 沒有發現被藏起來的東西".into();
        for smp in &mut o.proc_samples {
            for u in &mut smp.unlisted {
                if u.pid == 7655 {
                    u.comm = "evil\n● [99] 假的項目".into();
                    u.exe = Some("/tmp/\u{1b}[2J\u{1b}[Hfake\u{202e}gpj.exe".into());
                    u.cmdline = "run\r\n-----\n結果 ○ 沒有發現".into();
                }
            }
        }
        o.disk.hidden.push(hidden("/tmp/a\nb\u{1b}[31mred", 'f'));
        o.disk.hidden_total = 4;
        let text = crate::recording::encode(&o);
        let o = crate::recording::decode(&text).unwrap();
        let r = render_of(&o);
        for bad in ['\u{1b}', '\u{202e}', '\r', '\u{7f}'] {
            assert!(!r.contains(bad), "報告裡不能有控制字元 {:?}：{}", bad, r);
        }
        let results = r
            .lines()
            .filter(|l| l.starts_with("  結果\u{3000}"))
            .count();
        assert_eq!(results, 1, "{}", r);
        assert!(!r.lines().any(|l| l.starts_with("● [99]")), "{}", r);
        assert!(
            !r.lines().any(|l| l.trim_start().starts_with("● [99]")),
            "{}",
            r
        );
        assert!(unit_content_survives_decoding(), "多行內容要保留換行");
    }

    fn unit_content_survives_decoding() -> bool {
        let mut o = crate::model::Observation::default();
        o.origin.ran = true;
        o.origin.raw_files.push(RawFileFact {
            path: "/etc/systemd/system/x.service".into(),
            vfs_error: None,
            vfs_content: Some("[Unit]\nDescription=x\n".into()),
            vfs_content_truncated: false,
            raw: RawLookup::NotFound,
        });
        let back = crate::recording::decode(&crate::recording::encode(&o)).unwrap();
        back.origin.raw_files[0].vfs_content.as_deref() == Some("[Unit]\nDescription=x\n")
    }

    #[test]
    #[ignore]
    fn show_deleted_layout() {
        let mut pending = hacker_proc();
        pending.pid = 7600;
        pending.comm = "setup-helper".into();
        pending.argv0 = "/tmp/inst/setup-helper".into();
        pending.cmdline = "/tmp/inst/setup-helper /root/nonet.py".into();
        pending.exe_link = "/tmp/inst/setup-helper (deleted)".into();
        pending.argv0_path = pending.argv0.clone();
        pending.sockets.clear();
        let r = render_of(&deleted_obs(vec![hacker_proc(), pending]));
        println!("{}", body_of(&r));
        println!(
            "{}",
            &r[r.find("附錄").unwrap()..r.find("B　掃描範圍").unwrap()]
        );
    }

    #[test]
    #[ignore]
    fn show_extreme_layout() {
        let r = render_of(&extreme_obs(false));
        println!("{}", body_of(&r));
    }

    #[test]
    fn layout_survives_extreme_name_lengths_when_processes_are_merged() {
        check_extreme_layout(&render_of(&extreme_obs(false)));
    }

    #[test]
    fn layout_survives_extreme_name_lengths_when_every_process_has_its_own_card() {
        check_extreme_layout(&render_of(&extreme_obs(true)));
    }

    fn check_extreme_layout(r: &str) {
        let r = r.to_string();
        let body = body_of(&r);
        let mut too_wide = Vec::new();
        for l in body.lines() {
            if l.chars().filter(|c| c.is_ascii_hexdigit()).count() >= 64 {
                continue;
            }
            if disp_width(l) > 66 {
                too_wide.push(format!("{}欄：{}", disp_width(l), l));
            }
        }
        assert!(
            too_wide.is_empty(),
            "這些行超過 66 欄：\n{}",
            too_wide.join("\n")
        );
        assert!(!body.contains("程式被蓋住編號"), "{}", body);
        assert!(!body.contains("程式檔被藏編號"), "{}", body);
        let in_body: Vec<String> = body
            .lines()
            .filter(|l| l.starts_with("  ● ["))
            .map(|l| {
                l.trim_start_matches("  ● ")
                    .split(']')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let appendix = &r[body.len()..];
        let in_appendix: Vec<String> = appendix
            .lines()
            .filter(|l| l.starts_with('[') && l.contains("] 被藏的") || l.contains("] 被蓋住"))
            .map(|l| l.split(']').next().unwrap().to_string())
            .collect();
        assert_eq!(in_body, in_appendix, "{}", body);
    }

    #[test]
    fn counts_are_worded_neutrally_when_the_list_is_not_shorter() {
        let mut o = rich_obs();
        o.conn_samples = vec![crate::model::ConnSample::default(); 8];
        o.conn.inuse_ports_pass2 = (1..=148u16)
            .map(|p| PortKey {
                proto: Proto::Tcp,
                port: p,
            })
            .collect();
        o.conn.listed_ports_after = (1..=149u16)
            .map(|p| PortKey {
                proto: Proto::Tcp,
                port: p,
            })
            .collect();
        for smp in &mut o.proc_samples {
            smp.n_alive = 100;
            smp.n_listed = 100;
        }
        let r = render_of(&o);
        let body = body_of(&r);
        assert!(has(body, "148 個被占用；連線清單列出 149 個"), "{}", body);
        assert!(!has(body, "連線清單只列出"), "{}", body);
        assert!(
            has(body, "100 個還活著；/proc 的程式清單列出 100 個"),
            "{}",
            body
        );
        assert!(!has(body, "程式清單只列出"), "{}", body);
        for smp in &mut o.proc_samples {
            smp.n_listed = 98;
        }
        let r2 = render_of(&o);
        assert!(
            has(body_of(&r2), "程式清單只列出 98 個"),
            "{}",
            body_of(&r2)
        );
    }

    #[test]
    fn the_body_has_no_glossary_block_and_no_limits_section() {
        let r = render_of(&rich_obs());
        let body = body_of(&r);
        assert!(!body.contains("名詞小抄"), "{}", body);
        assert!(body.contains("檢查過，正常的項目"), "{}", body);
    }

    #[test]
    fn the_report_does_not_describe_what_the_scanner_cannot_see() {
        let mut o = deleted_obs(vec![]);
        o.disk = disk_with_skipped(1);
        o.content_scan.ran = true;
        for r in [render_of(&o), render_of(&rich_obs())] {
            for gone in [
                "這份報告查不到的地方",
                "全部限制",
                "不等於保證沒事",
                "尚未驗證",
                "還沒驗證",
                "駭客",
                "容器裡的程式",
                "放過它",
                "休息時間比這更長",
                "D　取樣數字",
            ] {
                assert!(!r.contains(gone), "報告不該出現「{}」：{}", gone, r);
            }
            assert!(r.contains("C　取樣數字與規則版本"), "{}", r);
        }
    }

    #[test]
    fn what_could_not_be_compared_this_time_is_still_said_in_the_other_notes() {
        let mut o = clean_obs();
        o.meta.is_root = false;
        o.mod_samples.truncate(1);
        let r = render_of(&o);
        let body = body_of(&r);
        let notes = &body[body.find("其他提醒").expect("有其他提醒")..];
        assert!(has(notes, "這次不是以 root 執行"), "{}", notes);
        assert!(
            has(notes, "模組目錄的穩定樣本只有 1 份"),
            "穩定樣本不足時要在其他提醒說：{}",
            notes
        );
    }

    #[test]
    fn the_pending_line_uses_a_circle_when_there_is_nothing_and_a_triangle_when_there_is() {
        let r = render_of(&clean_obs());
        assert!(
            has(body_of(&r), "○ 沒有「有跡象但還不能確定」的項目"),
            "{}",
            r
        );
        assert!(
            !has(body_of(&r), "△ 沒有「有跡象但還不能確定」的項目"),
            "{}",
            r
        );
        let mut o = clean_obs();
        o.disk = disk_with_skipped(1);
        o.disk.dir_covers.push(crate::model::DirCover {
            path: "/opt/x".into(),
            fstype: "tmpfs".into(),
            source: "tmpfs".into(),
            total: 1,
            names: vec!["secret.txt".into()],
        });
        let r2 = render_of(&o);
        assert!(
            has(body_of(&r2), "△ 另有 1 個有跡象、但還不能確定的項目"),
            "{}",
            r2
        );
    }

    #[test]
    fn every_item_card_starts_with_a_label_that_says_what_the_line_is() {
        let r = render_of(&rich_obs());
        let body = body_of(&r);
        assert!(
            !body.contains("一句話"),
            "標籤講的是長度不是內容，已改成「說明」：{}",
            body
        );
        let cards = body.matches("\n  說明\u{3000}\u{3000}\u{3000}").count();
        assert!(
            cards >= 3,
            "每一張說明都要有「說明」這一行（至少 3 張）：{}",
            body
        );
    }

    #[test]
    fn body_has_no_raw_evidence_table_jargon_but_the_appendix_keeps_it() {
        let r = render_of(&rich_obs());
        let body = body_of(&r);
        for jargon in [
            "kill(編號,0)",
            "cgroup 工作清單",
            "sched_debug",
            "fstat",
            "lstat",
            "ENOENT",
            "loginuid",
            "觀察角度",
        ] {
            assert!(
                !body.contains(jargon),
                "正文不該出現「{}」：{}",
                jargon,
                body
            );
        }
        let appendix = &r[body.len()..];
        for kept in ["kill(編號,0)", "cgroup 工作清單", "觀察角度"] {
            assert!(has(appendix, kept), "附錄要保留「{}」", kept);
        }
    }

    #[test]
    fn recording_text_is_appended_after_the_appendix_and_can_be_extracted() {
        let o = with_evidence(Default::default());
        let rec = crate::recording::encode(&o);
        let run = RunInfo {
            rec_sha256: Some(crate::sha256::hex_of(rec.as_bytes())),
            rec_text: Some(rec.clone()),
        };
        let r = render_run(&o, &run);
        let appendix = r.find("附錄　技術細節（給資安人員看）").expect("有附錄");
        let begin = r.find(crate::recording::EMBED_BEGIN).expect("有開始標記");
        assert!(appendix < begin, "錄製檔放在附錄的下方");
        assert!(
            r.ends_with(&format!("{}\n", crate::recording::EMBED_END)),
            "結束標記是報告最後一行"
        );
        let back = crate::recording::extract_embedded(&r)
            .unwrap()
            .expect("取得出來");
        assert_eq!(back, rec);
        assert!(r.contains(&format!(
            "錄製檔指紋　{}",
            crate::sha256::hex_of(back.as_bytes())
        )));
        assert_eq!(crate::recording::extract_embedded(&rec).unwrap(), None);
    }

    #[test]
    fn replaying_a_report_with_its_recording_gives_the_same_report() {
        let o = with_evidence(Default::default());
        let rec = crate::recording::encode(&o);
        let run = RunInfo {
            rec_sha256: Some(crate::sha256::hex_of(rec.as_bytes())),
            rec_text: Some(rec.clone()),
        };
        let first = render_run(&o, &run);
        let text = crate::recording::extract_embedded(&first)
            .unwrap()
            .expect("取得出來");
        let o2 = crate::recording::decode(&text).unwrap();
        let run2 = RunInfo {
            rec_sha256: Some(crate::sha256::hex_of(text.as_bytes())),
            rec_text: Some(text),
        };
        assert_eq!(render_run(&o2, &run2), first, "重播報告得到逐字相同的報告");
    }

    #[test]
    fn a_report_whose_recording_was_cut_off_is_rejected() {
        let o = with_evidence(Default::default());
        let rec = crate::recording::encode(&o);
        let run = RunInfo {
            rec_sha256: None,
            rec_text: Some(rec),
        };
        let r = render_run(&o, &run);
        let cut = r
            .trim_end()
            .strip_suffix(crate::recording::EMBED_END)
            .unwrap()
            .to_string();
        assert!(crate::recording::extract_embedded(&cut).is_err());
    }

    #[test]
    fn every_time_in_the_report_is_labelled_utc_plus_8() {
        let o = with_evidence(Default::default());
        let r = render_of(&o);
        assert!(r.contains("UTC+8"), "{}", r);
        assert!(!r.replace("UTC+8", "").contains("UTC"), "{}", r);
    }

    #[test]
    fn display_width_counts_cjk_as_two_columns() {
        assert_eq!(disp_width("abc"), 3);
        assert_eq!(disp_width("結果"), 4);
        assert_eq!(disp_width("a（b）"), 1 + 2 + 1 + 2);
        assert_eq!(pad("結果", 8).chars().count(), 2 + 4);
        assert_eq!(thousands(1_983_716), "1,983,716");
        assert_eq!(thousands(999), "999");
    }

    fn add_twin_process(o: &mut Observation, new_pid: u32, change_hash: bool) {
        let twin = {
            let first = o.proc_samples[0]
                .unlisted
                .iter()
                .find(|u| u.comm == "python2")
                .expect("樣本裡有 python2 行程")
                .clone();
            crate::model::Unlisted {
                pid: new_pid,
                starttime: first.starttime + 100,
                ..first
            }
        };
        for smp in o.proc_samples.iter_mut() {
            smp.unlisted.push(twin.clone());
        }
        let mut facts = o.origin.items[0].clone();
        facts.pid = new_pid;
        o.origin.items.push(facts);
        let mut ev = o.origin.evidence[0].clone();
        ev.pid = new_pid;
        if change_hash {
            ev.exe_sha256 = Some("ef".repeat(32));
        }
        o.origin.evidence.push(ev);
    }

    #[test]
    fn identical_processes_get_a_short_card_pointing_to_the_first() {
        let mut o = with_evidence(crate::model::ProcEvidence {
            exe_bytes: Some(10),
            exe_sha256: Some("cd".repeat(32)),
            ..Default::default()
        });
        add_twin_process(&mut o, 7700, false);
        let r = render_of(&o);
        assert!(
            r.contains("與 [3] 完全相同：執行檔（含 SHA-256）、行程身分、啟動來源"),
            "{}",
            r
        );
        assert_eq!(r.matches("與 [3] 完全相同").count(), 1, "{}", r);
        assert_eq!(r.matches("服務單元檔").count(), 1, "完整資料只列一次");
        assert_eq!(
            r.matches(&"cd".repeat(32)).count(),
            1,
            "指紋只在第一張卡出現"
        );
        assert!(r.contains("● 找到 5 個被藏起來的東西"), "{}", r);
        assert!(has(&r, "程式 python2（編號 7700）"), "{}", r);
        assert!(
            has(&r, "[3][4] 程式 python2（2 個）"),
            "正文把相同的程式合成一張：{}",
            r
        );
        assert!(
            r.contains("被藏的行程　名字：python2（編號 7700）"),
            "{}",
            r
        );
    }

    #[test]
    fn processes_with_different_executables_are_not_merged() {
        let mut o = with_evidence(crate::model::ProcEvidence {
            exe_bytes: Some(10),
            exe_sha256: Some("cd".repeat(32)),
            ..Default::default()
        });
        add_twin_process(&mut o, 7700, true);
        let r = render_of(&o);
        assert!(!r.contains("完全相同"), "{}", r);
        assert!(
            r.contains(&"ef".repeat(32)) && r.contains(&"cd".repeat(32)),
            "{}",
            r
        );
    }

    #[test]
    fn boot_time_line_is_in_the_header() {
        let o = with_evidence(Default::default());
        let r = render_of(&o);
        assert!(
            r.contains("開機時間\u{3000}1970-01-01 08:16（已連續開機"),
            "{}",
            r
        );
    }

    #[test]
    fn unused_import_guard() {
        let _ = Unlisted {
            pid: 1,
            via_kill: false,
            via_cgroup: false,
            via_sched: false,
            via_timer: false,
            starttime: 0,
            ppid: None,
            comm: String::new(),
            exe: None,
            cmdline: String::new(),
        };
    }
}
