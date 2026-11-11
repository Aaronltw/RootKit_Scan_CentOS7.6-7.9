use super::*;
use crate::judge::{ConnGroup, Endpoint, OriginKind};

pub(super) mod deleted;

const WIDTH: usize = 66;
const IND: &str = "  ";
const LABEL_W: usize = 10;
const RULE: usize = 60;
const KIND_W: usize = 12;

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || ".-_:/@%~+=#[]".contains(c)
}

fn is_closing_punct(c: char) -> bool {
    "，。、；：！？）」』】》,.;:!?)".contains(c)
}

pub(super) fn wrap(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    let mut starts: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        let mut j = i + 1;
        if is_word_char(c) {
            while j < chars.len() && is_word_char(chars[j]) {
                j += 1;
            }
        }
        let tok: String = chars[i..j].iter().collect();
        let tw = disp_width(&tok);
        if cur.is_empty() && tok == " " {
            i = j;
            continue;
        }
        let single_closing = tok.chars().count() == 1 && is_closing_punct(c);
        if single_closing && cur_w + tw > width {
            let mut k = starts.len();
            while k > 0 {
                let c0 = cur[starts[k - 1]..].chars().next();
                if c0.is_some_and(|ch| ch == ' ' || is_closing_punct(ch)) {
                    k -= 1;
                } else {
                    break;
                }
            }
            if k > 0 && starts[k - 1] > 0 {
                let at = starts[k - 1];
                let tail = cur[at..].to_string();
                let head = cur[..at].trim_end().to_string();
                lines.push(head);
                cur = format!("{}{}", tail, tok);
                cur_w = disp_width(&cur);
                starts = vec![0];
                i = j;
                continue;
            }
        }
        if cur_w + tw <= width || (single_closing && cur_w + tw <= width + 2) {
            starts.push(cur.len());
            cur.push_str(&tok);
            cur_w += tw;
            i = j;
            continue;
        }
        if !cur.is_empty() {
            lines.push(cur.trim_end().to_string());
            cur.clear();
            cur_w = 0;
            starts.clear();
            continue;
        }
        let tc: Vec<char> = tok.chars().collect();
        let mut start = 0usize;
        while start < tc.len() {
            let mut acc = 0usize;
            let mut fit = 0usize;
            let mut slash_at = None;
            let mut soft_at = None;
            for (k, ch) in tc[start..].iter().enumerate() {
                let w = disp_width(&ch.to_string());
                if acc + w > width {
                    break;
                }
                acc += w;
                fit = k + 1;
                if *ch == '/' {
                    slash_at = Some(k + 1);
                }
                if "-._:".contains(*ch) && k >= 3 {
                    soft_at = Some(k + 1);
                }
            }
            let take = if start + fit >= tc.len() {
                fit
            } else {
                slash_at.or(soft_at).unwrap_or(fit).max(1)
            };
            let piece: String = tc[start..start + take].iter().collect();
            start += take;
            if start >= tc.len() {
                cur = piece;
                cur_w = disp_width(&cur);
                starts = vec![0];
            } else {
                lines.push(piece);
            }
        }
        i = j;
    }
    if !cur.trim().is_empty() {
        lines.push(cur.trim_end().to_string());
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn big_title(s: &mut String, title: &str) {
    s.push_str(&"=".repeat(RULE));
    s.push('\n');
    for l in wrap(title, WIDTH - IND.len()) {
        s.push_str(&format!("{}{}\n", IND, l));
    }
    s.push_str(&"=".repeat(RULE));
    s.push('\n');
}

fn section(s: &mut String, title: &str) {
    s.push_str(&"-".repeat(RULE));
    s.push('\n');
    s.push_str(&format!("{}{}\n", IND, title));
    s.push_str(&"-".repeat(RULE));
    s.push('\n');
}

pub(super) fn pad_cjk(s: &str, width: usize) -> String {
    let need = width.saturating_sub(disp_width(s));
    format!(
        "{}{}{}",
        s,
        "\u{3000}".repeat(need / 2),
        " ".repeat(need % 2)
    )
}

pub(super) fn blank_cjk(width: usize) -> String {
    pad_cjk("", width)
}

fn kv(s: &mut String, label: &str, text: &str) {
    debug_assert!(
        disp_width(label) + 2 <= LABEL_W,
        "標籤「{}」太長，會黏住後面的字",
        label
    );
    let w = WIDTH - IND.len() - LABEL_W;
    let mut first = true;
    for para in text.split('\n') {
        for l in wrap(para, w) {
            if first {
                s.push_str(&format!("{}{}{}\n", IND, pad_cjk(label, LABEL_W), l));
                first = false;
            } else {
                s.push_str(&format!("{}{}{}\n", IND, blank_cjk(LABEL_W), l));
            }
        }
    }
}

fn para(s: &mut String, indent: usize, text: &str) {
    for l in wrap(text, WIDTH - indent) {
        s.push_str(&format!("{}{}\n", " ".repeat(indent), l));
    }
}

fn hang(s: &mut String, indent: usize, prefix: &str, text: &str) {
    let pw = disp_width(prefix);
    for (n, l) in wrap(text, WIDTH - indent - pw).iter().enumerate() {
        if n == 0 {
            s.push_str(&format!("{}{}{}\n", " ".repeat(indent), prefix, l));
        } else {
            s.push_str(&format!("{}{}{}\n", " ".repeat(indent), " ".repeat(pw), l));
        }
    }
}

fn refs(idxs: &[usize]) -> String {
    let mut sorted: Vec<usize> = idxs.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = String::new();
    let mut i = 0usize;
    while i < sorted.len() {
        let mut j = i;
        while j + 1 < sorted.len() && sorted[j + 1] == sorted[j] + 1 {
            j += 1;
        }
        if j - i + 1 >= 5 {
            out.push_str(&format!("[{}]～[{}]", sorted[i], sorted[j]));
        } else {
            for v in &sorted[i..=j] {
                out.push_str(&format!("[{}]", v));
            }
        }
        i = j + 1;
    }
    out
}

fn os_short(os: &str) -> String {
    if let Some((name, rest)) = os.split_once(" release ") {
        let ver = rest.split_whitespace().next().unwrap_or("");
        let short: Vec<&str> = ver.split('.').take(2).collect();
        let first = name.split_whitespace().next().unwrap_or(name);
        if !short.is_empty() && short.iter().all(|p| !p.is_empty()) {
            return format!("{} {}", first, short.join("."));
        }
    }
    os.to_string()
}

fn kernel_short(k: &str) -> String {
    k.strip_suffix(".x86_64").unwrap_or(k).to_string()
}

fn kb_text(kb: u64) -> String {
    if kb >= 1024 {
        format!("約 {} MB", thousands((kb + 512) / 1024))
    } else {
        format!("約 {} KB", kb)
    }
}

fn state_plain(e: &Endpoint) -> String {
    let (meaning, name) = match e.state.as_deref() {
        Some("SYN_SENT") => ("已送出連線請求，還沒收到回應", "SYN_SENT"),
        Some("ESTABLISHED") => ("已連上", "ESTABLISHED"),
        Some("SYN_RECV") => ("對方要求連線，還沒完成", "SYN_RECV"),
        Some(s @ ("FIN_WAIT" | "CLOSE_WAIT" | "LAST_ACK" | "TIME_WAIT" | "CLOSE")) => {
            ("正在結束或已結束", s)
        }
        Some(other) => return format!("狀態：{}", other),
        None => return String::new(),
    };
    let mut t = format!("狀態：{}（{}）", meaning, name);
    if e.unreplied {
        t.push_str("，對方至今沒有回應");
    }
    t
}

fn split_endpoint(b: &str) -> (String, String) {
    match b.rsplit_once(':') {
        Some((ip, port)) => (ip.to_string(), port.to_string()),
        None => (b.to_string(), String::new()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum FileRole {
    Exe,
    Unit,
    Link,
    Other,
}

pub(super) fn unit_paths(origins: &[OriginJudgement]) -> Vec<String> {
    let mut v = Vec::new();
    for o in origins {
        if let OriginKind::Service { unit } = &o.kind {
            for d in UNIT_DIRS {
                v.push(format!("{}/{}", d, unit));
            }
        }
    }
    v
}

pub(super) fn file_role(
    h: &HiddenFile,
    p: &ProcJudgement,
    origins: &[OriginJudgement],
    x: &ExeJudgement,
) -> FileRole {
    let strip = |e: &str| e.strip_suffix(" (deleted)").unwrap_or(e).to_string();
    let is_exe = p
        .confirmed
        .iter()
        .filter(|q| !q.is_kernel_thread)
        .any(|q| q.info.exe.as_deref().map(strip).as_deref() == Some(h.path.as_str()))
        || x.items.iter().any(|c| strip(&c.exe) == h.path);
    if is_exe {
        return FileRole::Exe;
    }
    let units = unit_paths(origins);
    if units.contains(&h.path) {
        return FileRole::Unit;
    }
    if h.raw.kind == 'l' {
        if let Some(t) = &h.raw.link_target {
            if units.contains(t) {
                return FileRole::Link;
            }
        }
    }
    FileRole::Other
}

fn unit_summary(content: &str) -> Option<String> {
    let get = |k: &str| -> Option<String> {
        content
            .lines()
            .filter_map(|l| l.trim().strip_prefix(k))
            .filter_map(|r| r.strip_prefix('='))
            .map(|v| v.trim().to_string())
            .next()
    };
    let exec = get("ExecStart")?;
    let mut parts = vec![match get("User") {
        Some(u) => format!("服務啟動時會以 {} 身分執行 {}", u, exec),
        None => format!("服務啟動時會執行 {}", exec),
    }];
    if get("StandardOutput").as_deref() == Some("null")
        && get("StandardError").as_deref() == Some("null")
    {
        parts.push("輸出全部丟掉".to_string());
    }
    match get("Restart").as_deref() {
        Some("no") => parts.push("不自動重啟".to_string()),
        Some(other) => parts.push(format!("掛掉時的重啟設定是 {}", other)),
        None => {}
    }
    Some(format!("{}。", parts.join("；")))
}

fn unit_file_summary(obs: &Observation, path: &str) -> Option<String> {
    let fact = raw_fact(obs, path)?;
    let content = match &fact.raw {
        RawLookup::Found(r) if r.content.is_some() => r.content.clone(),
        _ => fact.vfs_content.clone(),
    }?;
    unit_summary(&content)
}

pub(super) struct ProcGroup<'a> {
    pub idxs: Vec<usize>,
    pub members: Vec<&'a HiddenProc>,
    pub ev: Option<&'a ProcEvidence>,
    pub origin: Option<&'a OriginJudgement>,
}

pub(super) fn proc_groups<'a, 'b>(
    items: &Items<'a>,
    obs: &'b Observation,
    origins: &'b [OriginJudgement],
) -> Vec<ProcGroup<'b>>
where
    'a: 'b,
{
    let mut keys: Vec<String> = Vec::new();
    let mut groups: Vec<ProcGroup<'b>> = Vec::new();
    for (idx, h) in &items.procs {
        let ev = obs.origin.evidence.iter().find(|e| e.pid == h.info.pid);
        let origin = origins.iter().find(|o| o.pid == h.info.pid);
        let key = proc_key(h, ev, origin);
        match keys.iter().position(|k| *k == key) {
            Some(pos) => {
                groups[pos].idxs.push(*idx);
                groups[pos].members.push(*h);
            }
            None => {
                keys.push(key);
                groups.push(ProcGroup {
                    idxs: vec![*idx],
                    members: vec![*h],
                    ev,
                    origin,
                });
            }
        }
    }
    groups
}

fn holder_refs(items: &Items<'_>, holders: &[crate::judge::Holder]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut idxs: Vec<usize> = Vec::new();
    for h in holders {
        match items
            .procs
            .iter()
            .chain(items.threads.iter())
            .find(|(_, q)| q.info.pid == h.pid)
        {
            Some((i, _)) => idxs.push(*i),
            None => parts.push(format!(
                "{}（編號 {}）",
                if h.comm.is_empty() { "?" } else { &h.comm },
                h.pid
            )),
        }
    }
    idxs.sort_unstable();
    if !idxs.is_empty() {
        parts.insert(0, refs(&idxs));
    }
    parts.join("、")
}

fn gap_count(gaps: &[i64]) -> i64 {
    gaps.iter().copied().filter(|g| *g >= 1).min().unwrap_or(1)
}

fn conn_clues(c: &ConnJudgement, items: &Items<'_>, g: Option<&ConnGroup>) -> Vec<String> {
    let (tcp, udp, ports, holders): (bool, bool, Vec<PortKey>, &[crate::judge::Holder]) = match g {
        Some(g) if !g.ports.is_empty() => (
            g.ports.iter().any(|k| k.proto == Proto::Tcp),
            g.ports.iter().any(|k| k.proto == Proto::Udp),
            g.ports.clone(),
            &g.holders,
        ),
        Some(g) => (
            c.hidden_ports.iter().any(|k| k.proto == Proto::Tcp),
            c.hidden_ports.iter().any(|k| k.proto == Proto::Udp),
            c.hidden_ports.clone(),
            &g.holders,
        ),
        None => (
            c.hidden_ports.iter().any(|k| k.proto == Proto::Tcp),
            c.hidden_ports.iter().any(|k| k.proto == Proto::Udp),
            c.hidden_ports.clone(),
            &c.holders,
        ),
    };
    let no_ports = match g {
        Some(g) => g.ports.is_empty(),
        None => true,
    };
    let mut v = Vec::new();
    if c.gap_fired && (tcp || no_ports) {
        v.push(format!(
            "核心登記的連線數，比連線清單多 {} 條",
            gap_count(&c.gaps)
        ));
    }
    if c.udp_gap_fired && (udp || no_ports) {
        v.push(format!(
            "核心登記的 UDP 數量，比連線清單多 {} 個",
            gap_count(&c.udp_gaps)
        ));
    }
    if !holders.is_empty() {
        v.push(format!(
            "{} 握著{}不在清單裡的連線",
            holder_refs(items, holders),
            if holders.len() > 1 {
                "這條"
            } else {
                "一條"
            }
        ));
    }
    for proto in [Proto::Tcp, Proto::Udp] {
        let mine: Vec<String> = ports
            .iter()
            .filter(|k| k.proto == proto)
            .map(|k| k.port.to_string())
            .collect();
        if !mine.is_empty() {
            v.push(format!(
                "{}{} 號埠被占用，卻沒列在連線清單",
                if proto == Proto::Udp { "UDP " } else { "" },
                mine.join("、")
            ));
        }
    }
    v
}

fn count_word(n: usize) -> String {
    match n {
        1 => "一".into(),
        2 => "兩".into(),
        3 => "三".into(),
        4 => "四".into(),
        5 => "五".into(),
        6 => "六".into(),
        7 => "七".into(),
        8 => "八".into(),
        _ => n.to_string(),
    }
}

pub(super) fn render_plain(
    obs: &Observation,
    j: &Findings,
    run: &RunInfo,
    items: &Items<'_>,
) -> String {
    let (m, c, f) = (j.mods, j.conns, j.files);
    let meta = &obs.meta;
    let pending =
        m.unnamed_extra + usize::from(c.pending) + f.dir_covers.len() + j.deleted.pending.len();
    let mut s = String::new();

    big_title(&mut s, &format!("RootKit 掃描報告　{}", meta.hostname));
    s.push('\n');
    if items.total == 0 {
        kv(&mut s, "結果", "○ 沒有發現被藏起來的東西");
    } else {
        kv(
            &mut s,
            "結果",
            &format!("● 找到 {} 個被藏起來的東西", items.total),
        );
    }
    if let Some(l) = deleted::result_line(j.deleted) {
        kv(&mut s, "", &l);
    }
    if pending > 0 {
        kv(
            &mut s,
            "",
            &format!("△ 另有 {} 個有跡象、但還不能確定的項目（見下面）", pending),
        );
    } else {
        kv(&mut s, "", "○ 沒有「有跡象但還不能確定」的項目");
    }
    s.push('\n');
    kv(&mut s, "符號", "● 確認被藏起來了");
    kv(&mut s, "", "△ 有跡象，還不能確定");
    kv(&mut s, "", "○ 檢查過，正常");
    kv(&mut s, "時間", "本報告的時間都是 UTC+8");
    s.push('\n');

    section(&mut s, "這台機器");
    kv(&mut s, "主機名稱", &meta.hostname);
    kv(
        &mut s,
        "系統",
        &format!(
            "{}（核心 {}）",
            os_short(&meta.os),
            kernel_short(&meta.kernel)
        ),
    );
    machine_addrs(&mut s, &obs.local_addrs);
    if meta.btime > 0 {
        kv(
            &mut s,
            "開機時間",
            &format!(
                "{}（已連續開機 {:.1} 天）",
                fmt_tw(meta.btime),
                meta.uptime_s / 86_400.0
            ),
        );
    }
    kv(
        &mut s,
        "掃描時間",
        &format!(
            "{}，花了 {:.1} 秒",
            fmt_tw(meta.epoch),
            meta.elapsed_ms as f64 / 1000.0
        ),
    );
    s.push('\n');

    if items.total > 0 {
        found_list(&mut s, j, items);
        relations(&mut s, obs, j, items);
    }
    if !j.deleted.confirmed.is_empty() {
        deleted::list_section(&mut s, &items.deleted, j.deleted.confirmed.len());
    }

    scope_block(&mut s, obs, j, run);

    if items.total > 0 || !items.deleted.is_empty() {
        big_title(&mut s, "每一項的說明");
        s.push('\n');
        if items.total > 0 {
            cards(&mut s, obs, j, items);
        }
        deleted::cards(&mut s, &items.deleted);
    }

    pending_block(&mut s, obs, j, pending);
    notes_block(&mut s, obs, j);
    ok_block(&mut s, obs, j, items);
    s
}

fn machine_addrs(s: &mut String, a: &crate::model::LocalAddrs) {
    if !a.ran {
        kv(
            s,
            "網路位址",
            "沒有取得（掃描當時問不到網卡清單，或這是舊版錄製檔、沒有記錄）",
        );
        return;
    }
    if a.items.is_empty() {
        kv(s, "網路位址", "沒有 IPv4 位址（只有本機迴路）");
        return;
    }
    for (i, it) in a.items.iter().enumerate() {
        let kind = crate::collect_addr::kind_of(it.addr);
        let kind = if kind == "公開" || kind == "內網" {
            format!("{}位址", kind)
        } else {
            kind.to_string()
        };
        kv(
            s,
            if i == 0 { "網路位址" } else { "" },
            &format!("{}（{}，網卡 {}）", it.addr, kind, it.iface),
        );
    }
}

fn found_list(s: &mut String, j: &Findings, items: &Items<'_>) {
    section(s, &format!("找到的 {} 個東西", items.total));
    let mut line = |idx: usize, kind: &str, text: &str| {
        let prefix = format!("{}● {} ", IND, pad(&format!("[{}]", idx), 4));
        let kind_col = pad_cjk(kind, KIND_W);
        let indent = IND.len() + 1 + 1 + 4 + 1 + KIND_W;
        let cont = format!(
            "{}{}",
            " ".repeat(IND.len() + 1 + 1 + 4 + 1),
            blank_cjk(KIND_W)
        );
        let first_w = WIDTH.saturating_sub(indent + 1);
        let lines = wrap(text, first_w);
        for (n, l) in lines.iter().enumerate() {
            if n == 0 {
                s.push_str(&format!("{}{}{}\n", prefix, kind_col, l));
            } else {
                s.push_str(&format!("{}{}\n", cont, l));
            }
        }
    };
    for (i, m) in &items.modules {
        line(*i, "核心模組", &m.name);
    }
    for (i, h) in &items.threads {
        line(
            *i,
            "核心執行緒",
            &format!("{}（編號 {}）", name_of(h), h.info.pid),
        );
    }
    for (i, h) in &items.procs {
        line(
            *i,
            "程式",
            &format!("{}（編號 {}）", name_of(h), h.info.pid),
        );
    }
    for (i, e) in &items.exes {
        let name = if e.comm.is_empty() {
            "無法取得"
        } else {
            &e.comm
        };
        line(*i, "程式檔被藏", &format!("{}（編號 {}）", name, e.pid));
    }
    for (i, cv) in &items.covers {
        line(
            *i,
            "程式被蓋住",
            &format!("編號 {}（{}）", cv.pid, cv.mount_point),
        );
    }
    for (i, g) in &items.conns {
        line(*i, conn_kind(g), &conn_summary(g));
    }
    for (i, h) in &items.files {
        line(*i, "檔案", &h.path);
    }
    for (i, mm) in &items.contents {
        line(*i, "內容被動過", &mm.path);
    }
    if j.files.total > items.files.len() {
        s.push_str(&format!(
            "{}另有 {} 個被藏的檔案沒有列出（報告最多列 {} 個）。\n",
            IND,
            j.files.total - items.files.len(),
            items.files.len()
        ));
    }
    s.push('\n');
}

fn conn_kind(g: &ConnGroup) -> &'static str {
    if g.endpoints
        .iter()
        .any(|e| e.proto == Proto::Tcp && e.state.as_deref() == Some("SYN_SENT"))
    {
        "對外連線"
    } else {
        "網路連線"
    }
}

fn endpoint_text(e: &Endpoint) -> String {
    let local = e.a.rsplit_once(':').map_or(e.a.as_str(), |(_, p)| p);
    let arrow = if e.proto == Proto::Tcp { "→" } else { "↔" };
    let proto = if e.proto == Proto::Udp { "UDP " } else { "" };
    format!("{}本機 {} {} {}", proto, local, arrow, e.b)
}

fn conn_summary(g: &ConnGroup) -> String {
    if let Some(e) = g.endpoints.first() {
        return endpoint_text(e);
    }
    if let Some(l) = g.listeners.first() {
        return format!(
            "{}{}（{}）",
            if l.proto == Proto::Udp { "UDP " } else { "" },
            l.addr,
            if l.bound_only {
                "只綁定了，還沒連線"
            } else {
                "等著別人連進來"
            }
        );
    }
    if !g.ports.is_empty() {
        let list: Vec<String> = g
            .ports
            .iter()
            .map(|k| {
                format!(
                    "{}{}",
                    if k.proto == Proto::Udp { "UDP " } else { "" },
                    k.port
                )
            })
            .collect();
        return format!("埠 {}（遠端位址無法取得）", list.join("、"));
    }
    "遠端位址無法取得".to_string()
}

fn relations(s: &mut String, obs: &Observation, j: &Findings, items: &Items<'_>) {
    let groups = proc_groups(items, obs, j.origins);
    let mut out: Vec<String> = Vec::new();
    for g in &groups {
        let Some(exe) = g.members[0].info.exe.as_deref() else {
            continue;
        };
        let exe = exe.strip_suffix(" (deleted)").unwrap_or(exe);
        let ids = refs(&g.idxs);
        let n = g.idxs.len();
        let who = if n > 1 {
            format!("{} 這 {} 個程式", ids, n)
        } else {
            format!("{} 這個程式", ids)
        };
        let exe_idx = items
            .files
            .iter()
            .find(|(_, h)| h.path == exe)
            .map(|(i, _)| *i);
        if let Some(ei) = exe_idx {
            out.push(format!("{}，執行的就是檔案 {}", who, refs(&[ei])));
        }
        if let Some(o) = g.origin {
            if let OriginKind::Service { unit } = &o.kind {
                let unit_hit = items.files.iter().find(|(_, h)| {
                    UNIT_DIRS
                        .iter()
                        .any(|d| format!("{}/{}", d, unit) == h.path)
                });
                if let Some((ui, uh)) = unit_hit {
                    let mut t = format!("它們是由服務設定檔 {} 啟動的", refs(&[*ui]));
                    if let Some((li, _)) = items.files.iter().find(|(_, h)| {
                        h.raw.kind == 'l' && h.raw.link_target.as_deref() == Some(uh.path.as_str())
                    }) {
                        t.push_str(&format!("，{} 是開機自動啟動的連結", refs(&[*li])));
                    }
                    out.push(t);
                }
            }
        }
    }
    for (ci, g) in &items.conns {
        if g.holders.is_empty() {
            continue;
        }
        let who = holder_refs(items, &g.holders);
        out.push(if g.holders.len() > 1 {
            format!("連線 [{}] 是 {} 共用的一條連線", ci, who)
        } else {
            format!("連線 [{}] 是 {} 握著的連線", ci, who)
        });
    }
    let kernel: Vec<usize> = items
        .modules
        .iter()
        .map(|(i, _)| *i)
        .chain(items.threads.iter().map(|(i, _)| *i))
        .collect();
    for (mi, m) in &items.modules {
        if let Some((thread, diff)) = &m.born_with {
            if let Some((ti, _)) = items.threads.iter().find(|(_, h)| name_of(h) == *thread) {
                out.push(format!(
                    "[{}] 載入的時間，和 [{}] 啟動的時間只差 {} 秒",
                    mi, ti, diff
                ));
            }
        }
    }
    let others = items.total.saturating_sub(kernel.len());
    if !kernel.is_empty() && others > 0 {
        out.push(format!(
            "{} 和上面這些是不是同一個來源，這份報告判斷不出來",
            refs(&kernel)
        ));
    }
    if out.is_empty() {
        return;
    }
    s.push_str(&format!("{}看得出來的關係：\n", IND));
    for line in out {
        para(s, 4, &format!("{}。", line));
    }
    s.push('\n');
}

fn scope_block(s: &mut String, obs: &Observation, j: &Findings, run: &RunInfo) {
    let m = j.mods;
    section(s, "這次檢查了什麼");
    if let Some(l) = obs.proc_samples.last() {
        kv(
            s,
            "程式",
            &format!(
                "問核心 1 到 {} 號，{} 個還活著；/proc 的程式清單{}列出 {} 個",
                obs.meta.pid_max,
                l.n_alive,
                if l.n_alive > l.n_listed { "只" } else { "" },
                l.n_listed
            ),
        );
    }
    if let Some(l) = obs.mod_samples.last() {
        let expect = l.nl_after - 2;
        let listed = l.n_sub as i64;
        let diff = match expect - listed {
            0 => "，一致".to_string(),
            d if d > 0 => format!("，差 {} 個", d),
            d => format!("，多 {} 個", -d),
        };
        kv(
            s,
            "核心模組",
            &format!(
                "量了 {} 次：依核心的計數應有 {} 個，實際列出 {} 個{}",
                m.total, expect, listed, diff
            ),
        );
    }
    if !obs.conn_samples.is_empty() {
        let mut t = format!(
            "量了 {} 次；逐一試了 65535 個埠號，{} 個被占用；連線清單列出 {} 個",
            obs.conn_samples.len(),
            obs.conn.inuse_ports_pass2.len(),
            obs.conn.listed_ports_after.len()
        );
        if obs.conn.attempts > 1 {
            t.push_str(&format!(
                "；只湊到一個線索，共收集 {} 輪（輪與輪之間隔約 {} 秒）",
                obs.conn.attempts,
                crate::CONN_EXTRA_GAP_MS / 1000
            ));
        }
        if obs.conn.patrol_ran {
            if obs.conn.patrol_caught {
                t.push_str(&format!(
                    "；一開始沒看到被藏的連線，巡邏約 {} 秒後看到了",
                    patrol_secs(obs)
                ));
            } else {
                t.push_str(&format!(
                    "；已確認有被藏的程式卻沒看到被藏的連線，又巡邏了約 {} 秒，仍然沒看到",
                    patrol_secs(obs)
                ));
            }
        }
        kv(s, "網路連線", &t);
    }
    if !obs.logs.is_empty() {
        let parts: Vec<String> = obs
            .logs
            .iter()
            .map(|c| {
                let name = match c.source.as_str() {
                    "kmsg" => "核心訊息",
                    "messages" => "系統紀錄檔",
                    "journal" => "systemd 日誌",
                    _ => source_label(&c.source),
                };
                if !c.readable {
                    format!("{}讀不到", name)
                } else if c.source == "journal" {
                    format!("{}{}", name, kb_text(c.records))
                } else {
                    format!("{} {} 筆", name, thousands(c.records))
                }
            })
            .collect();
        kv(s, "系統紀錄", &parts.join("、"));
    }
    disk_scope(s, obs);
    if obs.content_scan.ran {
        let c = &obs.content_scan;
        let roots: Vec<&str> = c.roots.iter().take(2).map(|r| r.as_str()).collect();
        let where_ = if c.roots.len() > 2 {
            format!("{} 等 {} 個資料夾", roots.join("、"), c.roots.len())
        } else {
            format!("{} 資料夾", roots.join("、"))
        };
        let mut t = format!(
            "比對 {} 個檔案（{}，以及執行中程式的程式檔），",
            thousands(c.checked as u64),
            where_
        );
        t.push_str(&if j.contents.items.is_empty() {
            "內容都一致".to_string()
        } else {
            format!("有 {} 個內容不一致", j.contents.items.len())
        });
        let mut skip = Vec::new();
        if c.skipped_recent > 0 {
            skip.push(format!("{} 個剛改過，先不比", c.skipped_recent));
        }
        if c.skipped_big > 0 {
            skip.push(format!("{} 個太大，先不比", c.skipped_big));
        }
        if c.skipped_unreadable > 0 {
            skip.push(format!("{} 個一般方式讀不到", c.skipped_unreadable));
        }
        if !skip.is_empty() {
            t.push_str(&format!("；{}", skip.join("；")));
        }
        kv(s, "檔案內容", &t);
    }
    if obs.exe_scan.ran {
        let n = j.exes.items.len();
        kv(
            s,
            "程式檔",
            &if n == 0 {
                format!("檢查 {} 個看得到的程式，都正常", obs.exe_scan.checked)
            } else {
                format!(
                    "檢查 {} 個看得到的程式，其中 {} 個的程式檔被藏",
                    obs.exe_scan.checked, n
                )
            },
        );
    }
    if j.deleted.ran {
        kv(s, "刪檔程式", &deleted::scope_text(j.deleted));
    }
    s.push('\n');
    let mt = &obs.meta;
    s.push_str(&format!("{}核對用資料（事後確認報告沒被改過）：\n", IND));
    s.push_str(&format!(
        "    掃描器指紋　{}\n",
        mt.scanner_sha256.as_deref().unwrap_or("沒有記錄")
    ));
    s.push_str(&format!(
        "    錄製檔指紋　{}\n",
        run.rec_sha256.as_deref().unwrap_or("沒有")
    ));
    let start = fmt_tw_sec(mt.epoch);
    let end = fmt_tw_sec(mt.epoch + mt.elapsed_ms / 1000);
    let end_short = if end.split(' ').next() == start.split(' ').next() {
        end.split(' ').nth(1).unwrap_or(&end).to_string()
    } else {
        end.clone()
    };
    s.push_str(&format!("    開始～結束　{} ～ {}\n\n", start, end_short));
}

pub(super) fn fs_kinds(walked: &[(String, String)]) -> String {
    let has_ext4 = walked.iter().any(|(_, t)| t != "xfs");
    let has_xfs = walked.iter().any(|(_, t)| t == "xfs");
    match (has_ext4, has_xfs) {
        (true, true) => "ext4 和 XFS",
        (false, true) => "XFS",
        _ => "ext4",
    }
    .to_string()
}

fn disk_scope(s: &mut String, obs: &Observation) {
    if !obs.disk.ran {
        return;
    }
    let mut dirs = 0u64;
    let mut entries = 0u64;
    let mut walked: Vec<(String, String)> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
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
    let mut t = if walked.is_empty() {
        "沒有能對照的硬碟（只支援 ext4 和 XFS）".to_string()
    } else {
        format!(
            "掃了 {} 顆 {} 硬碟（{}）：{} 個資料夾、{} 個名字（檔案和資料夾）",
            walked.len(),
            fs_kinds(&walked),
            walked
                .iter()
                .map(|(m, _)| m.as_str())
                .collect::<Vec<_>>()
                .join("、"),
            thousands(dirs),
            thousands(entries)
        )
    };
    if unsettled > 0 {
        t.push_str(&format!(
            "；XFS 有 {} 個名字所在的資料夾剛被修改，這次不判斷",
            unsettled
        ));
    }
    if !skipped.is_empty() {
        t.push_str(&format!("；不能對照：{}", skipped.join("、")));
    }
    kv(s, "硬碟檔案", &t);
}

fn item_title(s: &mut String, idxs_text: &str, title: &str) {
    hang(s, 0, &format!("{} ", idxs_text), title);
    s.push_str(&"-".repeat(RULE));
    s.push('\n');
}

fn cards(s: &mut String, obs: &Observation, j: &Findings, items: &Items<'_>) {
    let (c, f) = (j.conns, j.files);
    for (i, nm) in &items.modules {
        module_card(s, *i, nm);
    }
    for (i, h) in &items.threads {
        thread_card(s, *i, h, obs);
    }
    let groups = proc_groups(items, obs, j.origins);
    for g in &groups {
        proc_card(s, g, obs);
    }
    for (i, e) in &items.exes {
        exe_card(s, *i, e);
    }
    for (i, cv) in &items.covers {
        item_title(s, &format!("[{}]", i), "被蓋住的程式");
        kv(
            s,
            "說明",
            &format!(
                "編號 {} 的程式資料夾 {} 被別的東西蓋住了，ps、top 讀不到它。",
                cv.pid, cv.mount_point
            ),
        );
        kv(
            s,
            "蓋在上面",
            &format!("{}（來源 {}）", cv.fstype, cv.source),
        );
        kv(
            s,
            "怎麼知道",
            &format!(
                "系統的掛載清單有這一筆；問核心，這個編號{}。",
                if cv.alive { "還活著" } else { "不存在" }
            ),
        );
        s.push('\n');
    }
    for (i, g) in &items.conns {
        conn_card(s, *i, g, c, items, obs);
    }
    if c.confirmed {
        shared_plain(s, c);
    }
    if !items.files.is_empty() {
        files_card(s, f, j, items, obs);
    }
    for (i, mm) in &items.contents {
        content_card(s, *i, mm);
    }
}

fn module_card(s: &mut String, i: usize, m: &NamedModule) {
    item_title(s, &format!("[{}]", i), &format!("核心模組　{}", m.name));
    kv(
        s,
        "說明",
        &format!("核心裡裝了一個叫 {} 的模組，但清單裡找不到它。", m.name),
    );
    let state = match m.initstate.as_str() {
        "live" => "「有，正在運作」".to_string(),
        "" => "「有」".to_string(),
        other => format!("「有」（狀態：{}）", other),
    };
    kv(
        s,
        "怎麼知道",
        &format!(
            "直接用名字問核心，核心說{}；可是平常列模組的兩份清單都沒有它。",
            state
        ),
    );
    let names: Vec<String> = m
        .sources
        .iter()
        .map(|x| {
            let n = match x.source.as_str() {
                "kmsg" => "核心訊息",
                "messages" => "系統紀錄檔",
                "journal" => "systemd 日誌",
                _ => "其他來源",
            };
            if x.covered {
                n.to_string()
            } else {
                format!("{}（紀錄可能不完整）", n)
            }
        })
        .collect();
    kv(
        s,
        "名字哪來",
        &if names.is_empty() {
            "沒有找到載入紀錄。".to_string()
        } else {
            format!("{}裡有它的載入紀錄。", names.join("、"))
        },
    );
    if let Some((thread, diff)) = &m.born_with {
        kv(
            s,
            "時間",
            &format!(
                "載入那一行紀錄的時間，與被藏的核心執行緒 {} 的啟動時間只差 {} 秒。",
                thread, diff
            ),
        );
    }
    let mut other: Vec<String> = Vec::new();
    match (m.taint.contains('O'), m.taint.contains('E')) {
        (true, true) => other.push("沒有簽章的外來模組".to_string()),
        (true, false) => other.push("外來模組".to_string()),
        (false, true) => other.push("沒有簽章".to_string()),
        _ => {}
    }
    if !m.text_addr.is_empty() {
        other.push(format!("位址 {}", m.text_addr));
    }
    if !other.is_empty() {
        kv(s, "補充", &other.join("；"));
    }
    s.push('\n');
}

fn thread_card(s: &mut String, i: usize, h: &HiddenProc, obs: &Observation) {
    item_title(
        s,
        &format!("[{}]", i),
        &format!("核心執行緒　{}（編號 {}）", name_of(h), h.info.pid),
    );
    kv(
        s,
        "說明",
        &format!("核心裡有一個叫 {} 的背景工作，ps 看不到它。", name_of(h)),
    );
    kv(
        s,
        "怎麼知道",
        "核心說這個編號還活著，但 /proc 的程式清單沒有它。",
    );
    kv(
        s,
        "啟動時間",
        &format!(
            "{}；由核心的 2 號程式啟動，沒有程式檔。",
            born(h, obs.meta.clk_tck)
        ),
    );
    s.push('\n');
}

fn proc_card(s: &mut String, g: &ProcGroup<'_>, obs: &Observation) {
    let n = g.idxs.len();
    let first = g.members[0];
    let name = name_of(first);
    item_title(
        s,
        &refs(&g.idxs),
        &if n > 1 {
            format!("程式　{}（{} 個）", name, n)
        } else {
            format!("程式　{}", name)
        },
    );
    kv(
        s,
        "說明",
        &if n > 1 {
            format!(
                "有 {} 個叫 {} 的程式正在執行，但 ps、top 看不到它們。",
                n, name
            )
        } else {
            format!("有一個叫 {} 的程式正在執行，但 ps、top 看不到它。", name)
        },
    );
    let pids: Vec<String> = g.members.iter().map(|h| h.info.pid.to_string()).collect();
    let who = match g.ev.and_then(|e| e.uid) {
        Some((0, 0)) => format!("（{}以 root 身分執行）", if n > 1 { "都" } else { "" }),
        Some((u, _)) => format!("（帳號編號 {}）", u),
        None => String::new(),
    };
    kv(s, "編號", &format!("{}{}", pids.join("、"), who));
    kv(
        s,
        "怎麼知道",
        &if n > 1 {
            format!("核心說這 {} 個編號還活著，但 /proc 清單沒有它們。", n)
        } else {
            "核心說這個編號還活著，但 /proc 清單沒有它。".to_string()
        },
    );
    if let Some(exe) = &first.info.exe {
        let mut t = exe.clone();
        if let Some(b) = g.ev.and_then(|e| e.exe_bytes) {
            t.push_str(&format!("（{} 位元組）", thousands(b)));
        }
        if let Some(e) = g.ev {
            match (&e.exe_open_error, &e.exe_info) {
                (Some(err), _) => t.push_str(&format!("\n這個檔案打不開（{}）。", err)),
                (None, Some(FileInfo::Err(err))) if e.exe_bytes.is_some() => {
                    if err == "ENOENT" {
                        t.push_str("\n用一般方式查這個檔案會說「不存在」，卻讀得到內容。");
                    } else {
                        t.push_str(&format!(
                            "\n用一般方式查不到這個檔案的資訊（{}），卻讀得到內容。",
                            err
                        ));
                    }
                }
                _ => {}
            }
        }
        kv(s, "程式檔", &t);
    }
    if !first.info.cmdline.is_empty() && first.info.exe.as_deref() != Some(&first.info.cmdline) {
        kv(s, "啟動指令", &first.info.cmdline);
    }
    let times: Vec<f64> = g
        .members
        .iter()
        .filter(|h| h.info.starttime > 0)
        .map(|h| h.info.starttime as f64 / obs.meta.clk_tck.max(1) as f64)
        .collect();
    let when = if times.is_empty() {
        "啟動時間無法取得".to_string()
    } else {
        let lo = times.iter().cloned().fold(f64::MAX, f64::min);
        let hi = times.iter().cloned().fold(f64::MIN, f64::max);
        if (hi - lo).abs() < 0.05 {
            format!("開機後 {:.1} 秒", lo)
        } else {
            format!("開機後 {:.1} 秒～{:.1} 秒", lo, hi)
        }
    };
    match g.origin.map(|o| &o.kind) {
        Some(OriginKind::Service { unit }) => {
            kv(s, "啟動方式", &format!("由服務 {} 啟動（{}）", unit, when));
            kv(
                s,
                "是誰啟動",
                "看不出來（是系統服務啟動的，沒有登入紀錄可查）",
            );
        }
        Some(OriginKind::Login { uid, ses }) => {
            kv(
                s,
                "啟動方式",
                &format!(
                    "從帳號編號 {} 的登入啟動（登入編號 {}；{}）。登入的細節見附錄",
                    uid,
                    ses.map_or("未設定".to_string(), |n| n.to_string()),
                    when
                ),
            );
        }
        Some(OriginKind::Neither) => {
            kv(s, "啟動方式", &format!("不明（{}）", when));
            kv(s, "是誰啟動", "看不出來（沒有登入紀錄，也不屬於任何服務）");
        }
        Some(OriginKind::Unreadable) => {
            kv(s, "啟動方式", &format!("讀不到（{}）", when));
        }
        None => kv(s, "啟動時間", &when),
    }
    s.push('\n');
}

fn exe_card(s: &mut String, i: usize, e: &crate::model::ExeContradiction) {
    let name = if e.comm.is_empty() {
        "無法取得"
    } else {
        &e.comm
    };
    item_title(
        s,
        &format!("[{}]", i),
        &format!("程式檔被藏的程式　{}（編號 {}）", name, e.pid),
    );
    kv(
        s,
        "說明",
        &format!(
            "{} 這個程式看得到，但它的程式檔被藏了：問檔案資訊說「不存在」，卻打得開、讀得到。",
            name
        ),
    );
    kv(s, "程式檔", &e.exe);
    kv(
        s,
        "怎麼知道",
        "同一個程式檔，用「打開讀取」和「問檔案資訊」兩種方式查，說法不同；有東西在攔截問檔案資訊這一條路。",
    );
    s.push('\n');
}

fn conn_card(
    s: &mut String,
    i: usize,
    g: &ConnGroup,
    c: &ConnJudgement,
    items: &Items<'_>,
    obs: &Observation,
) {
    item_title(s, &format!("[{}]", i), conn_kind(g));
    let holders = holder_refs(items, &g.holders);
    let held = if g.holders.is_empty() {
        "有一條連線被藏起來了".to_string()
    } else if g.holders.len() > 1 {
        format!("{} 共用一條連線", holders)
    } else {
        format!("{} 握著一條不在連線清單裡的連線", holders)
    };
    let tcp_ep = g
        .endpoints
        .iter()
        .find(|e| e.proto == Proto::Tcp)
        .or_else(|| g.endpoints.first());
    let sentence = match tcp_ep {
        Some(e) => {
            let (ip, port) = split_endpoint(&e.b);
            let target = if port.is_empty() {
                ip
            } else {
                format!("{} 的 {} 號埠", ip, port)
            };
            match e.state.as_deref() {
                Some("SYN_SENT") => format!(
                    "{}，正在嘗試連到 {}，{}。",
                    held,
                    target,
                    if e.unreplied {
                        "對方沒有回應"
                    } else {
                        "還沒連上"
                    }
                ),
                Some("ESTABLISHED") => format!("{}，已連到 {}。", held, target),
                _ => format!("{}，連線對象是 {}。", held, target),
            }
        }
        None => match g.listeners.first() {
            Some(l) if l.bound_only => {
                format!(
                    "{}，綁定了位址 {}，但還沒開始連線，所以沒有遠端位址。",
                    held, l.addr
                )
            }
            Some(l) => format!("{}，開著一個等別人連進來的位址 {}。", held, l.addr),
            None => format!("{}，但遠端位址無法取得。", held),
        },
    };
    kv(s, "說明", &sentence);
    for e in &g.endpoints {
        let local_full = e.a.clone();
        let line = format!(
            "{}本機 {} {} {}",
            if e.proto == Proto::Udp { "UDP " } else { "" },
            local_full,
            if e.proto == Proto::Tcp { "→" } else { "↔" },
            e.b
        );
        kv(s, "連線", &line);
        let st = state_plain(e);
        if !st.is_empty() {
            kv(s, "", &st);
        }
    }
    for l in &g.listeners {
        match l.proto {
            Proto::Tcp if l.bound_only => kv(
                s,
                "尚未連線",
                &format!(
                    "TCP {}（只綁定了埠，還沒開始連線，所以沒有遠端位址）",
                    l.addr
                ),
            ),
            Proto::Tcp => kv(
                s,
                "監聽端",
                &format!("TCP {}（等別人連進來，沒有另一端）", l.addr),
            ),
            Proto::Udp => kv(
                s,
                "收發端",
                &format!("UDP {}（沒有對特定對象連線，本來就沒有遠端位址）", l.addr),
            ),
        }
    }
    if !g.unresolved_ports.is_empty() {
        kv(
            s,
            "沒有位址",
            &format!(
                "{} 號埠的遠端位址無法取得，試過哪些辦法見附錄。",
                g.unresolved_ports
                    .iter()
                    .map(|k| k.port.to_string())
                    .collect::<Vec<_>>()
                    .join("、")
            ),
        );
    }
    let clues = conn_clues(c, items, Some(g));
    if !clues.is_empty() {
        let mut t = format!("{}個線索都對得上：", count_word(clues.len()));
        for (n, cl) in clues.iter().enumerate() {
            t.push_str(&format!("\n{}. {}", n + 1, cl));
        }
        kv(s, "怎麼知道", &t);
    }
    if obs.conn.patrol_caught {
        kv(
            s,
            "巡邏",
            &format!(
                "一開始掃描時沒看到這條連線，巡邏約 {} 秒後才看到，表示它不是一直都在（有時有、有時沒有）。",
                patrol_secs(obs)
            ),
        );
    }
    if let Some(e) = g.endpoints.first() {
        if !e.sources.is_empty() {
            kv(s, "位址來源", &sources_text(&e.sources));
        }
    }
    s.push('\n');
}

fn patrol_secs(obs: &Observation) -> u64 {
    (obs.conn.patrol_ms + 500) / 1000
}

fn shared_plain(s: &mut String, c: &ConnJudgement) {
    if c.shared_ports.is_empty() && c.shared_endpoints.is_empty() && c.shared_listeners.is_empty() {
        return;
    }
    item_title(s, "其他", "無法對應到上面哪一條連線的位址");
    for e in &c.shared_endpoints {
        kv(
            s,
            "連線",
            &format!("{}　{}", endpoint_text(e), state_plain(e)),
        );
    }
    for l in &c.shared_listeners {
        kv(s, "監聽端", &format!("{} {}", l.proto.name(), l.addr));
    }
    if !c.shared_ports.is_empty() {
        kv(
            s,
            "占用的埠",
            &c.shared_ports
                .iter()
                .map(|k| format!("{} {}", k.proto.name(), k.port))
                .collect::<Vec<_>>()
                .join("、"),
        );
    }
    s.push('\n');
}

fn files_card(
    s: &mut String,
    f: &FileJudgement,
    j: &Findings,
    items: &Items<'_>,
    obs: &Observation,
) {
    let idxs: Vec<usize> = items.files.iter().map(|(i, _)| *i).collect();
    item_title(
        s,
        &refs(&idxs),
        &format!("被藏起來的檔案（{} 個）", f.total.max(items.files.len())),
    );
    para(
        s,
        2,
        &if items.files.len() > 1 {
            format!(
                "這 {} 個檔案確實在硬碟上，但用 ls 列資料夾時看不到：",
                items.files.len()
            )
        } else {
            "這個檔案確實在硬碟上，但用 ls 列資料夾時看不到：".to_string()
        },
    );
    for (i, h) in &items.files {
        hang(s, 2, &format!("[{}] ", i), &h.path);
        let role = file_role(h, j.procs, j.origins, j.exes);
        let mut d: Vec<String> = Vec::new();
        match h.raw.kind {
            'l' => {
                let target = h.raw.link_target.clone().unwrap_or_default();
                let target_text = items
                    .files
                    .iter()
                    .find(|(_, x)| x.path == target)
                    .map(|(ti, _)| refs(&[*ti]))
                    .unwrap_or(target);
                let mut t = format!("連結，指向 {}", target_text);
                if h.path.contains(".wants/") {
                    t.push_str("，讓服務開機自動啟動");
                }
                d.push(t);
            }
            'd' => {
                d.push(format!("資料夾，裡面有 {} 個名字", h.children_total));
            }
            _ => {
                d.push(
                    match role {
                        FileRole::Exe => "程式檔",
                        FileRole::Unit => "服務設定檔",
                        _ => "檔案",
                    }
                    .to_string(),
                );
                d.push(format!("{} 位元組", thousands(h.raw.size)));
            }
        }
        if let Some(t) = h.raw.crtime {
            d.push(format!("建立於 {}", fmt_tw(t.max(0) as u64)));
        }
        para(s, 6, &d.join("，"));
        if role == FileRole::Unit {
            if let Some(t) = unit_file_summary(obs, &h.path) {
                para(
                    s,
                    6,
                    &format!("內容：{}（完整內容見附錄）", t.trim_end_matches('。')),
                );
            }
        }
    }
    if f.total > items.files.len() {
        para(
            s,
            2,
            &format!(
                "另有 {} 個被藏的檔案沒有列出（報告最多列 {} 個）。",
                f.total - items.files.len(),
                items.files.len()
            ),
        );
    }
    s.push('\n');
}

fn content_card(s: &mut String, i: usize, m: &crate::model::ContentMismatch) {
    item_title(s, &format!("[{}]", i), "內容被動過的檔案");
    kv(s, "檔案", &m.path);
    kv(
        s,
        "說明",
        "同一個檔案，一般方式讀到的內容，和直接讀硬碟看到的不一樣。",
    );
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
    kv(s, "差異", &diff);
    kv(
        s,
        "怎麼知道",
        &format!(
            "重驗 {} 輪，兩邊的內容都沒變；代表有東西在讀取的路徑上動了手腳。報告不顯示檔案內容。",
            crate::collect_content::RECHECK_ROUNDS
        ),
    );
    s.push('\n');
}

fn clue_plain(c: &ConnJudgement, items: &Items<'_>) -> Vec<String> {
    conn_clues(c, items, None)
}

fn pending_block(s: &mut String, obs: &Observation, j: &Findings, pending: usize) {
    let (m, c, f) = (j.mods, j.conns, j.files);
    if pending == 0 {
        section(s, "有跡象但還不能確定的項目：沒有");
        s.push('\n');
        return;
    }
    section(s, &format!("有跡象但還不能確定的項目（{} 個）", pending));
    if m.unnamed_extra > 0 {
        s.push_str(&format!("{}△ 核心模組（名字拿不到）\n", IND));
        kv(
            s,
            "跡象",
            &format!(
                "模組目錄的計數比列出來的多 {} 個，其中 {} 個找不到名字。",
                m.gap.unwrap_or(0),
                m.unnamed_extra
            ),
        );
        kv(
            s,
            "原因",
            "這兩個數字出自核心同一份資料，對方如果連計數也改，這個證據就失效；要確定需要名字，再用名字獨立確認一次，但這次沒有找到名字。",
        );
        s.push('\n');
    }
    if c.pending {
        let empty = Items::empty();
        let clues = clue_plain(c, &empty);
        s.push_str(&format!("{}△ 網路連線\n", IND));
        kv(s, "跡象", &format!("只有一個線索：{}。", clues.join("；")));
        kv(
            s,
            "原因",
            "要確定需要兩個以上互相獨立的線索（連線總數對不上、有程式握著清單裡沒有的連線、有埠號被占用卻沒列在清單）。這次只成立一個，可能是掃描當下剛好有連線進出，所以先不當成確定。",
        );
        if obs.conn.attempts > 1 {
            kv(
                s,
                "已重試",
                &format!(
                    "連線證據共收集了 {} 輪（輪與輪之間隔約 {} 秒），每一輪都只有一個線索；可能是被藏的連線只在很短的時間存在。建議隔一段時間再掃一次。",
                    obs.conn.attempts,
                    crate::CONN_EXTRA_GAP_MS / 1000
                ),
            );
        }
        if obs.conn.patrol_ran && !obs.conn.patrol_caught {
            kv(
                s,
                "已巡邏",
                &format!(
                    "已確認有被藏的程式，之後又巡邏了約 {} 秒，這個線索一直沒能搭配到第二個線索。",
                    patrol_secs(obs)
                ),
            );
        }
        s.push('\n');
    }
    for d in &f.dir_covers {
        s.push_str(&format!("{}△ 被蓋住的資料夾\n", IND));
        kv(s, "資料夾", &d.path);
        kv(
            s,
            "跡象",
            &format!(
                "蓋在上面的是 {}（來源 {}）；硬碟上這個資料夾裡原本有 {} 個名字（前幾個：{}{}）。",
                d.fstype,
                d.source,
                d.total,
                d.names.join("、"),
                if d.total > d.names.len() { "…" } else { "" }
            ),
        );
        kv(
            s,
            "原因",
            "掛載點底下正常是空的（裝置檔、具名管道、通訊端除外），有東西代表被上面的掛載蓋住了；但管理員也可能不小心把硬碟掛在有檔案的資料夾上，所以先不當成確定。",
        );
        s.push('\n');
    }
    deleted::pending_cards(s, j.deleted);
}

fn notes_block(s: &mut String, obs: &Observation, j: &Findings) {
    let mut notes: Vec<String> = j.mods.notes.clone();
    notes.extend(disk_notes(obs, j.files));
    notes.extend(deleted::notes(j.deleted));
    if !obs.conn_samples.is_empty() && j.conns.udp_stable < 3 {
        notes.push(format!(
            "UDP 連線的穩定樣本只有 {} 份（共 {} 份），不足 3 份，UDP 數量比對沒有結果。",
            j.conns.udp_stable, j.conns.udp_total
        ));
    }
    if j.mods.stable < 3 {
        notes.push(format!(
            "模組目錄的穩定樣本只有 {} 份（共 {} 份），不足 3 份，模組數量比對沒有結果。",
            j.mods.stable, j.mods.total
        ));
    }
    if !obs.meta.is_root {
        notes.push(
            "這次不是以 root 執行：部分程式的資料讀不到，名字可能顯示為「無法取得」。".to_string(),
        );
    }
    let notes: Vec<String> = notes.iter().map(|n| n.replace(" UTC+8", "")).collect();
    section(s, "其他提醒");
    if notes.is_empty() {
        para(s, 2, "沒有。");
    } else {
        for n in &notes {
            let w = WIDTH - 4;
            for (k, l) in wrap(n, w).iter().enumerate() {
                if k == 0 {
                    s.push_str(&format!("{}- {}\n", IND, l));
                } else {
                    s.push_str(&format!("{}  {}\n", IND, l));
                }
            }
        }
    }
    s.push('\n');
}

fn ok_block(s: &mut String, obs: &Observation, j: &Findings, items: &Items<'_>) {
    let (p, m, c, f, x, ct) = (j.procs, j.mods, j.conns, j.files, j.exes, j.contents);
    section(s, "檢查過，正常的項目");
    let mut lines: Vec<String> = Vec::new();
    if let Some(last) = obs.proc_samples.last() {
        lines.push(if last.n_alive == last.n_listed {
            format!(
                "核心說有 {} 個程式，/proc 清單也列出 {} 個，兩邊完全相同。",
                last.n_alive, last.n_listed
            )
        } else if last.n_alive > last.n_listed {
            let d = last.n_alive - last.n_listed;
            let found: Vec<usize> = items
                .threads
                .iter()
                .chain(items.procs.iter())
                .map(|(i, _)| *i)
                .collect();
            if d == found.len() && !found.is_empty() {
                let mut ids = found.clone();
                ids.sort_unstable();
                format!(
                    "核心說有 {} 個程式，/proc 清單只列出 {} 個，少的 {} 個就是上面 {}。",
                    last.n_alive,
                    last.n_listed,
                    d,
                    refs(&ids)
                )
            } else {
                format!(
                    "核心說有 {} 個程式，/proc 清單只列出 {} 個，少的 {} 個就是上面找到的。",
                    last.n_alive, last.n_listed, d
                )
            }
        } else {
            format!(
                "核心說有 {} 個程式，/proc 清單列出 {} 個；清單比較多，是掃描當下有程式剛結束，屬正常。",
                last.n_alive, last.n_listed
            )
        });
    }
    if p.transient > 0 {
        lines.push(format!(
            "掃描期間出現又馬上消失的暫時編號 {} 個（沒有連續兩次都出現）：判斷為正常的短命程式。",
            p.transient
        ));
    }
    if m.gap.is_none() {
        if let Some(l) = obs.mod_samples.iter().rev().find(|x| x.vanished == 0) {
            lines.push(format!(
                "模組目錄的計數與列出的個數相同（{} 個），沒有被藏的模組目錄。",
                l.n_sub
            ));
        }
    }
    if !c.confirmed && !c.pending {
        if let Some(l) = obs.conn_samples.last() {
            lines.push(format!(
                "連線總數和連線清單一致（TCP：IPv4 {} 個、IPv6 {} 個；UDP {} 個），沒有被占用卻沒列出的埠號。",
                l.e4 + l.w4 + l.y4,
                l.e6 + l.w6 + l.y6,
                l.ru4 + l.rl4 + l.ru6 + l.rl6
            ));
        }
    }
    if obs.disk.ran && f.proc_covers.is_empty() {
        lines.push("沒有東西蓋在 /proc 的程式資料夾上。".to_string());
    }
    if f.devices_walked > 0 && f.skipped_mounts > 0 && f.dir_covers.is_empty() {
        lines.push(format!(
            "{} 個掛了別的裝置的資料夾，底下原本都是空的（裝置檔、具名管道、通訊端除外）。",
            f.skipped_mounts
        ));
    }
    if obs.content_scan.ran && ct.items.is_empty() && obs.content_scan.checked > 0 {
        lines.push(format!(
            "{} 個檔案，兩種讀法讀到的內容完全一致。",
            thousands(obs.content_scan.checked as u64)
        ));
    }
    if obs.exe_scan.ran && x.items.is_empty() {
        lines.push(format!(
            "看得到的 {} 個程式，程式檔都正常。",
            obs.exe_scan.checked
        ));
    }
    if let Some(l) = deleted::ok_line(j.deleted) {
        lines.push(l);
    }
    if f.devices_walked > 0 && f.total == 0 && f.devices_truncated == 0 {
        lines.push(format!(
            "硬碟上的資料夾清單，和檔案系統列出的一致：走訪 {} 個資料夾，沒有只在硬碟上有的名字。",
            thousands(f.dirs_walked)
        ));
    }
    if lines.is_empty() {
        para(s, 2, "沒有。");
    }
    for l in &lines {
        for (k, t) in wrap(l, WIDTH - 6).iter().enumerate() {
            if k == 0 {
                s.push_str(&format!("{}○ {}\n", IND, t));
            } else {
                s.push_str(&format!("{}  {}\n", IND, t));
            }
        }
    }
    s.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chinese_text_wraps_by_display_width_and_keeps_closing_punctuation_off_the_line_start() {
        assert_eq!(
            wrap("一二三四五六七八九十", 6),
            vec!["一二三", "四五六", "七八九", "十"]
        );
        let lines = wrap("甲乙丙丁，戊己", 8);
        assert_eq!(lines, vec!["甲乙丙", "丁，戊己"]);
        assert!(lines.iter().all(|l| !l.starts_with('，')), "{:?}", lines);
        assert_eq!(wrap("", 10), vec![String::new()]);
    }

    #[test]
    fn closing_brackets_and_full_stops_never_start_a_line_or_overflow() {
        for width in [24, 30, 36, 41, 52] {
            for text in [
                "從帳號編號 0 的登入啟動（登入編號 1；開機後 63.7 秒）。登入的細節見附錄",
                "狀態：已送出連線請求，還沒收到回應（SYN_SENT），對方至今沒有回應",
                "系統紀錄檔：沒有開機訊息，紀錄最早只到 2026-03-03 18:45:41，比本次開機（2026-03-01 08:00:00）還晚。",
            ] {
                let lines = wrap(text, width);
                for l in &lines {
                    assert!(disp_width(l) <= width, "寬度 {}：{:?}", width, l);
                    let first = l.chars().next().unwrap();
                    assert!(!is_closing_punct(first), "標點在行首：{:?}", l);
                }
                let joined: String = lines.concat();
                let strip = |t: &str| t.chars().filter(|c| !c.is_whitespace()).collect::<String>();
                assert_eq!(strip(&joined), strip(text), "寬度 {}", width);
            }
        }
    }

    #[test]
    fn long_paths_break_after_a_slash_and_words_are_not_split() {
        let l = wrap(
            "/etc/systemd/system/multi-user.target.wants/exampled-svc.service",
            45,
        );
        assert_eq!(
            l,
            vec![
                "/etc/systemd/system/multi-user.target.wants/",
                "exampled-svc.service"
            ]
        );
        let l = wrap("核心 3.10.0-1160.119.1.el7 版本", 24);
        assert!(
            l.iter().any(|x| x.contains("3.10.0-1160.119.1.el7")),
            "{:?}",
            l
        );
        for x in wrap(&"a".repeat(100), 30) {
            assert!(disp_width(&x) <= 30, "{}", x);
        }
    }

    #[test]
    fn labels_and_values_line_up_and_long_values_hang_under_the_value() {
        let mut s = String::new();
        kv(
            &mut s,
            "怎麼知道",
            "直接用名字問核心，核心說有；可是平常列模組的兩份清單都沒有它，這一句很長所以一定會折行。",
        );
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines.len() >= 2, "{}", s);
        assert!(lines[0].starts_with("  怎麼知道\u{3000}"), "{}", s);
        assert!(!lines[0].starts_with("  怎麼知道  "), "{}", s);
        for l in &lines[1..] {
            assert!(l.starts_with(&format!("  {}", blank_cjk(LABEL_W))), "{}", s);
            assert!(
                l.starts_with("  \u{3000}\u{3000}\u{3000}\u{3000}\u{3000}"),
                "{}",
                s
            );
        }
        assert!(lines.iter().all(|l| disp_width(l) <= WIDTH), "{}", s);
    }

    #[test]
    fn labels_are_padded_with_full_width_spaces_so_every_font_aligns_them() {
        assert_eq!(pad_cjk("結果", 10), "結果\u{3000}\u{3000}\u{3000}");
        assert_eq!(pad_cjk("刪檔程式", 10), "刪檔程式\u{3000}");
        assert_eq!(pad_cjk("", 10), "\u{3000}".repeat(5));
        assert_eq!(blank_cjk(12), "\u{3000}".repeat(6));
        assert_eq!(pad_cjk("SHA", 10), "SHA\u{3000}\u{3000}\u{3000} ");
        for l in [
            "結果",
            "程式",
            "核心模組",
            "網路連線",
            "刪檔程式",
            "怎麼知道",
        ] {
            assert_eq!(disp_width(&pad_cjk(l, 10)), 10, "{}", l);
        }
        for k in [
            "核心模組",
            "核心執行緒",
            "程式",
            "檔案",
            "對外連線",
            "程式檔被藏",
            "程式被蓋住",
            "內容被動過",
        ] {
            let c = pad_cjk(k, KIND_W);
            assert_eq!(disp_width(&c), KIND_W, "{}", k);
            assert!(!c.contains("  "), "{:?}", c);
        }
    }

    #[test]
    fn os_and_kernel_are_shortened_but_unknown_text_is_kept() {
        assert_eq!(
            os_short("CentOS Linux release 7.9.2009 (Core)"),
            "CentOS 7.9"
        );
        assert_eq!(os_short("CentOS release 6.10 (Final)"), "CentOS 6.10");
        assert_eq!(os_short("Some Other OS"), "Some Other OS");
        assert_eq!(
            kernel_short("3.10.0-1160.119.1.el7.x86_64"),
            "3.10.0-1160.119.1.el7"
        );
    }

    #[test]
    fn journal_size_is_in_kilobytes_not_records() {
        assert_eq!(kb_text(50_752), "約 50 MB");
        assert_eq!(kb_text(900), "約 900 KB");
        assert_eq!(kb_text(1_536), "約 2 MB");
    }

    #[test]
    fn unit_file_is_summarised_only_with_what_it_really_says() {
        let c = "[Unit]\nDescription=x\n[Service]\nUser=root\nType=simple\nExecStart=/usr/bin/exampled-svc -x \nRestart=no\nNice=5\nStandardOutput=null\nStandardError=null\n[Install]\nWantedBy=multi-user.target\n";
        assert_eq!(
            unit_summary(c).unwrap(),
            "服務啟動時會以 root 身分執行 /usr/bin/exampled-svc -x；輸出全部丟掉；不自動重啟。"
        );
        let c2 = "[Service]\nExecStartPre=/bin/true\nExecStart=/opt/a\nStandardOutput=null\nRestart=always\n";
        assert_eq!(
            unit_summary(c2).unwrap(),
            "服務啟動時會執行 /opt/a；掛掉時的重啟設定是 always。"
        );
        assert!(unit_summary("[Service]\nUser=root\n").is_none());
        assert!(unit_summary("[Service]\nExecStartPre=/bin/true\n").is_none());
    }

    #[test]
    fn closed_connection_states_are_explained_in_plain_words() {
        let e = Endpoint {
            proto: Proto::Tcp,
            a: "1.2.3.4:5".into(),
            b: "6.7.8.9:10".into(),
            sources: vec![],
            state: Some("SYN_SENT".into()),
            unreplied: true,
        };
        assert_eq!(
            state_plain(&e),
            "狀態：已送出連線請求，還沒收到回應（SYN_SENT），對方至今沒有回應"
        );
        let e2 = Endpoint {
            state: Some("ESTABLISHED".into()),
            unreplied: false,
            ..e.clone()
        };
        assert_eq!(state_plain(&e2), "狀態：已連上（ESTABLISHED）");
        assert_eq!(state_plain(&Endpoint { state: None, ..e }), "");
        assert_eq!(
            split_endpoint("198.51.100.200:18443"),
            ("198.51.100.200".to_string(), "18443".to_string())
        );
    }
}
