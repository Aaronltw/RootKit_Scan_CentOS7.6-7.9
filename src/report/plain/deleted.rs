use super::super::{card, row, thousands};
use super::{
    blank_cjk, count_word, item_title, kv, pad, pad_cjk, wrap, IND, KIND_W, LABEL_W, WIDTH,
};
use crate::judge::{DeletedItem, DeletedJudgement, Disguise};
use crate::model::{DeletedProc, PathNow, ProcSocket, Proto};
use crate::timeutil::fmt_tw_sec;

pub(in crate::report) const CONFIRMED_MAX: usize = 10;
const PENDING_MAX: usize = 10;
const APPENDIX_MAX: usize = 30;
const SOCKETS_SHOWN: usize = 3;

fn when(epoch: i64) -> String {
    if epoch <= 0 {
        "不明".to_string()
    } else {
        fmt_tw_sec(epoch as u64)
    }
}

pub(in crate::report) fn dur_text(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{} 秒", s)
    } else if s < 3600 {
        format!("{} 分 {} 秒", s / 60, s % 60)
    } else if s < 86_400 {
        format!("{} 小時 {} 分", s / 3600, (s % 3600) / 60)
    } else {
        format!("{} 天 {} 小時", s / 86_400, (s % 86_400) / 3600)
    }
}

pub(in crate::report) fn name_of(p: &DeletedProc) -> String {
    if !p.comm.is_empty() {
        return p.comm.clone();
    }
    let base = p.argv0.rsplit('/').next().unwrap_or("");
    if base.is_empty() {
        "無法取得".to_string()
    } else {
        base.to_string()
    }
}

fn user_text(uid: Option<u32>) -> String {
    match uid {
        Some(0) => "root".to_string(),
        Some(n) => format!("帳號編號 {}", n),
        None => "不明身分".to_string(),
    }
}

fn endpoint(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    }
}

fn state_words(s: &ProcSocket) -> String {
    if s.proto == Proto::Udp {
        return "UDP，已指定對象".to_string();
    }
    match s.state.as_str() {
        "01" => "已連上".to_string(),
        "02" => "已送出連線請求，還沒收到回應".to_string(),
        "03" => "收到連線請求，還沒完成".to_string(),
        "04" | "05" | "09" | "0B" => "正在關閉".to_string(),
        "08" => "對方已關閉".to_string(),
        other => format!("狀態碼 {}", other),
    }
}

fn state_full(s: &ProcSocket) -> String {
    if s.proto == Proto::Udp {
        return "UDP，已指定對象".to_string();
    }
    let code = match s.state.as_str() {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0B" => "CLOSING",
        _ => return state_words(s),
    };
    format!("{}（{}）", state_words(s), code)
}

fn sock_text(s: &ProcSocket) -> String {
    format!(
        "{}本機 {} → {}",
        if s.proto == Proto::Udp { "UDP " } else { "" },
        endpoint(&s.local_ip, s.local_port),
        endpoint(&s.remote_ip, s.remote_port)
    )
}

fn shown_sockets(d: &DeletedItem) -> Vec<&ProcSocket> {
    d.public_out
        .iter()
        .chain(d.internal_out.iter())
        .take(SOCKETS_SHOWN)
        .collect()
}

fn exe_path(p: &DeletedProc) -> &str {
    p.exe_link.strip_suffix(" (deleted)").unwrap_or(&p.exe_link)
}

fn sha_text(p: &DeletedProc) -> String {
    match (&p.sha256, &p.sha_note) {
        (Some(h), _) => h.clone(),
        (None, Some(n)) => format!("沒有算出（{}）", n),
        (None, None) => "沒有算出".to_string(),
    }
}

fn clues(d: &DeletedItem) -> Vec<String> {
    let p = &d.proc;
    let mut v = vec!["檔案已經被刪掉（系統把它標成「已刪除」，檔案連結數是 0）".to_string()];
    match &p.argv0_now {
        PathNow::Missing => v.push(if p.argv0_path.starts_with('/') {
            format!("啟動指令裡的路徑 {}，現在沒有任何檔案", p.argv0_path)
        } else {
            format!(
                "啟動指令裡的程式 {}，在標準目錄（/usr/bin 等）裡找不到任何檔案",
                if p.argv0_path.is_empty() {
                    "（沒有）"
                } else {
                    &p.argv0_path
                }
            )
        }),
        PathNow::File { .. } => v.push(format!(
            "{} 現在有一個檔案，但它比這個程式更早就存在，不是用來取代它的",
            p.argv0_path
        )),
        PathNow::Other => v.push(format!("{} 現在是別的東西，不是檔案", p.argv0_path)),
        PathNow::Unknown => {
            v.push("這個程式在別的根目錄裡，沒有檢查路徑上有沒有新檔案".to_string())
        }
    }
    if let Some(s) = d.public_out.first() {
        v.push(format!(
            "有主動連到外面的網路：{}（{}）",
            endpoint(&s.remote_ip, s.remote_port),
            state_words(s)
        ));
    } else if let Some(s) = d.internal_out.first() {
        v.push(format!(
            "有主動連到內部網路：{}（{}）",
            endpoint(&s.remote_ip, s.remote_port),
            state_words(s)
        ));
    }
    if d.fast {
        if let Some(n) = d.secs_to_delete {
            v.push(format!("程式啟動後 {}，檔案就被刪掉了", dur_text(n)));
        }
    }
    for g in &d.disguise {
        v.push(match g {
            Disguise::KernelThreadName => {
                format!("程式名稱「{}」長得像核心執行緒，但它其實是一般程式", p.comm)
            }
            Disguise::NameMismatch => {
                format!("程式名稱「{}」和它的檔名對不上（名稱被改過）", p.comm)
            }
            Disguise::StagingDir(dir) => format!("程式檔原本放在暫存資料夾 {}", dir),
            Disguise::HiddenName => "程式檔的檔名以點開頭（隱藏檔）".to_string(),
        });
    }
    v
}

fn numbered(v: &[String]) -> String {
    let mut t = String::new();
    for (n, c) in v.iter().enumerate() {
        t.push_str(&format!("\n{}. {}", n + 1, c));
    }
    t
}

fn time_lines(d: &DeletedItem) -> String {
    let p = &d.proc;
    let mut t = String::new();
    match (p.crtime, &p.crtime_note) {
        (Some(c), _) => t.push_str(&format!("檔案建立　{}", when(c))),
        (None, Some(why)) => t.push_str(&format!("檔案建立　讀不到（{}）", why)),
        (None, None) => t.push_str("檔案建立　讀不到"),
    }
    t.push_str(&format!("\n最後寫入　{}", when(p.mtime)));
    t.push_str(&format!("\n程式啟動　{}", when(d.start_epoch)));
    t.push_str(&format!(
        "\n檔案刪除　{}{}",
        when(d.delete_epoch),
        match d.secs_to_delete {
            Some(n) => format!("（程式啟動後 {}）", dur_text(n)),
            None => String::new(),
        }
    ));
    if let Some(c) = p.crtime {
        if d.start_epoch > 0 && d.start_epoch - c >= 3600 {
            t.push_str(&format!(
                "\n這個檔案在程式啟動前 {} 就已經放進來了",
                dur_text(d.start_epoch - c)
            ));
        }
    }
    t
}

fn common_lines(s: &mut String, d: &DeletedItem) {
    let p = &d.proc;
    kv(
        s,
        "編號",
        &format!(
            "{}（以 {} 身分執行，由編號 {} 的程式啟動）",
            p.pid,
            user_text(p.uid),
            p.ppid
        ),
    );
    kv(
        s,
        "啟動指令",
        &if p.cmdline.is_empty() {
            "無法取得".to_string()
        } else {
            p.cmdline.clone()
        },
    );
    kv(
        s,
        "程式檔",
        &format!("原本放在 {}，{} 位元組", exe_path(p), thousands(p.size)),
    );
    if let Some(h) = &p.sha256 {
        s.push_str(&format!(
            "{}{}SHA-256 {}\n",
            IND,
            pad_cjk("指紋", LABEL_W),
            h
        ));
    } else {
        kv(s, "指紋", &format!("SHA-256 {}", sha_text(p)));
    }
    kv(s, "時間", &time_lines(d));
}

fn connection_lines(s: &mut String, d: &DeletedItem) {
    let shown = shown_sockets(d);
    for (n, sk) in shown.iter().enumerate() {
        kv(
            s,
            if n == 0 { "對外連線" } else { "" },
            &format!("{}\n狀態：{}", sock_text(sk), state_full(sk)),
        );
    }
    let total = d.public_out.len() + d.internal_out.len();
    if total > shown.len() {
        kv(
            s,
            "",
            &format!("另有 {} 條連線沒有列出，見附錄。", total - shown.len()),
        );
    }
}

const EVIDENCE_ADVICE: &str = "要保存證據，請趁程式還在執行時複製它的程式檔（在 /proc/編號/exe）；程式一結束或重新開機，這個檔案就永遠消失了。";

fn confirmed_card(s: &mut String, idx: usize, d: &DeletedItem) {
    let p = &d.proc;
    item_title(
        s,
        &format!("[{}]", idx),
        &format!("刪檔程式　{}（編號 {}）", name_of(p), p.pid),
    );
    kv(
        s,
        "說明",
        "這個程式 ps 看得到，但它的程式檔已經被刪掉，硬碟上找不到。",
    );
    common_lines(s, d);
    let c = clues(d);
    kv(
        s,
        "怎麼知道",
        &format!("{}個線索都對得上：{}", count_word(c.len()), numbered(&c)),
    );
    connection_lines(s, d);
    kv(s, "建議", EVIDENCE_ADVICE);
    s.push('\n');
}

fn pending_card(s: &mut String, d: &DeletedItem) {
    let p = &d.proc;
    s.push_str(&format!(
        "{}△ 刪檔程式　{}（編號 {}）\n",
        IND,
        name_of(p),
        p.pid
    ));
    kv(
        s,
        "說明",
        "這個程式 ps 看得到，但它的程式檔已經被刪掉，硬碟上找不到。",
    );
    common_lines(s, d);
    let c = clues(d);
    kv(s, "跡象", &format!("有這些跡象：{}", numbered(&c)));
    connection_lines(s, d);
    let why = if d.public_out.is_empty() {
        "沒有看到它主動連到外面的網路（可能正在休息，或只在本機、內部網路活動），所以先不當成確定。"
    } else {
        "它有連到外面，但檔案不是剛啟動就被刪、名字也沒有偽裝，也有可能是管理員移除軟體後舊程式還在跑，所以先不當成確定。"
    };
    kv(s, "原因", why);
    kv(s, "建議", EVIDENCE_ADVICE);
    s.push('\n');
}

pub(in crate::report) fn result_line(j: &DeletedJudgement) -> Option<String> {
    if !j.ran {
        return None;
    }
    Some(if j.confirmed.is_empty() {
        "○ 沒有「程式檔被刪掉、還在執行」的可疑程式".to_string()
    } else {
        format!(
            "● 另有 {} 個「程式檔被刪掉、還在執行」的可疑程式",
            j.confirmed.len()
        )
    })
}

pub(in crate::report) fn list_section(
    s: &mut String,
    items: &[(usize, &DeletedItem)],
    total: usize,
) {
    super::section(
        s,
        &format!("程式檔被刪掉、還在執行的可疑程式（{} 個）", total),
    );
    let indent = IND.len() + 1 + 1 + 4 + 1 + KIND_W;
    let cont = format!(
        "{}{}",
        " ".repeat(IND.len() + 1 + 1 + 4 + 1),
        blank_cjk(KIND_W)
    );
    for (idx, d) in items {
        let prefix = format!("{}● {} ", IND, pad(&format!("[{}]", idx), 4));
        let text = format!("{}（編號 {}）", name_of(&d.proc), d.proc.pid);
        for (n, l) in wrap(&text, WIDTH.saturating_sub(indent + 1))
            .iter()
            .enumerate()
        {
            if n == 0 {
                s.push_str(&format!("{}{}{}\n", prefix, pad_cjk("刪檔程式", KIND_W), l));
            } else {
                s.push_str(&format!("{}{}\n", cont, l));
            }
        }
        for sk in shown_sockets(d) {
            let t = format!(
                "連到 {}（{}）",
                endpoint(&sk.remote_ip, sk.remote_port),
                state_words(sk)
            );
            for l in wrap(&t, WIDTH.saturating_sub(indent + 1)) {
                s.push_str(&format!("{}{}\n", cont, l));
            }
        }
    }
    if total > items.len() {
        s.push_str(&format!(
            "{}另有 {} 個沒有列出（報告最多列 {} 個）。\n",
            IND,
            total - items.len(),
            items.len()
        ));
    }
    s.push('\n');
}

pub(in crate::report) fn cards(s: &mut String, items: &[(usize, &DeletedItem)]) {
    for (idx, d) in items {
        confirmed_card(s, *idx, d);
    }
}

pub(in crate::report) fn pending_cards(s: &mut String, j: &DeletedJudgement) {
    for d in j.pending.iter().take(PENDING_MAX) {
        pending_card(s, d);
    }
    if j.pending.len() > PENDING_MAX {
        s.push_str(&format!(
            "{}另有 {} 個待確認的刪檔程式沒有列出說明（見附錄）。\n\n",
            IND,
            j.pending.len() - PENDING_MAX
        ));
    }
}

pub(in crate::report) fn scope_text(j: &DeletedJudgement) -> String {
    let deleted = j.confirmed.len() + j.pending.len() + j.updated.len() + j.quiet.len();
    if deleted == 0 {
        return format!("檢查 {} 個程式，沒有程式檔被刪除", j.checked);
    }
    let mut parts = Vec::new();
    if !j.confirmed.is_empty() {
        parts.push(format!("{} 個確定可疑", j.confirmed.len()));
    }
    if !j.pending.is_empty() {
        parts.push(format!("{} 個待確認", j.pending.len()));
    }
    if !j.updated.is_empty() {
        parts.push(format!("{} 個是更新後還沒重新啟動", j.updated.len()));
    }
    if !j.quiet.is_empty() {
        parts.push(format!("{} 個沒有可疑跡象", j.quiet.len()));
    }
    format!(
        "檢查 {} 個程式，{} 個的程式檔已被刪除（{}）",
        j.checked,
        deleted,
        parts.join("、")
    )
}

fn names_list(v: &[DeletedProc]) -> String {
    let mut names: Vec<String> = Vec::new();
    for p in v {
        let n = name_of(p);
        if !names.contains(&n) {
            names.push(n);
        }
    }
    let more = names.len() > 8;
    names.truncate(8);
    format!("{}{}", names.join("、"), if more { " 等" } else { "" })
}

pub(in crate::report) fn notes(j: &DeletedJudgement) -> Vec<String> {
    let mut v = Vec::new();
    if !j.updated.is_empty() {
        v.push(format!(
            "有 {} 個程式的程式檔已經被新版檔案取代（軟體更新後還沒重新啟動），這是正常現象，不算異常；建議找時間重新啟動這些服務：{}。",
            j.updated.len(),
            names_list(&j.updated)
        ));
    }
    if !j.quiet.is_empty() {
        v.push(format!(
            "有 {} 個程式的程式檔已被刪除，但沒有可疑跡象（沒有主動連到外面、不是剛啟動就被刪、名字也正常）：{}；多半是軟體被移除後舊程式還在執行。",
            j.quiet.len(),
            names_list(&j.quiet)
        ));
    }
    if j.unsettled > 0 {
        v.push(format!(
            "有 {} 個程式的連結寫著「已刪除」，但系統說檔案其實還在別的名字底下（連結數不是 0），或問不到檔案資訊，沒有判斷。",
            j.unsettled
        ));
    }
    if j.other_ns > 0 {
        v.push(format!(
            "有 {} 個程式在別的掛載空間（例如容器）裡，這些程式看到的路徑和這台主機不同，沒有檢查它們的程式檔是否被刪。",
            j.other_ns
        ));
    }
    if j.omitted > 0 {
        v.push(format!(
            "程式檔被刪除的程式太多，只記錄了前 {} 個，另有 {} 個沒有記錄。",
            crate::collect_deleted::MAX_ITEMS,
            j.omitted
        ));
    }
    v
}

pub(in crate::report) fn ok_line(j: &DeletedJudgement) -> Option<String> {
    if !j.ran || !j.confirmed.is_empty() || !j.pending.is_empty() {
        return None;
    }
    Some(format!(
        "檢查了 {} 個程式的程式檔，沒有發現「程式檔被刪掉、還在執行」的可疑程式。",
        j.checked
    ))
}

fn path_now_text(p: &PathNow) -> String {
    match p {
        PathNow::Unknown => "沒有檢查或查不到".to_string(),
        PathNow::Missing => "沒有任何檔案".to_string(),
        PathNow::Other => "有東西，但不是一般檔案".to_string(),
        PathNow::File {
            ino, ctime, mtime, ..
        } => format!(
            "有一個一般檔案（編號 {}；變更 {} UTC+8；修改 {} UTC+8）",
            ino,
            when(*ctime),
            when(*mtime)
        ),
    }
}

pub(in crate::report) fn appendix_item(idx: Option<usize>, d: &DeletedItem) -> String {
    let p = &d.proc;
    let head = match idx {
        Some(i) => format!("[{}] 刪檔程式（確定可疑）", i),
        None => "△ 刪檔程式（待確認）".to_string(),
    };
    let mut s = format!("{}　名字：{}（編號 {}）\n", head, name_of(p), p.pid);
    let mut rows = vec![
        row("程式檔連結", "已刪除", &p.exe_link),
        row(
            "問檔案資訊（fstat）",
            if p.fstat_ok { "成功" } else { "失敗" },
            &format!(
                "編號 {}；裝置 {}；連結數 {}；大小 {} 位元組",
                p.ino,
                p.dev,
                p.nlink,
                thousands(p.size)
            ),
        ),
        row("內容指紋", "-", &format!("SHA-256 {}", sha_text(p))),
        row(
            "啟動指令",
            "-",
            if p.cmdline.is_empty() {
                "-"
            } else {
                &p.cmdline
            },
        ),
        row(
            "程式名稱／身分",
            "-",
            &format!(
                "{}；{}；父行程 {}",
                if p.comm.is_empty() { "-" } else { &p.comm },
                user_text(p.uid),
                p.ppid
            ),
        ),
        row(
            "路徑現況（啟動指令）",
            match p.argv0_now {
                PathNow::Missing => "沒有",
                PathNow::File { .. } => "有",
                _ => "-",
            },
            &format!(
                "{}：{}",
                if p.argv0_path.is_empty() {
                    "（沒有路徑）"
                } else {
                    &p.argv0_path
                },
                path_now_text(&p.argv0_now)
            ),
        ),
        row(
            "路徑現況（原本的位置）",
            "-",
            &format!("{}：{}", exe_path(p), path_now_text(&p.link_now)),
        ),
        row(
            "時間",
            "-",
            &format!(
                "建立 {}；最後寫入 {}；啟動 {}；刪除（最後變更）{}；全部 UTC+8",
                match p.crtime {
                    Some(c) => when(c),
                    None => format!("讀不到（{}）", p.crtime_note.as_deref().unwrap_or("-")),
                },
                when(p.mtime),
                when(d.start_epoch),
                when(d.delete_epoch)
            ),
        ),
    ];
    if p.sockets.is_empty() {
        rows.push(row("握著的連線", "-", "沒有"));
    }
    for (n, sk) in p.sockets.iter().enumerate() {
        rows.push(row(
            if n == 0 { "握著的連線" } else { "" },
            if sk.local_port_listening {
                "連入"
            } else {
                "連出"
            },
            &format!("{}；{}", sock_text(sk), state_full(sk)),
        ));
    }
    if p.sockets_capped {
        rows.push(row("", "-", "握著的連線太多，只記錄前面一部分"));
    }
    s.push_str(&card(&rows));
    s.push_str("    判斷依據\n");
    for (n, c) in clues(d).iter().enumerate() {
        s.push_str(&format!("        {}. {}\n", n + 1, c));
    }
    s.push_str(
        "    說明        「刪除」時間是系統記的檔案「最後變更時間」，平常就是刪除那一刻；\n",
    );
    s.push_str(
        "                如果刪除之後又對這個檔案動過手腳，這個時間只會被往後推、不會提前。\n",
    );
    s
}

pub(in crate::report) fn appendix_all(
    confirmed: &[(usize, &DeletedItem)],
    j: &DeletedJudgement,
) -> String {
    let mut s = String::new();
    let mut n = 0usize;
    for (i, d) in confirmed {
        if n >= APPENDIX_MAX {
            break;
        }
        s.push_str(&appendix_item(Some(*i), d));
        s.push('\n');
        n += 1;
    }
    for d in &j.pending {
        if n >= APPENDIX_MAX {
            break;
        }
        s.push_str(&appendix_item(None, d));
        s.push('\n');
        n += 1;
    }
    let all = confirmed.len().max(j.confirmed.len()) + j.pending.len();
    if all > n {
        s.push_str(&format!(
            "    另有 {} 個程式沒有列出證據表（最多列 {} 個）。\n\n",
            all - n,
            APPENDIX_MAX
        ));
    }
    s
}

pub(in crate::report) fn appendix_scope(j: &DeletedJudgement) -> String {
    format!(
        "檢查 {} 個有程式檔的行程（在別的掛載空間而略過 {} 個）；程式檔已刪除的：確定可疑 {}、待確認 {}、更新後還沒重新啟動 {}、沒有可疑跡象 {}、連結數不是 0 或問不到檔案資訊而不判斷 {}；超過記錄上限沒有列出 {}",
        j.checked,
        j.other_ns,
        j.confirmed.len(),
        j.pending.len(),
        j.updated.len(),
        j.quiet.len(),
        j.unsettled,
        j.omitted
    )
}

pub(in crate::report) fn appendix_rule(j: &DeletedJudgement) -> String {
    format!(
        "刪檔程式檢查：檢查 {} 個行程，確定可疑 {} 個、待確認 {} 個、更新後還沒重新啟動 {} 個、沒有可疑跡象 {} 個、不判斷 {} 個，別的掛載空間略過 {} 個\n  判定：程式檔已刪（連結數 0）、原本的路徑上沒有啟動之後才出現的新檔案，再加上「主動連到公開位址」，並且「啟動後 {} 秒內刪除」或「偽裝／可疑位置」其中一項，才算確定可疑；其餘有跡象為待確認\n",
        j.checked,
        j.confirmed.len(),
        j.pending.len(),
        j.updated.len(),
        j.quiet.len(),
        j.unsettled,
        j.other_ns,
        crate::judge::DELETED_FAST_SECS
    )
}
