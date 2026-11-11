mod collect;
mod collect_addr;
mod collect_conn;
mod collect_content;
mod collect_deleted;
mod collect_disk;
mod collect_exe;
mod collect_origin;
mod crypto;
mod judge;
mod model;
mod mounts;
mod rawfs;
#[cfg(test)]
mod rawfs_fixture;
mod recording;
mod report;
mod sha256;
mod support;
mod timeutil;

use std::collections::HashSet;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MOD_SAMPLES: usize = 10;
const MOD_GAP_MS: u64 = 30;
const CONN_SAMPLES: usize = 8;
const CONN_GAP_MS: u64 = 50;
const RECHECK_ROUNDS: u32 = 4;
const RECHECK_GAP_MS: u64 = 100;
pub const CONN_EXTRA_ATTEMPTS: u32 = 4;
pub const CONN_EXTRA_GAP_MS: u64 = 1000;
pub const DEFAULT_WATCH_SECS: u32 = 150;
const MAX_WATCH_SECS: u32 = 3600;
const _: () = assert!(DEFAULT_WATCH_SECS <= MAX_WATCH_SECS);
const PATROL_GAP_MS: u64 = 500;
const PATROL_MAX_GAP_MS: u64 = 3000;
const PATROL_COST_FACTOR: u32 = 100;
const PATROL_ROUND_SPACING_MS: u64 = 5000;
const PATROL_MAX_ROUNDS: u32 = 6;
const MAX_VISIBLE_QUERIES: usize = 64;
const CAPTURE_SECS: u32 = 4;
const QUERY_RETRY_MS: u64 = 1200;
const QUERY_WAIT_NEW_MS: u64 = 12_000;
const QUERY_RECHECK_MS: u64 = 300;
const DIAL_CONNTRACK_GAP_MS: u64 = 200;
const DIAL_CONNTRACK_WAIT_MS: u64 = 3_000;
const QUERY_RETRY_GAP_MS: u64 = 100;

const USAGE: &str = "用法：rootkit-scan [選項]
  不加任何選項：掃描這台機器，把報告存成 rootkit-scan 所在資料夾裡的檔案 report-主機名稱-日期時間.txt（螢幕只印「掃描完成。」）。
                  打包時有帶入公鑰的版本（報告會加密、存成 .enc）還會多做兩件事：存好報告之後，把 rootkit-scan 這個檔案自己
                  從這台機器刪掉，並把報告從程式的工作記憶體裡塗成 0（盡力而為），再結束，被掃描的機器上只留下加密的報告。
                  刪不掉自己時只印一行提醒。
                  另外，這種版本在一開始（讀任何資料之前）會請系統「這支程式萬一崩潰時，不要把它的記憶體存成檔案」，
                  免得崩潰留下的檔案裡有報告明文；這同樣擋不住正在即時盯著記憶體的人，也不防記憶體被換到磁碟。
                  限制：這只是不留下檔案，擋不住正在即時盯著這台機器的人（程式執行的這段時間，它還是看得到的）；
                  刪掉之後如果還要再掃，得重新把檔案複製過去。沒帶入公鑰的版本（開發測試用）不會刪自己，也不塗記憶體。
  --record 檔案   把這次讀到的原始資料另存成檔案（報告最後本來就附有同樣的內容）
  --replay 檔案   不碰系統，改讀錄好的檔案（錄製檔，或最後附有錄製檔的報告），重做判斷與報告；報告印在螢幕上
  --watch 秒數    已確認有被藏程式、卻沒看到被藏連線時，最多再巡邏幾秒（預設 150；0 表示不巡邏）
  --genkey        產生一對新金鑰（在你自己的電腦上做一次）：公鑰印在螢幕上（交給打包的人），
                  私鑰寫到檔案（--out 指定路徑，預設 rootkit-scan-private.key）。私鑰請收好，
                  只有它能解密，絕不要放到被掃描的主機。
  --decrypt 檔案  解開加密的報告：用 --key 指定你的私鑰檔，報告印在螢幕上（或用 --out 寫到檔案）。
  --key 檔案      解密時指定私鑰檔
  --out 檔案      --genkey 時指定私鑰輸出路徑；--decrypt 時指定報告輸出路徑
  --samples N     行程取樣份數（預設 3，至少 2）
  --gap-ms 毫秒   兩份取樣之間的間隔（預設 300）
  --content-root 資料夾
                  追加一個要比對檔案內容的資料夾（可以重複；預設已經包含 /etc、/root 等）
  --version       顯示版本
  --help          顯示這段說明
不是 root 時什麼都不讀、不寫，只印一句「請以root權限執行」。程式沒有結束碼，結果看報告。";

struct Args {
    content_roots: Vec<String>,
    record: Option<String>,
    replay: Option<String>,
    samples: usize,
    gap_ms: u64,
    watch_secs: u32,
    genkey: bool,
    decrypt: Option<String>,
    key: Option<String>,
    out: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        content_roots: Vec::new(),
        record: None,
        replay: None,
        samples: 3,
        gap_ms: 300,
        watch_secs: DEFAULT_WATCH_SECS,
        genkey: false,
        decrypt: None,
        key: None,
        out: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{} 後面要接值", name));
        match arg.as_str() {
            "--record" => a.record = Some(value("--record")?),
            "--replay" => a.replay = Some(value("--replay")?),
            "--genkey" => a.genkey = true,
            "--decrypt" => a.decrypt = Some(value("--decrypt")?),
            "--key" => a.key = Some(value("--key")?),
            "--out" => a.out = Some(value("--out")?),
            "--content-root" => a.content_roots.push(value("--content-root")?),
            "--samples" => {
                a.samples = value("--samples")?
                    .parse()
                    .map_err(|_| "--samples 要接整數".to_string())?
            }
            "--watch" => {
                a.watch_secs = value("--watch")?
                    .parse()
                    .map_err(|_| "--watch 要接整數（秒）".to_string())?
            }
            "--gap-ms" => {
                a.gap_ms = value("--gap-ms")?
                    .parse()
                    .map_err(|_| "--gap-ms 要接整數".to_string())?
            }
            "--version" => {
                println!("rootkit-scan {}", VERSION);
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!("{}", USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("不認得的選項 {}\n{}", other, USAGE)),
        }
    }
    if a.samples < 2 {
        return Err("--samples 至少要 2：判定需要連續兩份樣本".into());
    }
    if a.watch_secs > MAX_WATCH_SECS {
        return Err(format!("--watch 最多 {} 秒", MAX_WATCH_SECS));
    }
    if a.record.is_some() && a.replay.is_some() {
        return Err("--record 與 --replay 不能一起用".into());
    }
    if a.genkey && a.decrypt.is_some() {
        return Err("--genkey 與 --decrypt 不能一起用".into());
    }
    Ok(a)
}

fn query_hidden_holders(conn: &mut model::ConnFacts) {
    use std::collections::{BTreeMap, BTreeSet};
    let local_addrs = collect_conn::local_ipv4_addrs();
    let pids: BTreeSet<u32> = conn
        .held
        .iter()
        .filter(|h| h.exe.is_some())
        .map(|h| h.pid)
        .collect();
    let mut groups: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for pid in pids {
        groups
            .entry(collect_conn::tgid_of(pid).unwrap_or(pid))
            .or_default()
            .push(pid);
    }
    for members in groups.into_values() {
        let pid = members[0];
        let first_new = conn.peer_queries.len();
        let mut answered: BTreeMap<u64, (usize, Instant)> = BTreeMap::new();
        let deadline = Instant::now() + Duration::from_millis(QUERY_RETRY_MS);
        let wait_deadline = Instant::now() + Duration::from_millis(QUERY_WAIT_NEW_MS);
        loop {
            let fresh: Vec<model::HeldSocket> = collect_conn::held_sockets(&[pid])
                .into_iter()
                .filter(|h| h.exe.is_some())
                .collect();
            for h in &fresh {
                if !conn
                    .held
                    .iter()
                    .any(|x| x.pid == h.pid && x.fd == h.fd && x.inode == h.inode)
                {
                    conn.held.push(h.clone());
                }
            }
            let todo: Vec<&model::HeldSocket> = fresh
                .iter()
                .filter(|h| match answered.get(&h.inode) {
                    None => true,
                    Some((idx, when)) => {
                        conn.peer_queries[*idx].state == Some(7)
                            && when.elapsed() >= Duration::from_millis(QUERY_RECHECK_MS)
                    }
                })
                .collect();
            let dialing = conn.peer_queries[first_new..]
                .iter()
                .any(|q| is_dialing_or_outbound(q, &local_addrs));
            if todo.is_empty() {
                if (!fresh.is_empty() && dialing) || Instant::now() >= wait_deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(QUERY_RETRY_GAP_MS));
                continue;
            }
            let fds: Vec<u32> = todo.iter().map(|h| h.fd).collect();
            conn.ptrace_ran = true;
            let mut retry = false;
            for q in collect_conn::query_peers(pid, &fds) {
                let gone = q.error.as_deref().is_some_and(|e| e.contains("errno 9"));
                if gone && Instant::now() < deadline {
                    retry = true;
                    continue;
                }
                let Some(h) = todo.iter().find(|h| h.fd == q.fd) else {
                    conn.peer_queries.push(q);
                    continue;
                };
                match answered.get(&h.inode) {
                    Some((idx, _)) => {
                        let idx = *idx;
                        conn.peer_queries[idx] = q;
                        answered.insert(h.inode, (idx, Instant::now()));
                    }
                    None => {
                        answered.insert(h.inode, (conn.peer_queries.len(), Instant::now()));
                        conn.peer_queries.push(q);
                    }
                }
            }
            let dialing = conn.peer_queries[first_new..]
                .iter()
                .any(|q| is_dialing_or_outbound(q, &local_addrs));
            if !retry && (dialing || Instant::now() >= wait_deadline) {
                break;
            }
            std::thread::sleep(Duration::from_millis(QUERY_RETRY_GAP_MS));
        }
        let mine: Vec<model::PeerQuery> = conn.peer_queries[first_new..].to_vec();
        for sibling in &members[1..] {
            for q in &mine {
                conn.peer_queries.push(model::PeerQuery {
                    pid: *sibling,
                    ..q.clone()
                });
            }
        }
    }
}

fn is_dialing_or_outbound(q: &model::PeerQuery, local_addrs: &[std::net::Ipv4Addr]) -> bool {
    if q.state == Some(2) {
        return true;
    }
    if q.error.is_some() || q.peer == "-" {
        return false;
    }
    let ip = q.peer.rsplit_once(':').map_or(q.peer.as_str(), |(h, _)| h);
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(a) => !a.is_loopback() && !local_addrs.contains(&a),
        Err(_) => !ip.starts_with("::1") && !ip.starts_with("[::1]") && !ip.starts_with("family="),
    }
}

fn wait_conntrack_for_dialing(conn: &mut model::ConnFacts, hidden: &[model::PortKey]) {
    if !conn.conntrack_present || !conn.peer_queries.iter().any(|q| q.state == Some(2)) {
        return;
    }
    let end = Instant::now() + Duration::from_millis(DIAL_CONNTRACK_WAIT_MS);
    while !judge::unresolved_ports(conn, hidden).is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(DIAL_CONNTRACK_GAP_MS));
        lookup_by_ports(conn, hidden);
    }
}

fn lookup_by_ports(conn: &mut model::ConnFacts, hidden: &[model::PortKey]) {
    let addrs = collect_conn::local_ipv4_addrs();
    conn.port_local_addrs = hidden
        .iter()
        .map(|k| (*k, collect_conn::port_local_addrs(*k, &addrs)))
        .collect();
    conn.conntrack_present = collect_conn::conntrack_present();
    conn.conntrack_lines = if conn.conntrack_present {
        collect_conn::conntrack_lines(hidden)
    } else {
        Vec::new()
    };
}

fn conn_attempt(start: Instant, hidden_pids: &[u32]) -> (Vec<model::ConnSample>, model::ConnFacts) {
    let mut samples = Vec::new();
    for i in 0..CONN_SAMPLES {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(CONN_GAP_MS));
        }
        samples.push(collect_conn::collect_conn_sample(start));
    }
    let gap = judge::conn_gap_fired(&samples) || judge::udp_gap_fired(&samples);
    let early_held = if gap || !hidden_pids.is_empty() {
        collect_conn::held_sockets(hidden_pids)
    } else {
        Vec::new()
    };
    let mut conn = model::ConnFacts {
        listed_ports_before: collect_conn::listed_ports(),
        inuse_ports_pass1: collect_conn::probe_ports(),
        ..Default::default()
    };
    conn.inuse_ports_pass2 = collect_conn::probe_ports();
    conn.recheck_rounds = RECHECK_ROUNDS;
    conn.recheck_vanished = collect_conn::recheck_ports(
        &judge::port_candidates(&conn),
        RECHECK_ROUNDS,
        RECHECK_GAP_MS,
    );
    conn.listed_ports_after = collect_conn::listed_ports();
    let hidden = judge::hidden_ports(&conn);
    let late_held = if gap || !hidden.is_empty() || !hidden_pids.is_empty() {
        collect_conn::held_sockets(hidden_pids)
    } else {
        Vec::new()
    };
    conn.held = merge_held(early_held, late_held);
    (samples, conn)
}

fn merge_held(
    mut first: Vec<model::HeldSocket>,
    second: Vec<model::HeldSocket>,
) -> Vec<model::HeldSocket> {
    for h in second {
        if !first
            .iter()
            .any(|x| x.pid == h.pid && x.fd == h.fd && x.inode == h.inode)
        {
            first.push(h);
        }
    }
    first
}

fn conn_classes(samples: &[model::ConnSample], conn: &model::ConnFacts) -> usize {
    judge::evidence_class_count(
        samples,
        !conn.held.is_empty(),
        !judge::hidden_ports(conn).is_empty(),
    )
}

fn conn_needs_more(samples: &[model::ConnSample], conn: &model::ConnFacts) -> bool {
    conn_classes(samples, conn) == 1
}

fn patrol_needed(watch_secs: u32, has_hidden_program: bool, classes: usize) -> bool {
    watch_secs > 0 && has_hidden_program && classes < 2
}

fn patrol_wait(cost: Duration) -> Duration {
    cost.saturating_mul(PATROL_COST_FACTOR).clamp(
        Duration::from_millis(PATROL_GAP_MS),
        Duration::from_millis(PATROL_MAX_GAP_MS),
    )
}

fn patrol(
    start: Instant,
    hidden_pids: &[u32],
    limit_secs: u32,
    conn_samples: &mut Vec<model::ConnSample>,
    conn: &mut model::ConnFacts,
) {
    let begin = Instant::now();
    let deadline = begin + Duration::from_secs(limit_secs as u64);
    let base_attempts = conn.attempts;
    let (mut samples, mut rounds, mut caught) = (0u32, 0u32, false);
    let mut prev_hit = false;
    let mut last_round: Option<Instant> = None;
    while Instant::now() < deadline {
        let t = Instant::now();
        let s = collect_conn::collect_conn_sample(start);
        let cost = t.elapsed();
        samples += 1;
        let hit = judge::patrol_hit(&s);
        let spaced = last_round
            .map(|t| t.elapsed() >= Duration::from_millis(PATROL_ROUND_SPACING_MS))
            .unwrap_or(true);
        if hit && prev_hit && spaced && rounds < PATROL_MAX_ROUNDS {
            rounds += 1;
            let (s2, mut c2) = conn_attempt(start, hidden_pids);
            last_round = Some(Instant::now());
            if conn_classes(&s2, &c2) >= 2 {
                c2.attempts = base_attempts;
                *conn_samples = s2;
                *conn = c2;
                caught = true;
                break;
            }
            prev_hit = false;
            continue;
        }
        prev_hit = hit;
        let left = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(patrol_wait(cost).min(left));
    }
    conn.patrol_ran = true;
    conn.patrol_limit_secs = limit_secs;
    conn.patrol_ms = begin.elapsed().as_millis() as u64;
    conn.patrol_samples = samples;
    conn.patrol_rounds = rounds;
    conn.patrol_caught = caught;
}

fn live(args: &Args) -> model::Observation {
    let start = Instant::now();
    let mut meta = collect::collect_meta();
    meta.scanner_sha256 = collect_origin::scanner_sha256();
    let mut proc_samples = Vec::new();
    for i in 0..args.samples {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(args.gap_ms));
        }
        proc_samples.push(collect::collect_proc_sample(start, meta.pid_max));
    }
    let mut known_dirs = HashSet::new();
    let mut mod_samples = Vec::new();
    for i in 0..MOD_SAMPLES {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(MOD_GAP_MS));
        }
        mod_samples.push(collect::collect_mod_sample(start, &mut known_dirs));
    }
    let mut mod_lists = model::ModLists::default();
    collect::fill_lists(&mut mod_lists, true);
    let logs = vec![
        collect::collect_kmsg(),
        collect::collect_messages(meta.epoch),
        collect::collect_journal(),
    ];
    let name_checks: Vec<model::NameCheck> = collect::candidate_names(&logs)
        .iter()
        .map(|n| collect::check_name(n))
        .collect();
    collect::fill_lists(&mut mod_lists, false);

    let hidden_procs = judge::judge_processes(&proc_samples);
    let hidden_pids: Vec<u32> = hidden_procs.confirmed.iter().map(|h| h.info.pid).collect();
    let (mut conn_samples, mut conn) = conn_attempt(start, &hidden_pids);
    conn.attempts = 1;
    if conn_needs_more(&conn_samples, &conn) {
        for n in 2..=(1 + CONN_EXTRA_ATTEMPTS) {
            std::thread::sleep(Duration::from_millis(CONN_EXTRA_GAP_MS));
            let (s2, mut c2) = conn_attempt(start, &hidden_pids);
            if conn_classes(&s2, &c2) >= 2 {
                c2.attempts = n;
                conn_samples = s2;
                conn = c2;
                break;
            }
            conn.attempts = n;
        }
    }
    let has_hidden_program = hidden_procs.confirmed.iter().any(|h| !h.is_kernel_thread);
    if patrol_needed(
        args.watch_secs,
        has_hidden_program,
        conn_classes(&conn_samples, &conn),
    ) {
        patrol(
            start,
            &hidden_pids,
            args.watch_secs,
            &mut conn_samples,
            &mut conn,
        );
    }
    let mut hidden = judge::hidden_ports(&conn);
    let mut holders_queried = false;
    if hidden.is_empty() && !conn.held.is_empty() {
        query_hidden_holders(&mut conn);
        holders_queried = true;
        hidden = judge::hidden_ports(&conn);
    }
    if !hidden.is_empty() {
        lookup_by_ports(&mut conn, &hidden);
        if !holders_queried && !judge::unresolved_ports(&conn, &hidden).is_empty() {
            query_hidden_holders(&mut conn);
            hidden = judge::hidden_ports(&conn);
            lookup_by_ports(&mut conn, &hidden);
        }
        wait_conntrack_for_dialing(&mut conn, &hidden);
        if !judge::unresolved_ports(&conn, &hidden).is_empty() {
            conn.capture_ran = true;
            conn.capture_secs = CAPTURE_SECS;
            conn.capture_pairs = collect_conn::capture_pairs(CAPTURE_SECS, &hidden);
        }
        let need_holders = !judge::unresolved_ports(&conn, &hidden).is_empty()
            || judge::unexplained_hidden_sockets(&conn_samples, &conn.held) > 0;
        if need_holders
            && judge::evidence_class_count(&conn_samples, !conn.held.is_empty(), !hidden.is_empty())
                >= 2
        {
            let pids = collect_conn::visible_user_pids(&hidden_pids);
            conn.visible_held = collect_conn::held_sockets(&pids);
            let mut by_pid: std::collections::BTreeMap<u32, Vec<u32>> = Default::default();
            for h in conn.visible_held.iter().filter(|h| h.exe.is_some()) {
                by_pid.entry(h.pid).or_default().push(h.fd);
            }
            conn.visible_capped = by_pid.len() > MAX_VISIBLE_QUERIES;
            for (pid, fds) in by_pid.into_iter().take(MAX_VISIBLE_QUERIES) {
                conn.ptrace_ran = true;
                conn.peer_queries
                    .extend(collect_conn::query_peers(pid, &fds));
            }
        }
        if judge::unresolved_ports(&conn, &hidden)
            .iter()
            .any(|k| k.proto == model::Proto::Tcp)
        {
            if let Some(addrs) = collect_conn::tcp_metrics_addrs() {
                conn.metrics_ran = true;
                conn.tcp_metrics = addrs;
                conn.visible_remotes = collect_conn::visible_remote_addrs();
            }
        }
    }
    let origin_pids: Vec<u32> = hidden_procs
        .confirmed
        .iter()
        .filter(|h| !h.is_kernel_thread)
        .map(|h| h.info.pid)
        .collect();
    let origin = if origin_pids.is_empty() {
        model::OriginData::default()
    } else {
        collect_origin::collect_origin_data(&origin_pids, meta.btime)
    };
    let disk = collect_disk::collect_disk_scan();
    let exe_scan = collect_exe::collect_exe_scan();
    let deleted_scan = collect_deleted::collect_deleted_scan();
    let content_scan = collect_content::collect_content_scan(&args.content_roots);
    let local_addrs = collect_addr::collect_local_addrs();
    meta.elapsed_ms = start.elapsed().as_millis() as u64;
    model::Observation {
        meta,
        proc_samples,
        mod_samples,
        mod_lists,
        logs,
        name_checks,
        conn_samples,
        conn,
        origin,
        disk,
        exe_scan,
        deleted_scan,
        content_scan,
        local_addrs,
    }
}

fn do_genkey(out: Option<&str>) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let (pubk, seck) = crypto::generate();
    let path = out.unwrap_or("rootkit-scan-private.key");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            format!(
                "寫不出私鑰檔 {}：{}（若已存在，請改用 --out 指定別的路徑）",
                path, e
            )
        })?;
    writeln!(
        f,
        "# rootkit-scan 私鑰，請收好；只有它能解密報告，絕不要放到被掃描的主機。"
    )
    .and_then(|_| writeln!(f, "{}", seck))
    .map_err(|e| format!("寫不出私鑰檔 {}：{}", path, e))?;
    println!("公鑰（打包掃描器時帶入環境變數 ROOTKIT_SCAN_PUBKEY，可公開）：");
    println!("{}", pubk);
    println!();
    println!(
        "私鑰已寫到：{}（權限 0600；請收好、備份，遺失就再也解不開舊報告）",
        path
    );
    Ok(())
}

fn do_decrypt(enc_path: &str, key: Option<&str>, out: Option<&str>) -> Result<(), String> {
    let key_path = key.ok_or("解密要用 --key 指定你的私鑰檔")?;
    let sec = std::fs::read_to_string(key_path)
        .map_err(|e| format!("讀不到私鑰檔 {}：{}", key_path, e))?;
    let data = std::fs::read(enc_path).map_err(|e| format!("讀不到 {}：{}", enc_path, e))?;
    let plain = crypto::unseal(&sec, &data)?;
    match out {
        Some(path) => {
            std::fs::write(path, &plain).map_err(|e| format!("寫不出 {}：{}", path, e))?;
            eprintln!("已解密寫到 {}", path);
        }
        None => {
            use std::io::Write;
            std::io::stdout()
                .write_all(&plain)
                .map_err(|e| format!("印不出來：{}", e))?;
        }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    if args.genkey {
        return do_genkey(args.out.as_deref());
    }
    if let Some(enc) = &args.decrypt {
        return do_decrypt(enc, args.key.as_deref(), args.out.as_deref());
    }
    if let Some(pk) = crypto::BAKED_PUBKEY {
        crypto::check_pub(pk).map_err(|e| format!("這支掃描器編入的公鑰無效：{}", e))?;
    }
    if support::must_refuse_non_root(args.replay.is_some(), collect::is_root()) {
        eprint!("{}", support::non_root_refusal_text());
        return Ok(());
    }
    if args.replay.is_none() {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let release = release.trim();
        if support::is_older_than_supported(release) {
            print!("{}", support::refusal_text(release, VERSION));
            return Ok(());
        }
    }
    if support::should_wipe_self(crypto::BAKED_PUBKEY, args.replay.is_some()) {
        support::disable_core_dumps();
    }
    let (obs, rec_text) = match &args.replay {
        Some(path) => {
            let file =
                std::fs::read_to_string(path).map_err(|e| format!("讀不到 {}：{}", path, e))?;
            let text = recording::extract_embedded(&file)?.unwrap_or(file);
            (recording::decode(&text)?, text)
        }
        None => {
            let obs = live(&args);
            let text = recording::encode(&obs);
            let obs = recording::decode(&text)
                .map_err(|e| format!("內部錯誤：剛錄下的資料讀不回來（{}）", e))?;
            (obs, text)
        }
    };
    if let Some(path) = &args.record {
        match crypto::BAKED_PUBKEY {
            Some(pk) => {
                let sealed = crypto::seal(pk, rec_text.as_bytes())?;
                std::fs::write(path, &sealed).map_err(|e| format!("寫不出 {}：{}", path, e))?;
            }
            None => {
                std::fs::write(path, &rec_text).map_err(|e| format!("寫不出 {}：{}", path, e))?;
            }
        }
    }
    let mut run = report::RunInfo {
        rec_sha256: Some(sha256::hex_of(rec_text.as_bytes())),
        rec_text: Some(rec_text),
    };
    let procs = judge::judge_processes(&obs.proc_samples);
    let mods = judge::judge_modules(&obs, &procs);
    let conns = judge::judge_connections(&obs, &procs);
    let origins = judge::judge_origins(&obs, &procs);
    let files = judge::judge_files(&obs);
    let exes = judge::judge_exe(&obs, &procs);
    let contents = judge::judge_content(&obs);
    let deleted = judge::judge_deleted(&obs, &procs);
    let text = report::render(
        &obs,
        &report::Findings {
            procs: &procs,
            mods: &mods,
            conns: &conns,
            files: &files,
            exes: &exes,
            contents: &contents,
            deleted: &deleted,
            origins: &origins,
        },
        &run,
        VERSION,
    );
    if args.replay.is_some() {
        print!("{}", text);
        return Ok(());
    }
    let base = support::report_file_base(&obs.meta.hostname, obs.meta.epoch);
    let exe_path = std::env::current_exe().ok();
    let dir = support::report_dir(exe_path.as_deref());
    let saved = save_scan_output(&dir, &base, &text, crypto::BAKED_PUBKEY);
    let wipe = support::should_wipe_self(crypto::BAKED_PUBKEY, args.replay.is_some());
    let wiped = wipe && support::remove_own_exe(exe_path.as_deref()).is_ok();
    if wipe {
        support::scrub_string(text);
        if let Some(rec) = run.rec_text.take() {
            support::scrub_string(rec);
        }
    }
    match saved {
        Ok(_) => print!("{}", support::DONE_TEXT),
        Err(_) if wiped => eprint!("{}", support::SAVE_FAILED_WIPED_TEXT),
        Err(_) => eprint!("{}", support::SAVE_FAILED_TEXT),
    }
    if wipe && !wiped {
        eprint!("{}", support::WIPE_FAILED_TEXT);
    }
    Ok(())
}

fn save_scan_output(
    dir: &std::path::Path,
    base: &str,
    text: &str,
    pubkey: Option<&str>,
) -> Result<std::path::PathBuf, String> {
    match pubkey {
        Some(pk) => {
            let sealed = crypto::seal(pk, text.as_bytes())?;
            support::save_bytes_in(dir, base, "enc", &sealed).map_err(|e| e.to_string())
        }
        None => support::save_report_in(dir, base, text).map_err(|e| e.to_string()),
    }
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("rootkit-scan：{}", e);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_dialing_or_outside_connection_ends_the_wait_for_the_c2_address() {
        use std::net::Ipv4Addr;
        let me = vec![Ipv4Addr::new(198, 51, 100, 20)];
        let q = |peer: &str, error: Option<&str>, state: Option<u8>| model::PeerQuery {
            pid: 1,
            fd: 3,
            local: "198.51.100.20:5000".into(),
            peer: peer.into(),
            error: error.map(String::from),
            state,
        };
        assert!(is_dialing_or_outbound(
            &q("-", Some("errno 107"), Some(2)),
            &me
        ));
        assert!(is_dialing_or_outbound(
            &q("198.51.100.200:18443", None, None),
            &me
        ));
        assert!(!is_dialing_or_outbound(
            &q("127.0.0.1:46462", None, None),
            &me
        ));
        assert!(!is_dialing_or_outbound(
            &q("198.51.100.20:80", None, None),
            &me
        ));
        assert!(!is_dialing_or_outbound(
            &q("-", Some("errno 107"), Some(10)),
            &me
        ));
        assert!(!is_dialing_or_outbound(
            &q("-", Some("errno 107"), Some(7)),
            &me
        ));
        assert!(!is_dialing_or_outbound(&q("-", Some("errno 9"), None), &me));
        assert!(!is_dialing_or_outbound(&q("family=16", None, None), &me));
    }

    #[test]
    fn keyed_scan_output_is_encrypted_on_disk_and_decrypts_back() {
        let dir = std::env::temp_dir().join(format!("rkenc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (pubk, seck) = crypto::generate();
        let report = "RootKit 掃描報告\n結果：沒有發現被藏起來的東西\n";
        let path = save_scan_output(&dir, "report-host-1", report, Some(&pubk)).unwrap();
        assert_eq!(path.extension().unwrap(), "enc");
        let on_disk = std::fs::read(&path).unwrap();
        assert!(on_disk.starts_with(crypto::SEALED_MAGIC));
        assert!(!on_disk
            .windows("沒有發現".len())
            .any(|w| w == "沒有發現".as_bytes()));
        let opened = crypto::unseal(&seck, &on_disk).unwrap();
        assert_eq!(opened, report.as_bytes());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unkeyed_scan_output_stays_plaintext_txt() {
        let dir = std::env::temp_dir().join(format!("rkplain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = "RootKit 掃描報告\n結果：沒有發現\n";
        let path = save_scan_output(&dir, "report-host-2", report, None).unwrap();
        assert_eq!(path.extension().unwrap(), "txt");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), report);
        std::fs::remove_file(&path).ok();
    }

    fn h(pid: u32, fd: u32, inode: u64) -> model::HeldSocket {
        model::HeldSocket {
            pid,
            comm: "x".into(),
            exe: None,
            fd,
            inode,
        }
    }

    #[test]
    fn patrol_only_when_enabled_hidden_program_and_not_yet_two_classes() {
        assert!(patrol_needed(150, true, 0));
        assert!(patrol_needed(150, true, 1));
        assert!(!patrol_needed(150, true, 2));
        assert!(!patrol_needed(150, true, 3));
        assert!(!patrol_needed(150, false, 0));
        assert!(!patrol_needed(0, true, 0));
    }

    #[test]
    fn patrol_wait_keeps_cpu_near_one_percent_and_within_bounds() {
        assert_eq!(
            patrol_wait(Duration::from_millis(1)),
            Duration::from_millis(500)
        );
        assert_eq!(
            patrol_wait(Duration::from_millis(20)),
            Duration::from_millis(2000)
        );
        assert_eq!(patrol_wait(Duration::from_secs(1)), Duration::from_secs(3));
        for ms in [1u64, 5, 10, 20, 29] {
            let c = Duration::from_millis(ms);
            let w = patrol_wait(c);
            assert!(c.as_secs_f64() / (c + w).as_secs_f64() <= 0.0101, "{}", ms);
        }
    }

    #[test]
    fn two_holder_scans_are_merged_without_duplicates() {
        let early = vec![h(1455, 3, 100), h(1605, 3, 100)];
        let late = vec![h(1455, 3, 100), h(1606, 3, 100), h(1455, 4, 200)];
        let merged = merge_held(early, late);
        assert_eq!(merged.len(), 4, "{:?}", merged);
        assert_eq!(merge_held(vec![], vec![h(9, 3, 1)]).len(), 1);
        assert_eq!(merge_held(vec![h(9, 3, 1)], vec![]).len(), 1);
        assert!(merge_held(vec![], vec![]).is_empty());
    }
}
