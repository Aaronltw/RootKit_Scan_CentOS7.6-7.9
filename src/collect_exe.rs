use crate::collect::describe;
use crate::collect_origin::collect_proc_evidence;
use crate::model::{ExeContradiction, ExeScan};
use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

pub const RECHECK_ROUNDS: u32 = 3;
const RECHECK_GAP_MS: u64 = 100;
const ENOENT: i32 = 2;

fn visible_pids() -> Vec<u32> {
    let mut v: Vec<u32> = fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExeState {
    Skip,
    Fine,
    Contradiction,
}

pub fn classify(open_ok: bool, stat_errno: Option<i32>) -> ExeState {
    match (open_ok, stat_errno) {
        (false, _) => ExeState::Skip,
        (true, None) => ExeState::Fine,
        (true, Some(ENOENT)) => ExeState::Contradiction,
        (true, Some(_)) => ExeState::Skip,
    }
}

fn check(pid: u32) -> (ExeState, String) {
    let Ok(link) = fs::read_link(format!("/proc/{}/exe", pid)) else {
        return (ExeState::Skip, String::new());
    };
    let exe = link.to_string_lossy().to_string();
    if exe.ends_with(" (deleted)") {
        return (ExeState::Skip, exe);
    }
    match fs::File::open(format!("/proc/{}/exe", pid)) {
        Err(_) => (classify(false, None), exe),
        Ok(f) => {
            let stat_errno = f.metadata().err().and_then(|e| e.raw_os_error());
            (classify(true, stat_errno), exe)
        }
    }
}

pub fn collect_exe_scan() -> ExeScan {
    let mut scan = ExeScan {
        ran: true,
        ..Default::default()
    };
    let mut cands: BTreeMap<u32, String> = BTreeMap::new();
    for pid in visible_pids() {
        match check(pid) {
            (ExeState::Skip, _) => {}
            (ExeState::Fine, _) => scan.checked += 1,
            (ExeState::Contradiction, exe) => {
                scan.checked += 1;
                cands.insert(pid, exe);
            }
        }
    }
    scan.candidates = cands.len();
    for _ in 0..RECHECK_ROUNDS {
        if cands.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(RECHECK_GAP_MS));
        cands.retain(|pid, exe| {
            let (state, now) = check(*pid);
            state == ExeState::Contradiction && now == *exe
        });
    }
    scan.vanished = scan.candidates - cands.len();
    for (pid, exe) in cands {
        let info = describe(pid, false, false, false, false);
        scan.items.push(ExeContradiction {
            pid,
            comm: info.comm,
            ppid: info.ppid,
            starttime: info.starttime,
            exe,
            cmdline: info.cmdline,
            evidence: collect_proc_evidence(pid),
        });
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_open_ok_plus_enoent_is_a_contradiction() {
        assert_eq!(classify(true, None), ExeState::Fine);
        assert_eq!(classify(true, Some(2)), ExeState::Contradiction);
        assert_eq!(classify(true, Some(13)), ExeState::Skip, "權限不足不是矛盾");
        assert_eq!(
            classify(true, Some(3)),
            ExeState::Skip,
            "行程剛結束不是矛盾"
        );
        assert_eq!(classify(false, Some(2)), ExeState::Skip, "打不開就不檢查");
        assert_eq!(classify(false, None), ExeState::Skip);
    }

    #[test]
    fn our_own_process_is_fine() {
        let (state, exe) = check(std::process::id());
        assert_eq!(state, ExeState::Fine, "{}", exe);
        assert!(!exe.is_empty());
    }

    #[test]
    fn a_missing_process_is_skipped() {
        assert_eq!(check(4_000_000).0, ExeState::Skip);
    }

    #[test]
    fn a_live_scan_of_this_machine_finds_nothing_contradictory() {
        let scan = collect_exe_scan();
        assert!(scan.ran);
        assert!(scan.checked > 0, "至少會檢查到自己");
        assert!(scan.items.is_empty(), "{:?}", scan.items);
    }
}
