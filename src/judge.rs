use crate::model::{
    AuditLogin, DiskStatus, HiddenFile, Observation, OriginFacts, ProcSample, Unlisted,
};
use std::collections::BTreeSet;

const TCP_LISTEN: u8 = 10;
const TCP_CLOSE: u8 = 7;
const TCP_SYN_SENT: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenProc {
    pub info: Unlisted,
    pub via_kill: bool,
    pub via_cgroup: bool,
    pub via_sched: bool,
    pub via_timer: bool,
    pub is_kernel_thread: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcJudgement {
    pub confirmed: Vec<HiddenProc>,
    pub transient: usize,
    pub samples: usize,
}

pub fn judge_processes(samples: &[ProcSample]) -> ProcJudgement {
    let key = |u: &Unlisted| (u.pid, u.starttime);
    let mut confirmed_keys: BTreeSet<(u32, u64)> = BTreeSet::new();
    let mut all_keys: BTreeSet<(u32, u64)> = BTreeSet::new();
    for s in samples {
        all_keys.extend(s.unlisted.iter().map(key));
    }
    for pair in samples.windows(2) {
        let prev: BTreeSet<_> = pair[0].unlisted.iter().map(key).collect();
        for u in &pair[1].unlisted {
            if prev.contains(&key(u)) {
                confirmed_keys.insert(key(u));
            }
        }
    }
    let mut confirmed = Vec::new();
    for k in &confirmed_keys {
        let seen: Vec<&Unlisted> = samples
            .iter()
            .flat_map(|s| s.unlisted.iter())
            .filter(|u| key(u) == *k)
            .collect();
        if let Some(u) = seen.last() {
            confirmed.push(HiddenProc {
                is_kernel_thread: u.ppid == Some(2) && u.exe.is_none(),
                via_kill: seen.iter().any(|x| x.via_kill),
                via_cgroup: seen.iter().any(|x| x.via_cgroup),
                via_sched: seen.iter().any(|x| x.via_sched),
                via_timer: seen.iter().any(|x| x.via_timer),
                info: (*u).clone(),
            });
        }
    }
    ProcJudgement {
        transient: all_keys.len() - confirmed_keys.len(),
        confirmed,
        samples: samples.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(pid: u32, start: u64, ppid: u32, comm: &str, exe: Option<&str>) -> Unlisted {
        Unlisted {
            pid,
            via_kill: true,
            via_cgroup: false,
            via_sched: false,
            via_timer: false,
            starttime: start,
            ppid: Some(ppid),
            comm: comm.into(),
            exe: exe.map(String::from),
            cmdline: String::new(),
        }
    }

    fn smp(unlisted: Vec<Unlisted>) -> ProcSample {
        ProcSample {
            unlisted,
            ..Default::default()
        }
    }

    #[test]
    fn nothing_hidden_means_nothing_confirmed() {
        let j = judge_processes(&[smp(vec![]), smp(vec![]), smp(vec![])]);
        assert!(j.confirmed.is_empty());
        assert_eq!(j.transient, 0);
    }

    #[test]
    fn needs_two_consecutive_samples() {
        let a = u(100, 5, 1, "x", Some("/bin/x"));
        let j = judge_processes(&[smp(vec![a.clone()]), smp(vec![]), smp(vec![a.clone()])]);
        assert!(j.confirmed.is_empty(), "隔開的兩次不算連續");
        assert_eq!(j.transient, 1);
        let j = judge_processes(&[smp(vec![a.clone()]), smp(vec![a.clone()]), smp(vec![])]);
        assert_eq!(j.confirmed.len(), 1);
        assert_eq!(j.transient, 0);
    }

    #[test]
    fn sources_are_merged_across_the_two_samples() {
        let mut a = u(100, 5, 1, "x", Some("/bin/x"));
        let mut b = a.clone();
        a.via_kill = true;
        a.via_cgroup = false;
        b.via_kill = false;
        b.via_cgroup = true;
        let j = judge_processes(&[smp(vec![a]), smp(vec![b])]);
        assert_eq!(j.confirmed.len(), 1);
        assert!(j.confirmed[0].via_kill && j.confirmed[0].via_cgroup);
    }

    #[test]
    fn exe_judgement_is_empty_when_not_run_and_never_double_counts_hidden_processes() {
        let mut o = Observation::default();
        let p = judge_processes(&[]);
        assert_eq!(judge_exe(&o, &p), ExeJudgement::default());
        let c = |pid| crate::model::ExeContradiction {
            pid,
            exe: "/usr/bin/x".into(),
            ..Default::default()
        };
        o.exe_scan = crate::model::ExeScan {
            ran: true,
            checked: 90,
            items: vec![c(100), c(200)],
            ..Default::default()
        };
        let j = judge_exe(&o, &p);
        assert_eq!((j.items.len(), j.checked), (2, 90));
        let a = u(100, 5, 1, "x", Some("/usr/bin/x"));
        let p2 = judge_processes(&[smp(vec![a.clone()]), smp(vec![a])]);
        let j2 = judge_exe(&o, &p2);
        assert_eq!(j2.items.len(), 1);
        assert_eq!(j2.items[0].pid, 200);
    }

    #[test]
    fn found_only_by_the_sched_table_is_confirmed_even_when_kill_and_cgroup_both_deny() {
        let mut a = u(100, 5, 1, "x", Some("/bin/x"));
        a.via_kill = false;
        a.via_cgroup = false;
        a.via_sched = true;
        let j = judge_processes(&[smp(vec![a.clone()]), smp(vec![a])]);
        assert_eq!(j.confirmed.len(), 1);
        let h = &j.confirmed[0];
        assert!(!h.via_kill && !h.via_cgroup && h.via_sched && !h.via_timer);
    }

    #[test]
    fn sched_and_timer_sources_are_merged_across_samples() {
        let mut a = u(100, 5, 1, "x", Some("/bin/x"));
        let mut b = a.clone();
        a.via_sched = true;
        b.via_timer = true;
        let j = judge_processes(&[smp(vec![a]), smp(vec![b])]);
        assert!(j.confirmed[0].via_sched && j.confirmed[0].via_timer);
    }

    #[test]
    fn found_only_by_cgroup_is_still_confirmed() {
        let mut a = u(100, 5, 1, "x", Some("/bin/x"));
        a.via_kill = false;
        a.via_cgroup = true;
        let j = judge_processes(&[smp(vec![a.clone()]), smp(vec![a])]);
        assert_eq!(j.confirmed.len(), 1);
        assert!(!j.confirmed[0].via_kill && j.confirmed[0].via_cgroup);
    }

    #[test]
    fn reused_pid_with_new_starttime_is_a_different_object() {
        let a = u(100, 5, 1, "x", Some("/bin/x"));
        let b = u(100, 9, 1, "y", Some("/bin/y"));
        let j = judge_processes(&[smp(vec![a]), smp(vec![b])]);
        assert!(j.confirmed.is_empty());
        assert_eq!(j.transient, 2);
    }

    #[test]
    fn kernel_thread_needs_ppid_2_and_no_exe() {
        let k = u(7652, 7364, 2, "ktestwork", None);
        let p = u(7655, 7673, 1, "python2", Some("/usr/bin/python2.7"));
        let j = judge_processes(&[smp(vec![k.clone(), p.clone()]), smp(vec![k, p])]);
        assert_eq!(j.confirmed.len(), 2);
        let by = |name: &str| j.confirmed.iter().find(|h| h.info.comm == name).unwrap();
        assert!(by("ktestwork").is_kernel_thread);
        assert!(!by("python2").is_kernel_thread);
    }
}

use crate::model::{LogCopy, ModSample};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub source: String,
    pub covered: bool,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameSource {
    pub source: String,
    pub covered: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedModule {
    pub name: String,
    pub initstate: String,
    pub taint: String,
    pub text_addr: String,
    pub sources: Vec<NameSource>,
    pub born_with: Option<(String, u64)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModJudgement {
    pub gap: Option<usize>,
    pub stable: usize,
    pub total: usize,
    pub named: Vec<NamedModule>,
    pub unnamed_extra: usize,
    pub notes: Vec<String>,
    pub coverage: Vec<Coverage>,
}

fn is_stable(s: &ModSample) -> bool {
    s.nl_before == s.nl_mid
        && s.nl_mid == s.nl_after
        && s.n_list1 == s.n_list2
        && s.vanished == 0
        && s.nl_after >= 0
}

fn gap_of(s: &ModSample) -> i64 {
    s.nl_after - 2 - s.n_sub as i64
}

fn judge_gap(samples: &[ModSample]) -> (Option<usize>, usize) {
    let stable: Vec<i64> = samples
        .iter()
        .filter(|s| is_stable(s))
        .map(gap_of)
        .collect();
    if stable.len() < 3 {
        return (None, stable.len());
    }
    let last3 = &stable[stable.len() - 3..];
    if last3.iter().all(|g| *g >= 1) {
        (
            Some(*last3.iter().min().unwrap_or(&1) as usize),
            stable.len(),
        )
    } else {
        (None, stable.len())
    }
}

fn missing_banner_reason(min_epoch: Option<u64>, btime: u64) -> String {
    match min_epoch {
        Some(m) if btime > 0 && m > btime => format!(
            "沒有開機訊息，紀錄最早只到 {} UTC+8，比本次開機（{} UTC+8）還晚，開機當時的紀錄已經不在，可能被輪替掉、清除或截斷",
            crate::timeutil::fmt_tw_sec(m),
            crate::timeutil::fmt_tw_sec(btime)
        ),
        Some(_) if btime > 0 => {
            "紀錄涵蓋本次開機的時間，卻沒有開機訊息，疑似被刪掉部分內容".to_string()
        }
        _ => "沒有開機訊息，可能被輪替掉、清除或截斷".to_string(),
    }
}

fn coverage_of(copy: &LogCopy, earliest_birth: Option<u64>, is_root: bool, btime: u64) -> Coverage {
    let (covered, reason) = match copy.source.as_str() {
        "kmsg" => {
            if !copy.readable {
                (false, "讀不到".to_string())
            } else if copy.first_seq == Some(0) && copy.seq_gaps == 0 {
                (true, "首序號 0、沒有缺號".to_string())
            } else {
                (
                    false,
                    format!(
                        "首序號 {:?}、缺號 {} 處，前面的訊息可能已被擠掉",
                        copy.first_seq, copy.seq_gaps
                    ),
                )
            }
        }
        "journal" => {
            if !copy.readable {
                if is_root {
                    (
                        false,
                        "讀不到任何日誌檔，可能被清除，也可能這台機器的日誌本來就沒有保存"
                            .to_string(),
                    )
                } else {
                    (false, "沒有權限讀取，因為不是以 root 執行".to_string())
                }
            } else if copy.boot_banner {
                (
                    true,
                    "有這次開機的核心訊息（無法逐筆核對時間，以開機訊息存在代表涵蓋）".to_string(),
                )
            } else {
                (false, missing_banner_reason(None, btime))
            }
        }
        _ => {
            if !copy.readable {
                if is_root {
                    (false, "讀不到".to_string())
                } else {
                    (false, "沒有權限讀取，因為不是以 root 執行".to_string())
                }
            } else if copy.unread > 0 {
                (
                    false,
                    format!(
                        "有 {} 個檔案太大（上限 2 GB）或讀到一半失敗，沒有讀完",
                        copy.unread
                    ),
                )
            } else if !copy.boot_banner {
                (false, missing_banner_reason(copy.min_epoch, btime))
            } else {
                match (copy.min_epoch, earliest_birth) {
                    (Some(m), Some(b)) if m <= b => {
                        (true, "有開機訊息，最早時間不晚於被藏物件啟動".to_string())
                    }
                    (Some(_), Some(_)) => (
                        false,
                        "最早一筆晚於被藏物件啟動，前面的紀錄不見了".to_string(),
                    ),
                    (_, None) => (false, "沒有被藏物件的啟動時間可對照，無法判斷".to_string()),
                    (None, _) => (false, "讀不出任何時間".to_string()),
                }
            }
        }
    };
    Coverage {
        source: copy.source.clone(),
        covered,
        reason,
    }
}

pub fn judge_modules(obs: &Observation, procs: &ProcJudgement) -> ModJudgement {
    let (gap, stable) = judge_gap(&obs.mod_samples);
    let btime = obs.meta.btime;
    let tck = obs.meta.clk_tck.max(1);
    let births: Vec<(String, u64)> = procs
        .confirmed
        .iter()
        .filter(|h| h.info.starttime > 0 && btime > 0)
        .map(|h| (h.info.comm.clone(), btime + h.info.starttime / tck))
        .collect();
    let earliest_birth = births.iter().map(|(_, e)| *e).min();
    let coverage: Vec<Coverage> = obs
        .logs
        .iter()
        .map(|c| coverage_of(c, earliest_birth, obs.meta.is_root, btime))
        .collect();
    let covered = |source: &str| coverage.iter().any(|c| c.source == source && c.covered);

    let l = &obs.mod_lists;
    let in_lists = |n: &str| {
        [&l.proc_before, &l.proc_after, &l.sys_before, &l.sys_after]
            .iter()
            .any(|v| v.iter().any(|x| x == n))
    };
    let mut named = Vec::new();
    let mut notes = Vec::new();
    for nc in &obs.name_checks {
        if !nc.stat_ok || in_lists(&nc.name) {
            continue;
        }
        let sources: Vec<NameSource> = obs
            .logs
            .iter()
            .filter(|c| c.load_lines.iter().any(|ll| ll.name == nc.name))
            .map(|c| NameSource {
                source: c.source.clone(),
                covered: covered(&c.source),
            })
            .collect();
        let have_covered: Vec<&str> = sources
            .iter()
            .filter(|s| s.covered)
            .map(|s| s.source.as_str())
            .collect();
        if !have_covered.is_empty() {
            for c in coverage.iter().filter(|c| c.covered) {
                if !sources.iter().any(|s| s.source == c.source) {
                    notes.push(format!(
                        "紀錄疑似被改：{} 涵蓋被藏物件啟動的時間，卻沒有 {} 的載入紀錄，而 {} 有。",
                        source_label(&c.source),
                        nc.name,
                        have_covered
                            .iter()
                            .map(|s| source_label(s))
                            .collect::<Vec<_>>()
                            .join("、")
                    ));
                }
            }
        }
        let mut born_with = None;
        for lg in &obs.logs {
            for ll in lg.load_lines.iter().filter(|ll| ll.name == nc.name) {
                if let Some(ep) = ll.epoch {
                    for h in procs.confirmed.iter().filter(|h| h.is_kernel_thread) {
                        if h.info.starttime > 0 && btime > 0 {
                            let b = btime + h.info.starttime / tck;
                            let diff = ep.abs_diff(b);
                            if diff <= 2 && born_with.as_ref().is_none_or(|(_, d)| diff < *d) {
                                born_with = Some((h.info.comm.clone(), diff));
                            }
                        }
                    }
                }
            }
        }
        named.push(NamedModule {
            name: nc.name.clone(),
            initstate: nc.initstate.clone(),
            taint: nc.taint.clone(),
            text_addr: nc.text_addr.clone(),
            sources,
            born_with,
        });
    }
    if !procs.confirmed.is_empty() || !named.is_empty() || gap.is_some() {
        for c in coverage.iter().filter(|c| !c.covered) {
            notes.push(format!("{}：{}。", source_label(&c.source), c.reason));
        }
    }
    notes.sort();
    notes.dedup();
    let unnamed_extra = gap.map_or(0, |g| g.saturating_sub(named.len()));
    ModJudgement {
        gap,
        stable,
        total: obs.mod_samples.len(),
        named,
        unnamed_extra,
        notes,
        coverage,
    }
}

pub fn source_label(source: &str) -> &'static str {
    match source {
        "kmsg" => "核心訊息緩衝",
        "messages" => "系統紀錄檔",
        "journal" => "systemd 日誌",
        _ => "其他來源",
    }
}

#[cfg(test)]
mod module_tests {
    use super::*;
    use crate::model::{LoadLine, ModLists, NameCheck};
    use crate::recording::tests::sample_observation;

    fn stable_sample(gap: i64) -> ModSample {
        ModSample {
            t_ms: 0,
            nl_before: 120 + gap,
            nl_mid: 120 + gap,
            nl_after: 120 + gap,
            n_list1: 118,
            n_list2: 118,
            n_sub: 118,
            vanished: 0,
        }
    }

    #[test]
    fn gap_needs_three_stable_samples_all_positive() {
        assert_eq!(judge_gap(&[stable_sample(1), stable_sample(1)]).0, None);
        assert_eq!(
            judge_gap(&[stable_sample(1), stable_sample(1), stable_sample(1)]).0,
            Some(1)
        );
        assert_eq!(
            judge_gap(&[stable_sample(1), stable_sample(0), stable_sample(1)]).0,
            None
        );
        assert_eq!(
            judge_gap(&[stable_sample(0), stable_sample(0), stable_sample(0)]).0,
            None
        );
    }

    #[test]
    fn unstable_samples_are_ignored() {
        let mut flaky = stable_sample(5);
        flaky.nl_mid += 1;
        let v = [
            stable_sample(1),
            flaky.clone(),
            stable_sample(1),
            flaky,
            stable_sample(1),
        ];
        assert_eq!(judge_gap(&v), (Some(1), 3));
        let mut vanished = stable_sample(1);
        vanished.vanished = 1;
        assert_eq!(
            judge_gap(&[vanished.clone(), vanished.clone(), vanished]).0,
            None
        );
    }

    fn infected() -> (Observation, ProcJudgement) {
        let mut o = sample_observation();
        o.mod_samples = vec![stable_sample(1); 5];
        o.mod_lists = ModLists {
            proc_before: vec!["xfs".into()],
            proc_after: vec!["xfs".into()],
            sys_before: vec!["xfs".into(), "kernel".into()],
            sys_after: vec!["xfs".into(), "kernel".into()],
        };
        o.proc_samples = vec![o.proc_samples[0].clone(), o.proc_samples[0].clone()];
        let p = judge_processes(&o.proc_samples);
        (o, p)
    }

    #[test]
    fn named_module_is_confirmed_by_contradiction() {
        let (o, p) = infected();
        let j = judge_modules(&o, &p);
        assert_eq!(j.gap, Some(1));
        assert_eq!(j.named.len(), 1);
        assert_eq!(j.named[0].name, "testmod");
        assert_eq!(j.unnamed_extra, 0);
        assert!(j.notes.is_empty());
        assert_eq!(j.named[0].sources.len(), 2);
        assert_eq!(j.named[0].born_with, Some(("ktestwork".to_string(), 1)));
    }

    #[test]
    fn name_present_in_a_listing_is_not_hidden() {
        let (mut o, p) = infected();
        o.mod_lists.sys_after.push("testmod".into());
        assert!(judge_modules(&o, &p).named.is_empty());
    }

    #[test]
    fn name_that_stat_cannot_find_is_not_confirmed() {
        let (mut o, p) = infected();
        o.name_checks = vec![NameCheck {
            name: "testmod".into(),
            stat_ok: false,
            ..Default::default()
        }];
        let j = judge_modules(&o, &p);
        assert!(
            j.named.is_empty(),
            "載入過又卸載的模組：紀錄有名字、但問核心查不到，不算被藏"
        );
        assert_eq!(j.unnamed_extra, 1, "連結數仍多 1，只能列待確認");
    }

    #[test]
    fn gap_without_any_name_is_only_pending() {
        let (mut o, p) = infected();
        o.logs.clear();
        o.name_checks.clear();
        let j = judge_modules(&o, &p);
        assert!(j.named.is_empty());
        assert_eq!(j.gap, Some(1));
        assert_eq!(j.unnamed_extra, 1);
    }

    #[test]
    fn selective_deletion_in_a_covering_copy_is_noted_but_name_survives() {
        let (mut o, p) = infected();
        o.logs[1].load_lines.clear();
        let j = judge_modules(&o, &p);
        assert_eq!(j.named.len(), 1, "名字仍由核心訊息緩衝取得");
        assert_eq!(j.notes.len(), 1);
        assert!(j.notes[0].contains("系統紀錄檔") && j.notes[0].contains("testmod"));
    }

    #[test]
    fn clean_machine_gets_no_coverage_note_even_if_logs_rotated_away() {
        let (mut o, _) = infected();
        o.proc_samples = vec![Default::default(), Default::default()];
        o.mod_samples = vec![stable_sample(0); 5];
        o.name_checks.clear();
        o.logs[1].boot_banner = false;
        let p = judge_processes(&o.proc_samples);
        let j = judge_modules(&o, &p);
        assert!(j.notes.is_empty());
        assert!(j.named.is_empty() && j.gap.is_none());
    }

    fn journal_copy(with_name: bool, banner: bool, readable: bool) -> LogCopy {
        LogCopy {
            source: "journal".into(),
            readable,
            records: 4096,
            boot_banner: banner,
            files: usize::from(readable),
            load_lines: if with_name {
                vec![LoadLine {
                    name: "testmod".into(),
                    text: "testmod: （systemd 日誌裡的載入訊息）".into(),
                    epoch: None,
                    seq: None,
                }]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }

    #[test]
    fn journal_with_banner_is_covered_and_names_agree() {
        let (mut o, p) = infected();
        o.logs.push(journal_copy(true, true, true));
        let j = judge_modules(&o, &p);
        assert!(j
            .coverage
            .iter()
            .any(|c| c.source == "journal" && c.covered));
        assert_eq!(j.named[0].sources.len(), 3);
        assert!(j.notes.is_empty());
    }

    #[test]
    fn journal_removed_is_not_covered_and_reminds_when_something_is_hidden() {
        let (mut o, p) = infected();
        o.logs.push(journal_copy(false, false, false));
        let j = judge_modules(&o, &p);
        assert!(j
            .coverage
            .iter()
            .any(|c| c.source == "journal" && !c.covered));
        assert!(j.notes.iter().any(|n| n.contains("systemd 日誌：")));
        assert_eq!(j.named.len(), 1, "名字仍由另外兩份副本取得");
    }

    #[test]
    fn covered_journal_missing_the_name_is_noted_as_inconsistent() {
        let (mut o, p) = infected();
        o.logs.push(journal_copy(false, true, true));
        let j = judge_modules(&o, &p);
        assert!(j
            .notes
            .iter()
            .any(|n| n.contains("systemd 日誌") && n.contains("testmod")));
    }

    #[test]
    fn wiped_messages_is_not_covered() {
        let (mut o, p) = infected();
        o.logs[1].boot_banner = false;
        o.logs[1].min_epoch = None;
        o.logs[1].load_lines.clear();
        let j = judge_modules(&o, &p);
        assert!(j
            .coverage
            .iter()
            .any(|c| c.source == "messages" && !c.covered));
        assert_eq!(j.notes.len(), 1, "只提醒副本不涵蓋，不算『不一致』");
        assert!(j.notes[0].contains("系統紀錄檔：") && j.notes[0].contains("沒有開機訊息"));
        let _ = LoadLine {
            name: String::new(),
            text: String::new(),
            epoch: None,
            seq: None,
        };
    }

    #[test]
    fn rotated_out_boot_messages_are_not_called_suspected_wiping() {
        let copy = LogCopy {
            source: "messages".into(),
            readable: true,
            boot_banner: false,
            min_epoch: Some(1_772_534_741),
            files: 5,
            ..Default::default()
        };
        let c = coverage_of(&copy, Some(1_772_323_210), true, 1_772_323_200);
        assert!(!c.covered);
        assert!(c.reason.contains("沒有開機訊息"), "{}", c.reason);
        assert!(
            c.reason.contains("最早只到 2026-03-03 18:45:41 UTC+8"),
            "{}",
            c.reason
        );
        assert!(c.reason.contains("輪替"), "{}", c.reason);
        assert!(!c.reason.contains("疑似被清除"), "{}", c.reason);
    }

    #[test]
    fn missing_banner_inside_the_covered_period_is_the_suspicious_case() {
        let copy = LogCopy {
            source: "messages".into(),
            readable: true,
            boot_banner: false,
            min_epoch: Some(1_000),
            files: 2,
            ..Default::default()
        };
        let c = coverage_of(&copy, Some(5_000), true, 4_000);
        assert!(c.reason.contains("涵蓋本次開機的時間"), "{}", c.reason);
        assert!(c.reason.contains("疑似被刪掉部分內容"), "{}", c.reason);
    }

    #[test]
    fn unreadable_logs_say_no_permission_when_not_root() {
        let j = LogCopy {
            source: "journal".into(),
            readable: false,
            ..Default::default()
        };
        let m = LogCopy {
            source: "messages".into(),
            readable: false,
            ..Default::default()
        };
        for c in [&j, &m] {
            let non_root = coverage_of(c, None, false, 100);
            assert!(
                non_root.reason.contains("沒有權限讀取"),
                "{}",
                non_root.reason
            );
            assert!(!non_root.reason.contains("清除"), "{}", non_root.reason);
        }
        let root = coverage_of(&j, None, true, 100);
        assert!(root.reason.contains("讀不到任何日誌檔"), "{}", root.reason);
        assert!(!root.reason.contains("疑似被清除"), "{}", root.reason);
    }

    #[test]
    fn a_messages_copy_with_unread_files_is_never_covered() {
        let copy = LogCopy {
            source: "messages".into(),
            readable: true,
            boot_banner: true,
            min_epoch: Some(100),
            files: 1,
            unread: 1,
            ..Default::default()
        };
        let c = coverage_of(&copy, Some(200), true, 0);
        assert!(!c.covered);
        assert!(c.reason.contains("太大"), "{}", c.reason);
        let ok = LogCopy { unread: 0, ..copy };
        assert!(coverage_of(&ok, Some(200), true, 0).covered);
    }
}

use crate::model::{ConnFacts, ConnSample, HeldSocket, PortKey, Proto};
use std::collections::BTreeMap;

pub fn conn_gap(s: &ConnSample) -> i64 {
    (s.inuse4 + s.inuse6 + s.tw) - (s.e4 + s.w4 + s.e6 + s.w6)
}

pub fn patrol_hit(s: &ConnSample) -> bool {
    conn_gap(s) >= 1 || (udp_stable(s) && udp_gap(s) >= 1)
}

pub fn udp_gap(s: &ConnSample) -> i64 {
    (s.su4 + s.sl4 + s.su6 + s.sl6) - (s.ru4 + s.rl4 + s.ru6 + s.rl6)
}

pub fn udp_stable(s: &ConnSample) -> bool {
    s.su4 + s.sl4 + s.su6 + s.sl6 == s.su_after
}

fn udp_recent_gaps(samples: &[ConnSample]) -> Vec<i64> {
    let stable: Vec<i64> = samples
        .iter()
        .filter(|s| udp_stable(s))
        .map(udp_gap)
        .collect();
    stable[stable.len().saturating_sub(3)..].to_vec()
}

pub fn udp_stable_counts(samples: &[ConnSample]) -> (usize, usize) {
    (
        samples.iter().filter(|s| udp_stable(s)).count(),
        samples.len(),
    )
}

fn gap_fired(samples: &[ConnSample], gap: fn(&ConnSample) -> i64) -> bool {
    if samples.len() < 3 {
        return false;
    }
    samples[samples.len() - 3..]
        .iter()
        .filter(|s| gap(s) >= 1)
        .count()
        >= 2
}

pub fn conn_gap_fired(samples: &[ConnSample]) -> bool {
    gap_fired(samples, conn_gap)
}

pub fn udp_gap_fired(samples: &[ConnSample]) -> bool {
    let recent = udp_recent_gaps(samples);
    recent.len() == 3 && recent.iter().all(|g| *g >= 1)
}

pub fn unexplained_hidden_sockets(samples: &[ConnSample], held: &[HeldSocket]) -> i64 {
    let tail_min =
        |v: Vec<i64>| -> i64 { v.iter().rev().take(3).copied().min().unwrap_or(0).max(0) };
    let tcp = tail_min(samples.iter().map(conn_gap).collect());
    let udp = tail_min(
        samples
            .iter()
            .filter(|s| udp_stable(s))
            .map(udp_gap)
            .collect(),
    );
    let held: BTreeSet<u64> = held.iter().map(|h| h.inode).collect();
    tcp + udp - held.len() as i64
}

pub fn evidence_class_count(
    samples: &[ConnSample],
    has_holder: bool,
    has_hidden_ports: bool,
) -> usize {
    usize::from(conn_gap_fired(samples) || udp_gap_fired(samples))
        + usize::from(has_holder)
        + usize::from(has_hidden_ports)
}

pub fn port_candidates(c: &ConnFacts) -> Vec<PortKey> {
    c.inuse_ports_pass1
        .iter()
        .filter(|p| c.inuse_ports_pass2.contains(p))
        .filter(|p| !c.listed_ports_before.contains(p))
        .copied()
        .collect()
}

pub fn hidden_ports(c: &ConnFacts) -> Vec<PortKey> {
    let mut v: Vec<PortKey> = port_candidates(c)
        .into_iter()
        .filter(|p| !c.recheck_vanished.contains(p))
        .filter(|p| !c.listed_ports_after.contains(p))
        .collect();
    for q in &c.peer_queries {
        if q.state.is_none() || !c.held.iter().any(|h| h.pid == q.pid) {
            continue;
        }
        let Some(port) = endpoint_port(&q.local) else {
            continue;
        };
        let k = PortKey::tcp(port);
        if !v.contains(&k)
            && !c.listed_ports_before.contains(&k)
            && !c.listed_ports_after.contains(&k)
        {
            v.push(k);
        }
    }
    v
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EndpointSource {
    Conntrack,
    Capture,
    Ptrace,
}

impl EndpointSource {
    pub fn label(self) -> &'static str {
        match self {
            EndpointSource::Conntrack => "連線追蹤表",
            EndpointSource::Capture => "旁聽封包",
            EndpointSource::Ptrace => "暫時查詢行程（最後手段，已完整還原）",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub proto: Proto,
    pub a: String,
    pub b: String,
    pub sources: Vec<EndpointSource>,
    pub state: Option<String>,
    pub unreplied: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub proto: Proto,
    pub addr: String,
    pub bound_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub sockets: usize,
    pub inodes: Vec<u64>,
    pub is_kernel_thread: bool,
    pub from_visible: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnGroup {
    pub holders: Vec<Holder>,
    pub ports: Vec<PortKey>,
    pub endpoints: Vec<Endpoint>,
    pub listeners: Vec<Listener>,
    pub unresolved_ports: Vec<PortKey>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnJudgement {
    pub address_candidates: Vec<String>,
    pub groups: Vec<ConnGroup>,
    pub shared_ports: Vec<PortKey>,
    pub shared_endpoints: Vec<Endpoint>,
    pub shared_listeners: Vec<Listener>,
    pub gap_fired: bool,
    pub udp_gap_fired: bool,
    pub gaps: Vec<i64>,
    pub udp_gaps: Vec<i64>,
    pub udp_stable: usize,
    pub udp_total: usize,
    pub hidden_ports: Vec<PortKey>,
    pub port_addrs: Vec<(PortKey, Vec<String>)>,
    pub holders: Vec<Holder>,
    pub endpoints: Vec<Endpoint>,
    pub unresolved_ports: Vec<PortKey>,
    pub listeners: Vec<Listener>,
    pub evidence: Vec<&'static str>,
    pub evidence_classes: usize,
    pub confirmed: bool,
    pub pending: bool,
}

fn endpoint_port(e: &str) -> Option<u16> {
    e.rsplit_once(':')?.1.parse().ok()
}

pub(crate) fn is_ip_endpoint(e: &str) -> bool {
    endpoint_port(e).is_some_and(|p| p != 0)
}

fn bracket(addr: &str) -> String {
    if addr.contains(':') && !addr.starts_with('[') {
        format!("[{}]", addr)
    } else {
        addr.to_string()
    }
}

fn conntrack_state(line: &str) -> (Option<String>, bool) {
    let t: Vec<&str> = line.split_whitespace().collect();
    let state = t
        .get(5)
        .filter(|s| !s.contains('=') && !s.starts_with('['))
        .map(|s| s.to_string());
    (state, t.contains(&"[UNREPLIED]"))
}

fn conntrack_pair(line: &str) -> Option<(String, String)> {
    let get = |k: &str| crate::collect_conn::key_value(line, k).map(String::from);
    let (src, dst, sp, dp) = (get("src=")?, get("dst=")?, get("sport=")?, get("dport=")?);
    Some((
        format!("{}:{}", bracket(&src), sp),
        format!("{}:{}", bracket(&dst), dp),
    ))
}

fn add_endpoint(list: &mut Vec<Endpoint>, proto: Proto, a: &str, b: &str, source: EndpointSource) {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    if let Some(e) = list
        .iter_mut()
        .find(|e| e.proto == proto && e.a == x && e.b == y)
    {
        if !e.sources.contains(&source) {
            e.sources.push(source);
            e.sources.sort();
        }
    } else {
        list.push(Endpoint {
            proto,
            a: x.to_string(),
            b: y.to_string(),
            sources: vec![source],
            state: None,
            unreplied: false,
        });
    }
}

fn proto_of_local(hidden: &[PortKey], local: &str) -> Proto {
    match endpoint_port(local) {
        Some(port)
            if !hidden.contains(&PortKey::tcp(port)) && hidden.contains(&PortKey::udp(port)) =>
        {
            Proto::Udp
        }
        _ => Proto::Tcp,
    }
}

fn local_is_hidden(hidden: &[PortKey], local: &str) -> bool {
    endpoint_port(local).is_some_and(|port| {
        hidden.contains(&PortKey {
            proto: proto_of_local(hidden, local),
            port,
        })
    })
}

#[allow(clippy::if_same_then_else)]
pub fn derive_endpoints(c: &ConnFacts, hidden: &[PortKey]) -> (Vec<Endpoint>, Vec<Listener>) {
    let mine = |proto: Proto, endpoint: &str| -> bool {
        let Some((addr, port)) = endpoint.rsplit_once(':') else {
            return false;
        };
        let Ok(port) = port.parse::<u16>() else {
            return false;
        };
        let key = PortKey { proto, port };
        if !hidden.contains(&key) {
            return false;
        }
        match c.port_local_addrs.iter().find(|(k, _)| *k == key) {
            Some((_, addrs)) if !addrs.is_empty() => addrs.iter().any(|a| a == addr),
            _ => true,
        }
    };
    let mut endpoints = Vec::new();
    let mut listeners: Vec<Listener> = Vec::new();
    for line in &c.conntrack_lines {
        let Some(proto) = crate::collect_conn::conntrack_proto(line) else {
            continue;
        };
        if let Some((a, b)) = conntrack_pair(line) {
            if mine(proto, &a) || mine(proto, &b) {
                add_endpoint(&mut endpoints, proto, &a, &b, EndpointSource::Conntrack);
                let (state, unreplied) = conntrack_state(line);
                if let Some(e) = endpoints.iter_mut().find(|e| {
                    e.proto == proto && ((e.a == a && e.b == b) || (e.a == b && e.b == a))
                }) {
                    if e.state.is_none() {
                        e.state = state;
                    }
                    e.unreplied |= unreplied;
                }
            }
        }
    }
    for cp in &c.capture_pairs {
        if mine(cp.proto, &cp.a) || mine(cp.proto, &cp.b) {
            add_endpoint(
                &mut endpoints,
                cp.proto,
                &cp.a,
                &cp.b,
                EndpointSource::Capture,
            );
        }
    }
    let visible_pids: Vec<u32> = c.visible_held.iter().map(|h| h.pid).collect();
    for q in &c.peer_queries {
        if !is_ip_endpoint(&q.local) {
            continue;
        }
        let proto = proto_of_local(hidden, &q.local);
        if visible_pids.contains(&q.pid) && !local_is_hidden(hidden, &q.local) {
            continue;
        }
        if q.error.is_none() && q.peer != "-" {
            add_endpoint(
                &mut endpoints,
                proto,
                &q.local,
                &q.peer,
                EndpointSource::Ptrace,
            );
            if q.state == Some(TCP_SYN_SENT) {
                if let Some(e) = endpoints.iter_mut().find(|e| {
                    e.proto == proto
                        && ((e.a == q.local && e.b == q.peer) || (e.a == q.peer && e.b == q.local))
                }) {
                    if e.state.is_none() {
                        e.state = Some("SYN_SENT".to_string());
                    }
                }
            }
        } else if q.state == Some(TCP_CLOSE) {
            if !listeners
                .iter()
                .any(|l| l.proto == proto && l.addr == q.local)
            {
                listeners.push(Listener {
                    proto,
                    addr: q.local.clone(),
                    bound_only: true,
                });
            }
        } else if q.state.is_none() && !local_is_hidden(hidden, &q.local) {
        } else if q.state.is_some_and(|st| st != TCP_LISTEN) {
        } else if !listeners
            .iter()
            .any(|l| l.proto == proto && l.addr == q.local)
        {
            listeners.push(Listener {
                proto,
                addr: q.local.clone(),
                bound_only: false,
            });
        }
    }
    (endpoints, listeners)
}

pub fn unresolved_ports(c: &ConnFacts, hidden: &[PortKey]) -> Vec<PortKey> {
    let (endpoints, listeners) = derive_endpoints(c, hidden);
    let known: Vec<PortKey> = endpoints
        .iter()
        .flat_map(|e| {
            [
                endpoint_port(&e.a).map(|port| PortKey {
                    proto: e.proto,
                    port,
                }),
                endpoint_port(&e.b).map(|port| PortKey {
                    proto: e.proto,
                    port,
                }),
            ]
        })
        .flatten()
        .chain(listeners.iter().filter_map(|l| {
            endpoint_port(&l.addr).map(|port| PortKey {
                proto: l.proto,
                port,
            })
        }))
        .collect();
    hidden
        .iter()
        .filter(|p| !known.contains(p))
        .copied()
        .collect()
}

fn query_ports(c: &ConnFacts, hidden: &[PortKey], pid: u32) -> Vec<PortKey> {
    let mut v: Vec<PortKey> = c
        .peer_queries
        .iter()
        .filter(|q| q.pid == pid && is_ip_endpoint(&q.local))
        .filter_map(|q| {
            endpoint_port(&q.local).map(|port| PortKey {
                proto: proto_of_local(hidden, &q.local),
                port,
            })
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

type Grouped = (Vec<ConnGroup>, Vec<PortKey>, Vec<Endpoint>, Vec<Listener>);

fn merge_by_shared_socket(holders: &[Holder]) -> Vec<Vec<Holder>> {
    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut root = x;
        while parent[root] != root {
            root = parent[root];
        }
        let mut cur = x;
        while parent[cur] != root {
            let next = parent[cur];
            parent[cur] = root;
            cur = next;
        }
        root
    }
    let mut parent: Vec<usize> = (0..holders.len()).collect();
    let mut owner: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, h) in holders.iter().enumerate() {
        for ino in &h.inodes {
            match owner.get(ino) {
                Some(&j) => {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    if a != b {
                        parent[a] = b;
                    }
                }
                None => {
                    owner.insert(*ino, i);
                }
            }
        }
    }
    let mut comps: BTreeMap<usize, Vec<Holder>> = BTreeMap::new();
    for (i, h) in holders.iter().enumerate() {
        let root = find(&mut parent, i);
        comps.entry(root).or_default().push(h.clone());
    }
    let mut out: Vec<Vec<Holder>> = comps.into_values().collect();
    out.sort_by_key(|g| g.first().map_or(0, |h| h.pid));
    out
}

fn group_connections(
    c: &ConnFacts,
    hidden: &[PortKey],
    components: &[Vec<Holder>],
    endpoints: &[Endpoint],
    listeners: &[Listener],
    unresolved: &[PortKey],
) -> Grouped {
    let in_ports = |ports: &[PortKey], proto: Proto, addr: &str| {
        endpoint_port(addr).is_some_and(|port| ports.contains(&PortKey { proto, port }))
    };
    let mk = |holders: Vec<Holder>, ports: Vec<PortKey>| ConnGroup {
        endpoints: endpoints
            .iter()
            .filter(|e| in_ports(&ports, e.proto, &e.a) || in_ports(&ports, e.proto, &e.b))
            .cloned()
            .collect(),
        listeners: listeners
            .iter()
            .filter(|l| in_ports(&ports, l.proto, &l.addr))
            .cloned()
            .collect(),
        unresolved_ports: unresolved
            .iter()
            .filter(|p| ports.contains(p))
            .copied()
            .collect(),
        holders,
        ports,
    };
    if components.len() <= 1 {
        let comp = components.first().cloned().unwrap_or_default();
        let mut ports = hidden.to_vec();
        for h in comp.iter().filter(|h| !h.from_visible) {
            ports.extend(query_ports(c, hidden, h.pid));
        }
        ports.sort_unstable();
        ports.dedup();
        return (vec![mk(comp, ports)], Vec::new(), Vec::new(), Vec::new());
    }
    let groups: Vec<ConnGroup> = components
        .iter()
        .map(|comp| {
            let mut ports: Vec<PortKey> = comp
                .iter()
                .flat_map(|h| query_ports(c, hidden, h.pid))
                .collect();
            ports.sort_unstable();
            ports.dedup();
            mk(comp.clone(), ports)
        })
        .collect();
    let claimed: Vec<PortKey> = groups
        .iter()
        .flat_map(|g| g.ports.iter().copied())
        .collect();
    (
        groups,
        hidden
            .iter()
            .filter(|p| !claimed.contains(p))
            .copied()
            .collect(),
        endpoints
            .iter()
            .filter(|e| !in_ports(&claimed, e.proto, &e.a) && !in_ports(&claimed, e.proto, &e.b))
            .cloned()
            .collect(),
        listeners
            .iter()
            .filter(|l| !in_ports(&claimed, l.proto, &l.addr))
            .cloned()
            .collect(),
    )
}

pub fn judge_connections(obs: &Observation, procs: &ProcJudgement) -> ConnJudgement {
    let c = &obs.conn;
    let tcp_gap_fired = conn_gap_fired(&obs.conn_samples);
    let udp_fired = udp_gap_fired(&obs.conn_samples);
    let last3 = |gap: fn(&ConnSample) -> i64| -> Vec<i64> {
        obs.conn_samples
            .iter()
            .rev()
            .take(3)
            .rev()
            .map(gap)
            .collect()
    };
    let hidden = hidden_ports(c);

    let mut by_pid: BTreeMap<u32, Holder> = BTreeMap::new();
    for h in &c.held {
        by_pid
            .entry(h.pid)
            .and_modify(|x| {
                x.sockets += 1;
                x.inodes.push(h.inode);
            })
            .or_insert(Holder {
                pid: h.pid,
                comm: h.comm.clone(),
                exe: h.exe.clone(),
                sockets: 1,
                inodes: vec![h.inode],
                is_kernel_thread: h.exe.is_none()
                    && procs
                        .confirmed
                        .iter()
                        .any(|p| p.info.pid == h.pid && p.is_kernel_thread),
                from_visible: false,
            });
    }
    let mut visible: BTreeMap<u32, Holder> = BTreeMap::new();
    for h in &c.visible_held {
        let matched = c.peer_queries.iter().any(|q| {
            q.pid == h.pid && is_ip_endpoint(&q.local) && local_is_hidden(&hidden, &q.local)
        });
        if !matched || by_pid.contains_key(&h.pid) {
            continue;
        }
        visible
            .entry(h.pid)
            .and_modify(|x| {
                x.sockets += 1;
                x.inodes.push(h.inode);
            })
            .or_insert(Holder {
                pid: h.pid,
                comm: h.comm.clone(),
                exe: h.exe.clone(),
                sockets: 1,
                inodes: vec![h.inode],
                is_kernel_thread: false,
                from_visible: true,
            });
    }
    by_pid.extend(visible);
    let holders: Vec<Holder> = by_pid.into_values().collect();
    let components = merge_by_shared_socket(&holders);

    let (endpoints, listeners) = derive_endpoints(c, &hidden);
    let unresolved_ports = unresolved_ports(c, &hidden);

    let mut evidence = Vec::new();
    if tcp_gap_fired {
        evidence.push("核心登記的 TCP 數量比連線表多");
    }
    if udp_fired {
        evidence.push("核心登記的 UDP 數量比連線表多");
    }
    if !holders.is_empty() {
        evidence.push("有行程握著不在任何連線表的 socket");
    }
    if hidden.iter().any(|k| k.proto == Proto::Tcp) {
        evidence.push("有 TCP 埠號被占用卻沒有列在連線表");
    }
    if hidden.iter().any(|k| k.proto == Proto::Udp) {
        evidence.push("有 UDP 埠號被占用卻沒有列在連線表");
    }
    let evidence_classes =
        evidence_class_count(&obs.conn_samples, !holders.is_empty(), !hidden.is_empty());
    let (groups, shared_ports, shared_endpoints, shared_listeners) = group_connections(
        c,
        &hidden,
        &components,
        &endpoints,
        &listeners,
        &unresolved_ports,
    );
    let address_candidates: Vec<String> = c
        .tcp_metrics
        .iter()
        .filter(|a| !c.visible_remotes.contains(a))
        .cloned()
        .collect();
    ConnJudgement {
        address_candidates,
        groups,
        shared_ports,
        shared_endpoints,
        shared_listeners,
        gap_fired: tcp_gap_fired,
        udp_gap_fired: udp_fired,
        gaps: last3(conn_gap),
        udp_gaps: udp_recent_gaps(&obs.conn_samples),
        udp_stable: udp_stable_counts(&obs.conn_samples).0,
        udp_total: udp_stable_counts(&obs.conn_samples).1,
        port_addrs: c.port_local_addrs.clone(),
        hidden_ports: hidden,
        holders,
        endpoints,
        unresolved_ports,
        listeners,
        confirmed: evidence_classes >= 2,
        pending: evidence_classes == 1,
        evidence_classes,
        evidence,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileJudgement {
    pub confirmed: Vec<HiddenFile>,
    pub total: usize,
    pub dirs_walked: u64,
    pub devices_walked: usize,
    pub devices_truncated: usize,
    pub unavailable: Vec<(String, String, String)>,
    pub proc_covers: Vec<crate::model::ProcCover>,
    pub dir_covers: Vec<crate::model::DirCover>,
    pub skipped_mounts: u64,
}

pub fn judge_files(obs: &Observation) -> FileJudgement {
    let mut j = FileJudgement::default();
    if !obs.disk.ran {
        return j;
    }
    j.confirmed = obs.disk.hidden.clone();
    j.proc_covers = obs.disk.proc_covers.clone();
    j.dir_covers = obs.disk.dir_covers.clone();
    j.total = obs.disk.hidden_total.max(obs.disk.hidden.len());
    for d in &obs.disk.devices {
        match &d.status {
            DiskStatus::Walked(w) => {
                j.devices_walked += 1;
                j.dirs_walked += w.dirs;
                j.skipped_mounts += w.skipped_mounts;
                if w.truncated {
                    j.devices_truncated += 1;
                }
            }
            DiskStatus::Unavailable(why) => {
                j.unavailable
                    .push((d.mount_point.clone(), d.fstype.clone(), why.clone()))
            }
        }
    }
    j
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentJudgement {
    pub items: Vec<crate::model::ContentMismatch>,
}

pub fn judge_content(obs: &Observation) -> ContentJudgement {
    ContentJudgement {
        items: if obs.content_scan.ran {
            obs.content_scan.items.clone()
        } else {
            Vec::new()
        },
    }
}

pub const DELETED_FAST_SECS: i64 = 600;
const NEWER_SLACK_SECS: i64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Disguise {
    KernelThreadName,
    NameMismatch,
    StagingDir(String),
    HiddenName,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletedItem {
    pub proc: crate::model::DeletedProc,
    pub start_epoch: i64,
    pub delete_epoch: i64,
    pub secs_to_delete: Option<i64>,
    pub fast: bool,
    pub disguise: Vec<Disguise>,
    pub public_out: Vec<crate::model::ProcSocket>,
    pub internal_out: Vec<crate::model::ProcSocket>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeletedJudgement {
    pub ran: bool,
    pub checked: usize,
    pub other_ns: usize,
    pub confirmed: Vec<DeletedItem>,
    pub pending: Vec<DeletedItem>,
    pub updated: Vec<crate::model::DeletedProc>,
    pub quiet: Vec<crate::model::DeletedProc>,
    pub unsettled: usize,
    pub omitted: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteKind {
    None,
    Internal,
    Public,
}

pub fn remote_kind(ip: &str) -> RemoteKind {
    use std::net::IpAddr;
    let Ok(a) = ip.parse::<IpAddr>() else {
        return RemoteKind::None;
    };
    match a {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                RemoteKind::None
            } else if v4.is_private()
                || v4.is_link_local()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
            {
                RemoteKind::Internal
            } else {
                RemoteKind::Public
            }
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                RemoteKind::None
            } else if seg[0] & 0xfe00 == 0xfc00 || seg[0] & 0xffc0 == 0xfe80 {
                RemoteKind::Internal
            } else {
                RemoteKind::Public
            }
        }
    }
}

fn is_outbound(s: &crate::model::ProcSocket) -> bool {
    use crate::model::Proto;
    if s.local_port_listening || s.remote_port == 0 {
        return false;
    }
    match s.proto {
        Proto::Tcp => !matches!(s.state.as_str(), "0A" | "06" | "07"),
        Proto::Udp => true,
    }
}

fn clean_name(path_or_name: &str) -> String {
    let base = path_or_name
        .split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("");
    base.split(';')
        .next()
        .unwrap_or("")
        .trim_end_matches(':')
        .to_string()
}

fn name_consistent(comm: &str, name: &str) -> bool {
    if comm.is_empty() || name.is_empty() {
        return false;
    }
    name.starts_with(comm) || comm.starts_with(name)
}

fn disguise_of(p: &crate::model::DeletedProc) -> Vec<Disguise> {
    let mut v = Vec::new();
    if p.comm.contains('/') {
        v.push(Disguise::KernelThreadName);
    } else {
        let link_path = p.exe_link.strip_suffix(" (deleted)").unwrap_or(&p.exe_link);
        let names = [clean_name(&p.argv0), clean_name(link_path)];
        if !p.comm.is_empty() && !names.iter().any(|n| name_consistent(&p.comm, n)) {
            v.push(Disguise::NameMismatch);
        }
    }
    let link_path = p.exe_link.strip_suffix(" (deleted)").unwrap_or(&p.exe_link);
    for dir in ["/tmp", "/var/tmp", "/dev/shm", "/run/user"] {
        if link_path == dir || link_path.starts_with(&format!("{}/", dir)) {
            v.push(Disguise::StagingDir(dir.to_string()));
            break;
        }
    }
    let base = link_path.rsplit('/').next().unwrap_or("");
    if base.starts_with('.') && base.len() > 1 {
        v.push(Disguise::HiddenName);
    }
    v
}

fn replaced_by_newer_file(p: &crate::model::DeletedProc, start_epoch: i64) -> bool {
    use crate::model::PathNow;
    match p.argv0_now {
        PathNow::File {
            ino, dev, ctime, ..
        } => {
            (ino != p.ino || dev != p.dev)
                && start_epoch > 0
                && ctime >= start_epoch - NEWER_SLACK_SECS
        }
        _ => false,
    }
}

pub fn judge_deleted(obs: &Observation, procs: &ProcJudgement) -> DeletedJudgement {
    use crate::model::Proto;
    let scan = &obs.deleted_scan;
    let mut out = DeletedJudgement {
        ran: scan.ran,
        checked: scan.checked,
        other_ns: scan.other_ns,
        omitted: scan.omitted,
        ..Default::default()
    };
    if !scan.ran {
        return out;
    }
    let tck = obs.meta.clk_tck.max(1);
    for p in &scan.items {
        if !p.same_ns || procs.confirmed.iter().any(|h| h.info.pid == p.pid) {
            continue;
        }
        if !p.fstat_ok || p.nlink != 0 {
            out.unsettled += 1;
            continue;
        }
        let start_epoch = if obs.meta.btime > 0 && p.starttime > 0 {
            (obs.meta.btime + p.starttime / tck) as i64
        } else {
            0
        };
        if replaced_by_newer_file(p, start_epoch) {
            out.updated.push(p.clone());
            continue;
        }
        let secs_to_delete = if start_epoch > 0 && p.ctime >= start_epoch {
            Some(p.ctime - start_epoch)
        } else {
            None
        };
        let fast = secs_to_delete.is_some_and(|s| s <= DELETED_FAST_SECS);
        let disguise = disguise_of(p);
        let mut public_out = Vec::new();
        let mut internal_out = Vec::new();
        for sk in p.sockets.iter().filter(|s| is_outbound(s)) {
            match remote_kind(&sk.remote_ip) {
                RemoteKind::Public => public_out.push(sk.clone()),
                RemoteKind::Internal => internal_out.push(sk.clone()),
                RemoteKind::None => {}
            }
        }
        let _ = Proto::Udp;
        let item = DeletedItem {
            proc: p.clone(),
            start_epoch,
            delete_epoch: p.ctime,
            secs_to_delete,
            fast,
            disguise: disguise.clone(),
            public_out: public_out.clone(),
            internal_out: internal_out.clone(),
        };
        if !public_out.is_empty() && (fast || !disguise.is_empty()) {
            out.confirmed.push(item);
        } else if fast || !disguise.is_empty() || !public_out.is_empty() || !internal_out.is_empty()
        {
            out.pending.push(item);
        } else {
            out.quiet.push(p.clone());
        }
    }
    out
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExeJudgement {
    pub items: Vec<crate::model::ExeContradiction>,
    pub checked: usize,
}

pub fn judge_exe(obs: &Observation, procs: &ProcJudgement) -> ExeJudgement {
    if !obs.exe_scan.ran {
        return ExeJudgement::default();
    }
    ExeJudgement {
        items: obs
            .exe_scan
            .items
            .iter()
            .filter(|c| !procs.confirmed.iter().any(|h| h.info.pid == c.pid))
            .cloned()
            .collect(),
        checked: obs.exe_scan.checked,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginKind {
    Login { uid: u32, ses: Option<u32> },
    Service { unit: String },
    Neither,
    Unreadable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginJudgement {
    pub pid: u32,
    pub kind: OriginKind,
    pub facts: OriginFacts,
    pub audit: Option<AuditLogin>,
}

pub fn judge_origins(obs: &Observation, procs: &ProcJudgement) -> Vec<OriginJudgement> {
    if !obs.origin.ran {
        return Vec::new();
    }
    procs
        .confirmed
        .iter()
        .filter(|h| !h.is_kernel_thread)
        .filter_map(|h| {
            let facts = obs.origin.items.iter().find(|f| f.pid == h.info.pid)?;
            let kind = match facts.loginuid {
                None => OriginKind::Unreadable,
                Some(uid) if facts.has_login_identity() => OriginKind::Login {
                    uid,
                    ses: facts.sessionid.filter(|&n| n != crate::model::ID_UNSET),
                },
                Some(_) => match facts.service_unit() {
                    Some(unit) => OriginKind::Service {
                        unit: unit.to_string(),
                    },
                    None => OriginKind::Neither,
                },
            };
            let audit = match &kind {
                OriginKind::Login { ses: Some(n), .. } => obs
                    .origin
                    .audit_logins
                    .iter()
                    .filter(|l| l.ses == *n && l.epoch >= obs.meta.btime)
                    .min_by_key(|l| l.epoch)
                    .cloned(),
                _ => None,
            };
            Some(OriginJudgement {
                pid: h.info.pid,
                kind,
                facts: facts.clone(),
                audit,
            })
        })
        .collect()
}

#[cfg(test)]
mod conn_tests {
    use super::*;
    use crate::model::{CapturePair, HeldSocket, PeerQuery};
    use crate::recording::tests::sample_observation;

    fn t(p: u16) -> PortKey {
        PortKey::tcp(p)
    }

    fn u(p: u16) -> PortKey {
        PortKey::udp(p)
    }

    fn cs(inuse4: i64, tw: i64, inuse6: i64, e4: i64, w4: i64, e6: i64, w6: i64) -> ConnSample {
        ConnSample {
            inuse4,
            tw,
            inuse6,
            e4,
            w4,
            e6,
            w6,
            ..Default::default()
        }
    }

    fn us(su4: i64, su6: i64, ru4: i64, ru6: i64) -> ConnSample {
        ConnSample {
            su4,
            su6,
            su_after: su4 + su6,
            ru4,
            ru6,
            ..Default::default()
        }
    }

    #[test]
    fn gap_merges_ipv4_and_ipv6_tw() {
        assert_eq!(conn_gap(&cs(5, 70, 4, 5, 0, 4, 70)), 0);
        assert_eq!(conn_gap(&cs(8, 0, 3, 5, 0, 3, 0)), 3, "多 3 個 socket");
    }

    #[test]
    fn gap_rule_is_two_of_last_three() {
        let ok = cs(5, 0, 3, 5, 0, 3, 0);
        let bad = cs(8, 0, 3, 5, 0, 3, 0);
        assert!(!conn_gap_fired(&[ok.clone(), ok.clone(), ok.clone()]));
        assert!(!conn_gap_fired(&[bad.clone(), ok.clone(), ok.clone()]));
        assert!(conn_gap_fired(&[ok.clone(), bad.clone(), bad.clone()]));
        assert!(!conn_gap_fired(&[bad.clone(), bad]));
    }

    #[test]
    fn udp_gap_counts_all_four_tables_and_uses_the_same_rule() {
        assert_eq!(udp_gap(&us(5, 3, 3, 3)), 2);
        assert_eq!(udp_gap(&us(3, 3, 3, 3)), 0);
        let lite = ConnSample {
            sl4: 1,
            ..us(3, 3, 3, 3)
        };
        assert_eq!(udp_gap(&lite), 1, "UDP-Lite 的登記數也算");
        let ok = us(3, 3, 3, 3);
        let bad = us(5, 3, 3, 3);
        assert!(!udp_gap_fired(&[bad.clone(), ok.clone(), ok.clone()]));
        assert!(
            !udp_gap_fired(&[ok.clone(), bad.clone(), bad.clone()]),
            "最近 3 份穩定樣本要全部有缺口，2 份不夠"
        );
        assert!(udp_gap_fired(&[
            ok.clone(),
            bad.clone(),
            bad.clone(),
            bad.clone()
        ]));
        assert!(!udp_gap_fired(&[bad.clone(), bad]), "不足 3 份樣本不判定");
        assert!(!conn_gap_fired(&[
            us(5, 3, 3, 3),
            us(5, 3, 3, 3),
            us(5, 3, 3, 3)
        ]));
        let tcp_gap = cs(8, 0, 3, 5, 0, 3, 0);
        assert!(!udp_gap_fired(&[tcp_gap.clone(), tcp_gap.clone(), tcp_gap]));
    }

    #[test]
    fn hidden_ports_need_both_passes_and_absence_from_both_tables() {
        let mut c = ConnFacts {
            inuse_ports_pass1: vec![t(22), t(100), t(200), t(300)],
            inuse_ports_pass2: vec![t(22), t(100), t(200)],
            listed_ports_before: vec![t(22), t(100)],
            listed_ports_after: vec![t(22), t(200)],
            ..Default::default()
        };
        assert!(
            hidden_ports(&c).is_empty(),
            "100、200 各有一次在表上；300 只出現一輪"
        );
        c.listed_ports_before = vec![t(22)];
        c.listed_ports_after = vec![t(22)];
        assert_eq!(hidden_ports(&c), vec![t(100), t(200)]);
    }

    #[test]
    fn a_candidate_that_vanishes_on_recheck_is_a_coincidence_not_a_hidden_port() {
        let mut c = ConnFacts {
            inuse_ports_pass1: vec![u(54349), t(22)],
            inuse_ports_pass2: vec![u(54349), t(22)],
            listed_ports_before: vec![t(22)],
            listed_ports_after: vec![t(22)],
            recheck_rounds: 4,
            ..Default::default()
        };
        assert_eq!(port_candidates(&c), vec![u(54349)]);
        assert_eq!(
            hidden_ports(&c),
            vec![u(54349)],
            "沒有重驗結果時，候選就是被藏"
        );
        c.recheck_vanished = vec![u(54349)];
        assert!(hidden_ports(&c).is_empty());
    }

    #[test]
    fn same_port_number_in_tcp_and_udp_are_different_ports() {
        let c = ConnFacts {
            inuse_ports_pass1: vec![t(53), u(53)],
            inuse_ports_pass2: vec![t(53), u(53)],
            listed_ports_before: vec![t(53)],
            listed_ports_after: vec![t(53)],
            ..Default::default()
        };
        assert_eq!(hidden_ports(&c), vec![u(53)]);
    }

    fn infected() -> (Observation, ProcJudgement) {
        let mut o = sample_observation();
        o.proc_samples = vec![o.proc_samples[0].clone(), o.proc_samples[0].clone()];
        o.conn_samples = vec![cs(8, 0, 3, 5, 0, 3, 0); 5];
        o.conn.inuse_ports_pass1 = vec![t(22), t(25), t(36552), t(42149)];
        o.conn.inuse_ports_pass2 = vec![t(22), t(25), t(36552), t(42149)];
        o.conn.listed_ports_before = vec![t(22), t(25)];
        o.conn.listed_ports_after = vec![t(22), t(25)];
        let p = judge_processes(&o.proc_samples);
        (o, p)
    }

    #[test]
    fn three_evidence_classes_confirm_and_endpoints_are_deduplicated() {
        let (o, p) = infected();
        let j = judge_connections(&o, &p);
        assert!(j.gap_fired && !j.udp_gap_fired);
        assert_eq!(j.hidden_ports, vec![t(36552), t(42149)]);
        assert_eq!(j.evidence.len(), 3);
        assert_eq!(j.evidence_classes, 3);
        assert!(j.confirmed && !j.pending);
        assert_eq!(j.holders.len(), 1);
        assert_eq!(j.holders[0].comm, "python2");
        assert_eq!(j.endpoints.len(), 1);
        assert_eq!(j.endpoints[0].proto, Proto::Tcp);
        assert_eq!(
            j.endpoints[0].sources,
            vec![EndpointSource::Capture, EndpointSource::Ptrace]
        );
        assert!(j.unresolved_ports.is_empty());
        assert_eq!(
            j.listeners.len(),
            0,
            "監聽那個 socket 沒有本機端可記（查詢失敗，位址為 -）"
        );
    }

    #[test]
    fn address_must_match_the_bound_local_address_not_just_the_port() {
        let (mut o, p) = infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries.clear();
        o.conn.conntrack_lines = vec![
            "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=10.0.0.6 sport=36552 dport=80 src=10.0.0.6 dst=10.0.0.5 sport=80 dport=36552 [ASSURED]".into(),
            "ipv4     2 tcp      6 431999 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=36552 dport=42149 src=127.0.0.1 dst=127.0.0.1 sport=42149 dport=36552 [ASSURED]".into(),
        ];
        let j = judge_connections(&o, &p);
        assert_eq!(j.endpoints.len(), 1);
        assert_eq!(j.endpoints[0].a, "127.0.0.1:36552");
    }

    #[test]
    fn address_candidates_exclude_visible_remote_addresses() {
        let (mut o, p) = infected();
        o.conn.tcp_metrics = vec!["10.99.0.1".into(), "192.168.1.5".into(), "8.8.8.8".into()];
        o.conn.visible_remotes = vec!["192.168.1.5".into()];
        let j = judge_connections(&o, &p);
        assert_eq!(
            j.address_candidates,
            vec!["10.99.0.1".to_string(), "8.8.8.8".to_string()]
        );
    }

    #[test]
    fn single_holder_gets_everything() {
        let (o, p) = infected();
        let j = judge_connections(&o, &p);
        assert_eq!(j.groups.len(), 1);
        assert_eq!(j.groups[0].ports, vec![t(36552), t(42149)]);
        assert_eq!(j.groups[0].endpoints.len(), 1);
        assert!(j.shared_endpoints.is_empty() && j.shared_ports.is_empty());
    }

    #[test]
    fn several_holders_get_only_their_own_addresses() {
        let (mut o, p) = infected();
        o.conn.held.push(HeldSocket {
            pid: 8000,
            comm: "python2".into(),
            exe: Some("/usr/bin/python2.7".into()),
            fd: 4,
            inode: 99,
        });
        o.conn.inuse_ports_pass1 = vec![t(22), t(25), t(36552), t(42149), t(1111), t(2222)];
        o.conn.inuse_ports_pass2 = o.conn.inuse_ports_pass1.clone();
        o.conn.peer_queries.push(PeerQuery {
            pid: 8000,
            fd: 4,
            local: "10.99.0.1:1111".into(),
            peer: "10.99.0.1:2222".into(),
            error: None,
            state: None,
        });
        let j = judge_connections(&o, &p);
        assert_eq!(j.groups.len(), 2);
        let g7655 = j
            .groups
            .iter()
            .find(|g| g.holders.iter().any(|h| h.pid == 7655))
            .unwrap();
        let g8000 = j
            .groups
            .iter()
            .find(|g| g.holders.iter().any(|h| h.pid == 8000))
            .unwrap();
        assert_eq!(g7655.endpoints.len(), 1);
        assert_eq!(g7655.endpoints[0].a, "127.0.0.1:36552");
        assert_eq!(g8000.endpoints.len(), 1);
        assert_eq!(g8000.endpoints[0].a, "10.99.0.1:1111");
        assert!(j.shared_endpoints.is_empty());
    }

    #[test]
    fn addresses_without_a_known_owner_go_to_shared_when_several_holders() {
        let (mut o, p) = infected();
        o.conn.held.push(HeldSocket {
            pid: 8000,
            comm: "python2".into(),
            exe: Some("/usr/bin/python2.7".into()),
            fd: 4,
            inode: 99,
        });
        o.conn.peer_queries.clear();
        o.conn.capture_pairs.clear();
        o.conn.conntrack_lines = vec![
            "ipv4     2 tcp      6 431999 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=36552 dport=42149 src=127.0.0.1 dst=127.0.0.1 sport=42149 dport=36552 [ASSURED]".into(),
        ];
        let j = judge_connections(&o, &p);
        assert_eq!(j.groups.len(), 2);
        assert!(
            j.groups.iter().all(|g| g.endpoints.is_empty()),
            "沒有線索就不亂分配"
        );
        assert_eq!(j.shared_endpoints.len(), 1);
        assert_eq!(j.shared_ports, vec![t(36552), t(42149)]);
    }

    #[test]
    fn single_evidence_class_is_only_pending() {
        let (mut o, p) = infected();
        o.conn.held.clear();
        o.conn.inuse_ports_pass1 = vec![t(22), t(25)];
        o.conn.inuse_ports_pass2 = vec![t(22), t(25)];
        let j = judge_connections(&o, &p);
        assert_eq!(j.evidence.len(), 1);
        assert!(j.pending && !j.confirmed, "只有數量缺口：待確認");
    }

    #[test]
    fn ports_alone_are_pending_and_nothing_is_clean() {
        let (mut o, p) = infected();
        o.conn_samples = vec![cs(5, 0, 3, 5, 0, 3, 0); 5];
        o.conn.held.clear();
        let j = judge_connections(&o, &p);
        assert!(j.pending && !j.confirmed);
        o.conn.inuse_ports_pass1 = vec![t(22), t(25)];
        o.conn.inuse_ports_pass2 = vec![t(22), t(25)];
        let j = judge_connections(&o, &p);
        assert!(!j.pending && !j.confirmed && j.evidence.is_empty());
    }

    #[test]
    fn unresolved_ports_listed_when_no_address_source_worked() {
        let (mut o, p) = infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries.clear();
        let j = judge_connections(&o, &p);
        assert_eq!(j.unresolved_ports, vec![t(36552), t(42149)]);
        assert!(j.endpoints.is_empty());
    }

    #[test]
    fn a_port_found_by_the_query_on_a_hidden_holders_socket_counts_as_hidden() {
        let (mut o, _p) = infected();
        o.conn.inuse_ports_pass1 = o.conn.listed_ports_before.clone();
        o.conn.inuse_ports_pass2 = o.conn.listed_ports_before.clone();
        let q = |pid: u32, local: &str, state: Option<u8>| PeerQuery {
            pid,
            fd: 3,
            local: local.into(),
            peer: "-".into(),
            error: Some("errno 107".into()),
            state,
        };
        assert!(hidden_ports(&o.conn).is_empty());
        o.conn.peer_queries = vec![q(7655, "10.0.0.5:56088", Some(2))];
        assert_eq!(hidden_ports(&o.conn), vec![t(56088)]);
        o.conn.peer_queries = vec![q(7655, "10.0.0.5:56088", None)];
        assert!(hidden_ports(&o.conn).is_empty());
        o.conn.peer_queries = vec![q(99999, "10.0.0.5:56088", Some(2))];
        assert!(hidden_ports(&o.conn).is_empty());
        o.conn.listed_ports_after.push(t(56088));
        o.conn.peer_queries = vec![q(7655, "10.0.0.5:56088", Some(2))];
        assert!(hidden_ports(&o.conn).is_empty());
    }

    #[test]
    fn a_listener_found_by_the_query_is_shown_even_when_no_hidden_port_was_confirmed() {
        let (mut o, p) = infected();
        o.conn.inuse_ports_pass1 = o.conn.listed_ports_before.clone();
        o.conn.inuse_ports_pass2 = o.conn.listed_ports_before.clone();
        o.conn.capture_pairs.clear();
        o.conn.conntrack_lines.clear();
        o.conn.peer_queries = vec![PeerQuery {
            pid: 7655,
            fd: 3,
            local: "127.0.0.1:36195".into(),
            peer: "-".into(),
            error: Some("errno 107".into()),
            state: Some(10),
        }];
        let j = judge_connections(&o, &p);
        assert_eq!(
            j.hidden_ports,
            vec![t(36195)],
            "逐埠驗證沒確認到埠，但查詢拿到的 TCP socket 也算被藏的埠"
        );
        assert_eq!(j.groups.len(), 1);
        assert_eq!(
            j.groups[0].listeners,
            vec![Listener {
                proto: Proto::Tcp,
                addr: "127.0.0.1:36195".into(),
                bound_only: false,
            }]
        );
    }

    #[test]
    fn an_untyped_unconfirmed_socket_is_not_shown_as_a_tcp_listener() {
        let (mut o, _p) = infected();
        o.conn.peer_queries = vec![PeerQuery {
            pid: 7655,
            fd: 6,
            local: "10.99.0.1:44441".into(),
            peer: "-".into(),
            error: Some("errno 107".into()),
            state: None,
        }];
        let (_e, l) = derive_endpoints(&o.conn, &[t(1234)]);
        assert!(l.is_empty(), "分不出協定，不能當成 TCP 監聽端：{:?}", l);
        let (_e, l) = derive_endpoints(&o.conn, &[t(44441)]);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].proto, Proto::Tcp);
        let (_e, l) = derive_endpoints(&o.conn, &[PortKey::udp(44441)]);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].proto, Proto::Udp);
    }

    #[test]
    fn a_dialing_socket_whose_destination_was_read_from_the_socket_gives_the_remote_address() {
        let (mut o, p) = infected();
        o.conn.inuse_ports_pass1 = o.conn.listed_ports_before.clone();
        o.conn.inuse_ports_pass2 = o.conn.listed_ports_before.clone();
        o.conn.capture_pairs.clear();
        o.conn.conntrack_lines.clear();
        o.conn.peer_queries = vec![PeerQuery {
            pid: 7655,
            fd: 3,
            local: "198.51.100.20:38370".into(),
            peer: "198.51.100.200:18443".into(),
            error: None,
            state: Some(2),
        }];
        assert!(unresolved_ports(&o.conn, &[t(38370)]).is_empty());
        let j = judge_connections(&o, &p);
        assert_eq!(j.hidden_ports, vec![t(38370)]);
        let e = &j.groups[0].endpoints;
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].sources, vec![EndpointSource::Ptrace]);
        assert_eq!(
            e[0].state.as_deref(),
            Some("SYN_SENT"),
            "連線還沒建立，報告要照實寫還沒連上"
        );
        assert!(j.groups[0].listeners.is_empty(), "它不是監聽端");
        assert_eq!(
            j.groups[0].ports,
            vec![t(38370)],
            "只有本機端的埠算被占用；對方的埠不算"
        );
    }

    #[test]
    fn a_not_connected_answer_is_a_listener_only_when_the_socket_state_says_listening() {
        let query = |state: Option<u8>| PeerQuery {
            pid: 7655,
            fd: 3,
            local: "127.0.0.1:42149".into(),
            peer: "-".into(),
            error: Some("errno 107".into()),
            state,
        };
        let listener = Listener {
            proto: Proto::Tcp,
            addr: "127.0.0.1:42149".into(),
            bound_only: false,
        };
        let (mut o, p) = infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries = vec![query(Some(10))];
        let j = judge_connections(&o, &p);
        assert_eq!(j.listeners, vec![listener.clone()]);
        assert!(!j.unresolved_ports.contains(&t(42149)));
        let (mut o, p) = infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries = vec![query(Some(2))];
        let j = judge_connections(&o, &p);
        assert!(j.listeners.is_empty(), "連出去的 socket 不能標成監聽端");
        assert!(j.unresolved_ports.contains(&t(42149)));
        let (mut o, p) = infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries = vec![query(Some(7))];
        let j = judge_connections(&o, &p);
        assert_eq!(
            j.listeners,
            vec![Listener {
                bound_only: true,
                ..listener.clone()
            }]
        );
        assert!(!j.unresolved_ports.contains(&t(42149)));
        let (mut o, p) = infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries = vec![query(None)];
        let j = judge_connections(&o, &p);
        assert_eq!(j.listeners, vec![listener]);
    }

    #[test]
    fn conntrack_and_listener_are_understood() {
        let (mut o, p) = infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries = vec![PeerQuery {
            pid: 7655,
            fd: 3,
            local: "127.0.0.1:42149".into(),
            peer: "-".into(),
            error: Some("errno 107".into()),
            state: None,
        }];
        o.conn.conntrack_lines = vec![
            "ipv4     2 tcp      6 431999 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=36552 dport=42149 src=127.0.0.1 dst=127.0.0.1 sport=42149 dport=36552 [ASSURED]".into(),
            "ipv4     2 tcp      6 100 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=1111 dport=2222 src=5.6.7.8 dst=1.2.3.4 sport=2222 dport=1111".into(),
        ];
        let j = judge_connections(&o, &p);
        assert_eq!(j.endpoints.len(), 1, "與被藏埠無關的追蹤列不收");
        assert_eq!(j.endpoints[0].sources, vec![EndpointSource::Conntrack]);
        assert_eq!(
            j.listeners,
            vec![Listener {
                proto: Proto::Tcp,
                addr: "127.0.0.1:42149".into(),
                bound_only: false,
            }]
        );
    }

    fn udp_infected() -> (Observation, ProcJudgement) {
        let (mut o, p) = infected();
        o.conn_samples = vec![
            ConnSample {
                su4: 5,
                su_after: 5,
                ru4: 3,
                ..cs(5, 0, 3, 5, 0, 3, 0)
            };
            5
        ];
        o.conn.inuse_ports_pass1 = vec![t(22), t(25), u(111), u(34091), u(49240)];
        o.conn.inuse_ports_pass2 = o.conn.inuse_ports_pass1.clone();
        o.conn.listed_ports_before = vec![t(22), t(25), u(111)];
        o.conn.listed_ports_after = o.conn.listed_ports_before.clone();
        o.conn.port_local_addrs = vec![(u(49240), vec!["127.0.0.1".into()])];
        o.conn.capture_pairs = vec![CapturePair {
            proto: Proto::Udp,
            a: "127.0.0.1:34091".into(),
            b: "127.0.0.1:49240".into(),
            count: 2,
        }];
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
        (o, p)
    }

    #[test]
    fn hidden_udp_socket_is_confirmed_by_three_classes() {
        let (o, p) = udp_infected();
        let j = judge_connections(&o, &p);
        assert!(!j.gap_fired && j.udp_gap_fired);
        assert_eq!(j.udp_gaps, vec![2, 2, 2]);
        assert_eq!(j.hidden_ports, vec![u(34091), u(49240)]);
        assert_eq!(
            j.evidence,
            vec![
                "核心登記的 UDP 數量比連線表多",
                "有行程握著不在任何連線表的 socket",
                "有 UDP 埠號被占用卻沒有列在連線表"
            ]
        );
        assert!(j.confirmed && !j.pending);
        assert_eq!(j.endpoints.len(), 1);
        assert_eq!(j.endpoints[0].proto, Proto::Udp);
        assert_eq!(
            j.endpoints[0].sources,
            vec![EndpointSource::Capture, EndpointSource::Ptrace]
        );
        assert_eq!(
            j.listeners,
            vec![Listener {
                proto: Proto::Udp,
                addr: "127.0.0.1:49240".into(),
                bound_only: false,
            }],
            "沒有連線的 UDP socket 記為只有本機端"
        );
        assert!(j.unresolved_ports.is_empty());
    }

    #[test]
    fn udp_listener_without_traffic_or_query_stays_unresolved_but_still_found() {
        let (mut o, p) = udp_infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries.clear();
        let j = judge_connections(&o, &p);
        assert!(j.confirmed);
        assert_eq!(j.unresolved_ports, vec![u(34091), u(49240)]);
    }

    #[test]
    fn tcp_traffic_on_the_same_number_is_not_mistaken_for_the_hidden_udp_port() {
        let (mut o, p) = udp_infected();
        o.conn.peer_queries.clear();
        o.conn.capture_pairs = vec![CapturePair {
            proto: Proto::Tcp,
            a: "127.0.0.1:34091".into(),
            b: "10.0.0.9:80".into(),
            count: 5,
        }];
        let j = judge_connections(&o, &p);
        assert!(j.endpoints.is_empty(), "協定不同，同號碼的 TCP 封包不算");
    }

    #[test]
    fn udp_conntrack_lines_are_understood() {
        let (mut o, p) = udp_infected();
        o.conn.peer_queries.clear();
        o.conn.capture_pairs.clear();
        o.conn.conntrack_lines = vec![
            "ipv4     2 udp      17 29 src=127.0.0.1 dst=127.0.0.1 sport=34091 dport=49240 src=127.0.0.1 dst=127.0.0.1 sport=49240 dport=34091 [ASSURED]".into(),
        ];
        let j = judge_connections(&o, &p);
        assert_eq!(j.endpoints.len(), 1);
        assert_eq!(j.endpoints[0].proto, Proto::Udp);
        assert_eq!(j.endpoints[0].sources, vec![EndpointSource::Conntrack]);
    }

    #[test]
    fn tcp_gap_and_udp_gap_together_count_as_one_class() {
        let (mut o, p) = infected();
        o.conn.held.clear();
        o.conn.inuse_ports_pass1.clear();
        o.conn.inuse_ports_pass2.clear();
        o.conn_samples = vec![
            ConnSample {
                su4: 5,
                su_after: 5,
                ru4: 3,
                ..cs(8, 0, 3, 5, 0, 3, 0)
            };
            5
        ];
        let j = judge_connections(&o, &p);
        assert_eq!(j.evidence.len(), 2);
        assert_eq!(j.evidence_classes, 1);
        assert!(j.pending && !j.confirmed);
    }

    #[test]
    fn proto_of_a_queried_socket_follows_the_hidden_port_set() {
        let hidden = vec![t(80), u(53), t(53), u(9999)];
        assert_eq!(proto_of_local(&hidden, "127.0.0.1:9999"), Proto::Udp);
        assert_eq!(proto_of_local(&hidden, "127.0.0.1:80"), Proto::Tcp);
        assert_eq!(
            proto_of_local(&hidden, "127.0.0.1:53"),
            Proto::Tcp,
            "兩種協定都藏同一個號碼時無法分辨，記為 TCP"
        );
        assert_eq!(proto_of_local(&hidden, "-"), Proto::Tcp);
    }

    #[test]
    fn burst_of_udp_sockets_between_the_two_reads_is_not_a_gap() {
        let burst = |rows| ConnSample {
            su4: 43,
            su6: 3,
            su_after: 25 + 3,
            ru4: rows,
            ru6: 3,
            ..Default::default()
        };
        let calm = us(43, 3, 43, 3);
        assert!(!udp_stable(&burst(25)));
        assert_eq!(udp_gap(&burst(25)), 18, "不穩定樣本單看缺口很大");
        let samples = vec![
            calm.clone(),
            burst(25),
            calm.clone(),
            burst(36),
            calm.clone(),
            calm,
        ];
        assert!(!udp_gap_fired(&samples), "穩定樣本的缺口都是 0");
        assert_eq!(udp_stable_counts(&samples), (4, 6));
    }

    #[test]
    fn hidden_udp_gap_survives_bursts_because_only_stable_samples_count() {
        let hidden = us(5, 3, 3, 3);
        let burst = ConnSample {
            su_after: 1,
            ..us(5, 3, 3, 3)
        };
        let samples = vec![
            hidden.clone(),
            burst.clone(),
            hidden.clone(),
            burst,
            hidden.clone(),
        ];
        assert!(udp_gap_fired(&samples));
        assert_eq!(udp_recent_gaps(&samples), vec![2, 2, 2]);
    }

    #[test]
    fn fewer_than_three_stable_udp_samples_gives_no_result() {
        let hidden = us(5, 3, 3, 3);
        let unstable = ConnSample {
            su_after: 1,
            ..us(5, 3, 3, 3)
        };
        let samples = vec![hidden.clone(), unstable.clone(), unstable, hidden];
        assert!(!udp_gap_fired(&samples));
        assert_eq!(udp_stable_counts(&samples), (2, 4));
    }

    #[test]
    fn sockets_that_are_not_tcp_or_udp_in_query_results_are_ignored() {
        let (mut o, p) = udp_infected();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries = ["family=1", "family=16", "[::]:0", "0.0.0.0:0"]
            .iter()
            .enumerate()
            .map(|(i, l)| PeerQuery {
                pid: 7655,
                fd: 10 + i as u32,
                local: (*l).into(),
                peer: "family=1".into(),
                error: None,
                state: None,
            })
            .collect();
        let j = judge_connections(&o, &p);
        assert!(j.endpoints.is_empty(), "{:?}", j.endpoints);
        assert!(j.listeners.is_empty(), "{:?}", j.listeners);
        assert_eq!(j.unresolved_ports, vec![u(34091), u(49240)]);
    }

    fn visible_holder(pid: u32, comm: &str, fd: u32) -> HeldSocket {
        HeldSocket {
            pid,
            comm: comm.into(),
            exe: Some(format!("/usr/bin/{}", comm)),
            fd,
            inode: 1000 + pid as u64 * 10 + fd as u64,
        }
    }

    fn ip_query(pid: u32, fd: u32, local: &str, peer: &str) -> PeerQuery {
        PeerQuery {
            pid,
            fd,
            local: local.into(),
            peer: peer.into(),
            error: None,
            state: None,
        }
    }

    fn visible_holder_case() -> (Observation, ProcJudgement) {
        let (mut o, p) = udp_infected();
        o.conn.held.clear();
        o.conn.capture_pairs.clear();
        o.conn.peer_queries.clear();
        o.conn.visible_held = vec![
            visible_holder(621, "rpcbind", 5),
            visible_holder(623, "dbus-daemon", 5),
            visible_holder(8100, "python2", 3),
            visible_holder(8100, "python2", 4),
        ];
        o.conn.peer_queries = vec![
            ip_query(621, 5, "family=10", "-"),
            ip_query(623, 5, "family=16", "family=16"),
            PeerQuery {
                pid: 8100,
                fd: 3,
                local: "127.0.0.1:49240".into(),
                peer: "-".into(),
                error: Some("errno 107".into()),
                state: None,
            },
            ip_query(8100, 4, "127.0.0.1:34091", "127.0.0.1:49240"),
        ];
        (o, p)
    }

    #[test]
    fn a_visible_process_whose_local_port_matches_a_hidden_port_becomes_the_holder() {
        let (o, p) = visible_holder_case();
        let j = judge_connections(&o, &p);
        assert_eq!(j.holders.len(), 1, "{:?}", j.holders);
        assert_eq!(j.holders[0].pid, 8100);
        assert_eq!(j.holders[0].comm, "python2");
        assert_eq!(j.holders[0].sockets, 2);
        assert!(!j.holders[0].is_kernel_thread);
        assert_eq!(j.endpoints.len(), 1);
        assert_eq!(j.endpoints[0].sources, vec![EndpointSource::Ptrace]);
        assert!(j.unresolved_ports.is_empty());
        assert_eq!(j.evidence_classes, 3, "缺口、持有者、被占用的埠");
        assert!(j.confirmed);
        assert_eq!(j.groups.len(), 1);
        assert_eq!(
            j.groups[0]
                .holders
                .iter()
                .map(|h| h.pid)
                .collect::<Vec<_>>(),
            vec![8100]
        );
    }

    #[test]
    fn visible_processes_with_other_kinds_of_sockets_are_never_holders() {
        let (mut o, p) = visible_holder_case();
        o.conn.peer_queries.retain(|q| q.pid != 8100);
        let j = judge_connections(&o, &p);
        assert!(j.holders.is_empty());
        assert!(j.endpoints.is_empty() && j.listeners.is_empty());
        assert_eq!(j.unresolved_ports, vec![u(34091), u(49240)]);
        assert!(
            j.confirmed,
            "仍有數量缺口與被占用的埠兩類證據，只是說不出持有者"
        );
        assert_eq!(j.groups.len(), 1);
        assert!(j.groups[0].holders.is_empty());
    }

    #[test]
    fn a_visible_process_with_an_ip_socket_on_an_unrelated_port_is_ignored() {
        let (mut o, p) = visible_holder_case();
        o.conn
            .peer_queries
            .push(ip_query(621, 6, "10.0.0.5:5555", "10.0.0.9:80"));
        let j = judge_connections(&o, &p);
        assert_eq!(j.holders.len(), 1);
        assert_eq!(j.endpoints.len(), 1);
        assert!(j.endpoints.iter().all(|e| !e.a.contains("5555")));
    }

    #[test]
    fn two_visible_holders_each_get_their_own_ports_and_addresses() {
        let (mut o, p) = visible_holder_case();
        o.conn.inuse_ports_pass1 = vec![t(22), t(25), u(111), u(1111), u(2222), u(34091), u(49240)];
        o.conn.inuse_ports_pass2 = o.conn.inuse_ports_pass1.clone();
        o.conn.visible_held.push(visible_holder(9000, "nc", 3));
        o.conn
            .peer_queries
            .push(ip_query(9000, 3, "10.99.0.1:1111", "10.99.0.1:2222"));
        let j = judge_connections(&o, &p);
        assert_eq!(j.holders.len(), 2);
        assert_eq!(j.groups.len(), 2);
        let g = |pid| {
            j.groups
                .iter()
                .find(|g| g.holders.iter().any(|h| h.pid == pid))
                .unwrap()
        };
        assert_eq!(g(9000).endpoints.len(), 1);
        assert_eq!(g(9000).endpoints[0].a, "10.99.0.1:1111");
        assert_eq!(g(8100).endpoints.len(), 1);
        assert_eq!(g(8100).endpoints[0].a, "127.0.0.1:34091");
        assert!(j.shared_endpoints.is_empty());
    }

    #[test]
    fn the_last_resort_needs_two_evidence_classes_before_touching_ordinary_services() {
        let gap = vec![
            ConnSample {
                su4: 5,
                su_after: 5,
                ru4: 3,
                ..Default::default()
            };
            5
        ];
        let calm = vec![ConnSample::default(); 5];
        assert_eq!(evidence_class_count(&calm, false, false), 0);
        assert_eq!(
            evidence_class_count(&calm, false, true),
            1,
            "只有埠：不動一般服務"
        );
        assert_eq!(
            evidence_class_count(&gap, false, false),
            1,
            "只有缺口：不動一般服務"
        );
        assert_eq!(evidence_class_count(&gap, false, true), 2);
        assert_eq!(evidence_class_count(&calm, true, true), 2);
    }

    fn shared_socket_case() -> (Observation, ProcJudgement) {
        let (mut o, p) = infected();
        o.conn_samples = vec![cs(6, 0, 3, 5, 0, 3, 0); 8];
        o.conn.inuse_ports_pass1 = vec![t(22), t(25), t(34072)];
        o.conn.inuse_ports_pass2 = o.conn.inuse_ports_pass1.clone();
        o.conn.port_local_addrs = vec![(t(34072), vec!["172.16.0.5".into()])];
        o.conn.capture_pairs.clear();
        o.conn.peer_queries.clear();
        o.conn.held = [1455u32, 1605, 1606]
            .iter()
            .map(|pid| HeldSocket {
                pid: *pid,
                comm: "exampled-svc".into(),
                exe: Some("/usr/bin/exampled-svc".into()),
                fd: 3,
                inode: 1271017,
            })
            .collect();
        o.conn.conntrack_present = true;
        o.conn.conntrack_lines = vec![
            "ipv4     2 tcp      6 52 SYN_SENT src=172.16.0.5 dst=203.0.113.10 sport=34072 dport=18443 [UNREPLIED] src=203.0.113.10 dst=172.16.0.5 sport=18443 dport=34072 mark=0 zone=0 use=2".into(),
        ];
        (o, p)
    }

    #[test]
    fn holders_sharing_one_socket_are_one_connection() {
        let (o, p) = shared_socket_case();
        let j = judge_connections(&o, &p);
        assert_eq!(j.holders.len(), 3, "三個行程都是持有者");
        assert_eq!(j.groups.len(), 1, "共用同一個 socket，只算一條連線");
        assert_eq!(
            j.groups[0]
                .holders
                .iter()
                .map(|h| h.pid)
                .collect::<Vec<_>>(),
            vec![1455, 1605, 1606]
        );
        assert!(j.shared_ports.is_empty() && j.shared_endpoints.is_empty());
        assert_eq!(
            j.groups[0].endpoints.len(),
            1,
            "位址對得上這一組，不丟進其他位址"
        );
        assert!(j.confirmed);
    }

    #[test]
    fn conntrack_state_and_unreplied_flag_are_kept() {
        let (o, p) = shared_socket_case();
        let j = judge_connections(&o, &p);
        let e = &j.groups[0].endpoints[0];
        assert_eq!(e.state.as_deref(), Some("SYN_SENT"));
        assert!(e.unreplied);
        assert_eq!(
            conntrack_state(
                "ipv4     2 udp      17 29 src=1.1.1.1 dst=2.2.2.2 sport=1 dport=2 [UNREPLIED] src=2.2.2.2"
            ),
            (None, true)
        );
        assert_eq!(
            conntrack_state(
                "ipv4     2 tcp      6 431999 ESTABLISHED src=1.1.1.1 dst=2.2.2.2 sport=1 dport=2 [ASSURED]"
            ),
            (Some("ESTABLISHED".to_string()), false)
        );
    }

    #[test]
    fn holders_with_separate_sockets_stay_separate_connections() {
        let (mut o, p) = shared_socket_case();
        o.conn.held[2].inode = 1271099;
        o.conn.inuse_ports_pass1.push(t(40000));
        o.conn.inuse_ports_pass2 = o.conn.inuse_ports_pass1.clone();
        let j = judge_connections(&o, &p);
        assert_eq!(j.groups.len(), 2);
        let sizes: Vec<usize> = j.groups.iter().map(|g| g.holders.len()).collect();
        assert_eq!(sizes, vec![2, 1]);
    }

    #[test]
    fn a_chain_of_shared_sockets_merges_transitively() {
        let h = |pid: u32, inodes: Vec<u64>| Holder {
            pid,
            comm: "x".into(),
            exe: None,
            sockets: inodes.len(),
            inodes,
            is_kernel_thread: false,
            from_visible: false,
        };
        let comps = merge_by_shared_socket(&[
            h(1, vec![10]),
            h(2, vec![10, 11]),
            h(3, vec![11]),
            h(4, vec![12]),
        ]);
        let pids: Vec<Vec<u32>> = comps
            .iter()
            .map(|c| c.iter().map(|h| h.pid).collect())
            .collect();
        assert_eq!(pids, vec![vec![1, 2, 3], vec![4]]);
    }

    #[test]
    fn hidden_sockets_not_held_by_hidden_processes_are_counted() {
        let held = |ino: u64| HeldSocket {
            pid: 1,
            comm: "x".into(),
            exe: Some("/x".into()),
            fd: 3,
            inode: ino,
        };
        let gap = |n: i64| ConnSample {
            inuse4: 10 + n,
            e4: 10,
            ..Default::default()
        };
        let samples = vec![gap(6); 8];
        let held3 = [held(1), held(2), held(3)];
        assert_eq!(unexplained_hidden_sockets(&samples, &held3), 3);
        let dup = [held(1), held(1), held(1)];
        assert_eq!(
            unexplained_hidden_sockets(&vec![gap(1); 8], &dup),
            0,
            "3 個行程共用 1 個 socket"
        );
        assert_eq!(unexplained_hidden_sockets(&vec![gap(3); 8], &held3), 0);
        assert!(unexplained_hidden_sockets(&vec![gap(0); 8], &held3) < 0);
        let mut spiky = vec![gap(3); 8];
        spiky[7] = gap(9);
        assert_eq!(unexplained_hidden_sockets(&spiky, &held3), 0);
        assert!(unexplained_hidden_sockets(&[], &held3) <= 0);
    }
}

#[cfg(test)]
mod origin_tests {
    use super::*;
    use crate::model::{Meta, OriginData, ID_UNSET};

    fn proc(pid: u32, kernel: bool) -> HiddenProc {
        HiddenProc {
            info: Unlisted {
                pid,
                via_kill: true,
                via_cgroup: true,
                via_sched: false,
                via_timer: false,
                starttime: 1000,
                ppid: Some(if kernel { 2 } else { 1 }),
                comm: "x".into(),
                exe: if kernel {
                    None
                } else {
                    Some("/usr/bin/x".into())
                },
                cmdline: String::new(),
            },
            via_kill: true,
            via_cgroup: true,
            via_sched: false,
            via_timer: false,
            is_kernel_thread: kernel,
        }
    }

    fn obs_with(items: Vec<OriginFacts>, logins: Vec<AuditLogin>) -> Observation {
        Observation {
            meta: Meta {
                btime: 1_000,
                ..Default::default()
            },
            origin: OriginData {
                ran: true,
                items,
                audit_ran: true,
                audit_files: 1,
                audit_logins: logins,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn facts(pid: u32, loginuid: u32, sessionid: u32, cgroup: &str) -> OriginFacts {
        OriginFacts {
            pid,
            loginuid: Some(loginuid),
            sessionid: Some(sessionid),
            cgroup: Some(cgroup.into()),
            ..Default::default()
        }
    }

    fn login(ses: u32, epoch: u64, addr: &str) -> AuditLogin {
        AuditLogin {
            ses,
            epoch,
            addr: addr.into(),
            ..Default::default()
        }
    }

    fn procs(v: Vec<HiddenProc>) -> ProcJudgement {
        ProcJudgement {
            confirmed: v,
            ..Default::default()
        }
    }

    #[test]
    fn login_started_process_gets_matching_audit_event_of_this_boot() {
        let o = obs_with(
            vec![facts(10, 0, 2, "/user.slice/user-0.slice/session-2.scope")],
            vec![
                login(2, 500, "1.1.1.1"),
                login(2, 2_000, "2.2.2.2"),
                login(2, 3_000, "3.3.3.3"),
                login(7, 2_500, "9.9.9.9"),
            ],
        );
        let r = judge_origins(&o, &procs(vec![proc(10, false)]));
        assert_eq!(r.len(), 1);
        assert_eq!(
            r[0].kind,
            OriginKind::Login {
                uid: 0,
                ses: Some(2)
            }
        );
        assert_eq!(r[0].audit.as_ref().unwrap().addr, "2.2.2.2");
        assert_eq!(r[0].facts.scope_session(), Some(2));
    }

    #[test]
    fn service_started_process_has_no_login_identity() {
        let o = obs_with(
            vec![facts(
                11,
                ID_UNSET,
                ID_UNSET,
                "/system.slice/exampled-svc.service",
            )],
            vec![login(2, 2_000, "2.2.2.2")],
        );
        let r = judge_origins(&o, &procs(vec![proc(11, false)]));
        assert_eq!(
            r[0].kind,
            OriginKind::Service {
                unit: "exampled-svc.service".into()
            }
        );
        assert!(r[0].audit.is_none(), "沒有登入身分就不去對稽核事件");
    }

    #[test]
    fn root_cgroup_and_unreadable_and_kernel_threads() {
        let mut gone = OriginFacts {
            pid: 13,
            ..Default::default()
        };
        gone.loginuid = None;
        let o = obs_with(
            vec![
                facts(12, ID_UNSET, ID_UNSET, "/"),
                gone,
                facts(14, ID_UNSET, ID_UNSET, "/"),
            ],
            vec![],
        );
        let r = judge_origins(
            &o,
            &procs(vec![proc(12, false), proc(13, false), proc(14, true)]),
        );
        assert_eq!(r.len(), 2, "核心執行緒不處理");
        assert_eq!(r[0].kind, OriginKind::Neither);
        assert_eq!(r[1].kind, OriginKind::Unreadable);
    }

    #[test]
    fn not_run_means_no_judgement() {
        let mut o = obs_with(vec![facts(10, 0, 2, "/")], vec![]);
        o.origin.ran = false;
        assert!(judge_origins(&o, &procs(vec![proc(10, false)])).is_empty());
    }
}

#[cfg(test)]
mod deleted_tests {
    use super::*;
    use crate::model::{DeletedProc, DeletedScan, PathNow, ProcSocket, Proto};

    fn obs_with(items: Vec<DeletedProc>) -> Observation {
        let mut o = Observation::default();
        o.meta.btime = 1000;
        o.meta.clk_tck = 100;
        o.deleted_scan = DeletedScan {
            ran: true,
            checked: 50,
            items,
            ..Default::default()
        };
        o
    }

    fn sock(remote: &str, state: &str) -> ProcSocket {
        ProcSocket {
            proto: Proto::Tcp,
            v6: false,
            local_ip: "10.9.9.1".into(),
            local_port: 40000,
            remote_ip: remote.into(),
            remote_port: 18443,
            state: state.into(),
            local_port_listening: false,
        }
    }

    fn hacker() -> DeletedProc {
        DeletedProc {
            pid: 7585,
            ppid: 7564,
            uid: Some(0),
            comm: "systemd-fakemal".into(),
            argv0: "/usr/bin/systemd-fakemal".into(),
            cmdline: "/usr/bin/systemd-fakemal".into(),
            exe_link: "/usr/bin/systemd-fakemal (deleted)".into(),
            starttime: 5000,
            fstat_ok: true,
            ino: 100,
            dev: 1,
            nlink: 0,
            size: 7144,
            ctime: 1055,
            argv0_path: "/usr/bin/systemd-fakemal".into(),
            argv0_now: PathNow::Missing,
            link_now: PathNow::Missing,
            same_ns: true,
            sockets: vec![sock("203.0.113.50", "02")],
            ..Default::default()
        }
    }

    fn judge(items: Vec<DeletedProc>) -> DeletedJudgement {
        judge_deleted(&obs_with(items), &ProcJudgement::default())
    }

    #[test]
    fn remote_addresses_are_classified() {
        for (ip, want) in [
            ("203.0.113.50", RemoteKind::Public),
            ("8.8.8.8", RemoteKind::Public),
            ("2001:db8::1", RemoteKind::Public),
            ("10.1.2.3", RemoteKind::Internal),
            ("172.16.0.1", RemoteKind::Internal),
            ("192.168.1.1", RemoteKind::Internal),
            ("169.254.1.1", RemoteKind::Internal),
            ("100.64.0.1", RemoteKind::Internal),
            ("fd00::1", RemoteKind::Internal),
            ("fe80::1", RemoteKind::Internal),
            ("127.0.0.1", RemoteKind::None),
            ("::1", RemoteKind::None),
            ("0.0.0.0", RemoteKind::None),
            ("::", RemoteKind::None),
            ("224.0.0.251", RemoteKind::None),
            ("not-an-ip", RemoteKind::None),
        ] {
            assert_eq!(remote_kind(ip), want, "{}", ip);
        }
        assert_eq!(remote_kind("100.63.0.1"), RemoteKind::Public);
        assert_eq!(remote_kind("100.128.0.1"), RemoteKind::Public);
    }

    #[test]
    fn only_connections_the_program_made_itself_count_as_outbound() {
        assert!(is_outbound(&sock("203.0.113.50", "02")), "已送出連線請求");
        assert!(is_outbound(&sock("203.0.113.50", "01")), "已連上");
        let mut listening = sock("203.0.113.50", "01");
        listening.local_port_listening = true;
        assert!(!is_outbound(&listening), "本機埠有人在等：是別人連進來的");
        assert!(
            !is_outbound(&sock("0.0.0.0", "0A")),
            "等別人連進來的 socket"
        );
        assert!(!is_outbound(&sock("203.0.113.50", "06")), "等待關閉");
        let mut udp = sock("0.0.0.0", "07");
        udp.proto = Proto::Udp;
        udp.remote_port = 0;
        assert!(!is_outbound(&udp), "沒有 connect 過的 UDP 沒有遠端對象");
        udp.remote_port = 53;
        udp.remote_ip = "8.8.8.8".into();
        assert!(is_outbound(&udp));
    }

    #[test]
    fn hacker_program_is_confirmed_with_its_connection() {
        let j = judge(vec![hacker()]);
        assert_eq!(j.confirmed.len(), 1, "{:?}", j);
        let c = &j.confirmed[0];
        assert_eq!(c.proc.pid, 7585);
        assert!(c.fast);
        assert_eq!(c.secs_to_delete, Some(5));
        assert_eq!(c.start_epoch, 1050);
        assert_eq!(c.delete_epoch, 1055);
        assert_eq!(c.public_out.len(), 1);
        assert_eq!(c.public_out[0].remote_ip, "203.0.113.50");
        assert!(j.pending.is_empty() && j.updated.is_empty() && j.quiet.is_empty());
    }

    #[test]
    fn program_replaced_by_an_update_is_not_reported() {
        let mut p = hacker();
        p.comm = "mydaemon".into();
        p.argv0 = "/usr/local/bin/mydaemon".into();
        p.exe_link = "/usr/local/bin/mydaemon;5fa0c1d2 (deleted)".into();
        p.ctime = 1050 + 86_400 * 9;
        p.argv0_now = PathNow::File {
            ino: 999,
            dev: 1,
            ctime: 1050 + 86_400 * 9,
            mtime: 1050 + 86_400 * 9,
        };
        let j = judge(vec![p]);
        assert!(j.confirmed.is_empty() && j.pending.is_empty(), "{:?}", j);
        assert_eq!(j.updated.len(), 1);
    }

    #[test]
    fn a_file_at_the_path_that_is_older_than_the_program_is_not_a_replacement() {
        let mut p = hacker();
        p.argv0_now = PathNow::File {
            ino: 999,
            dev: 1,
            ctime: 500,
            mtime: 500,
        };
        let j = judge(vec![p]);
        assert_eq!(j.confirmed.len(), 1, "{:?}", j);
        let mut same = hacker();
        same.argv0_now = PathNow::File {
            ino: 100,
            dev: 1,
            ctime: 1060,
            mtime: 1060,
        };
        assert!(judge(vec![same]).updated.is_empty());
    }

    #[test]
    fn temporary_installer_without_network_is_only_pending() {
        let mut p = hacker();
        p.comm = "setup-helper".into();
        p.argv0 = "/tmp/inst/setup-helper".into();
        p.exe_link = "/tmp/inst/setup-helper (deleted)".into();
        p.argv0_path = p.argv0.clone();
        p.sockets.clear();
        let j = judge(vec![p]);
        assert!(j.confirmed.is_empty());
        assert_eq!(j.pending.len(), 1);
        assert!(j.pending[0]
            .disguise
            .contains(&Disguise::StagingDir("/tmp".into())));
    }

    #[test]
    fn removed_package_still_running_with_public_connection_is_only_pending() {
        let mut p = hacker();
        p.comm = "olddaemon".into();
        p.argv0 = "/usr/sbin/olddaemon".into();
        p.exe_link = "/usr/sbin/olddaemon (deleted)".into();
        p.ctime = 1050 + 86_400 * 3;
        let j = judge(vec![p]);
        assert!(j.confirmed.is_empty(), "{:?}", j);
        assert_eq!(j.pending.len(), 1);
        assert!(!j.pending[0].fast);
        assert!(j.pending[0].disguise.is_empty());
    }

    #[test]
    fn deleted_but_harmless_looking_program_is_only_noted() {
        let mut p = hacker();
        p.comm = "olddaemon".into();
        p.argv0 = "/usr/sbin/olddaemon".into();
        p.exe_link = "/usr/sbin/olddaemon (deleted)".into();
        p.ctime = 1050 + 86_400 * 3;
        p.sockets.clear();
        let j = judge(vec![p]);
        assert!(j.confirmed.is_empty() && j.pending.is_empty());
        assert_eq!(j.quiet.len(), 1);
    }

    #[test]
    fn kernel_thread_looking_name_with_public_connection_is_confirmed_even_if_deleted_late() {
        let mut p = hacker();
        p.comm = "kworker/0:1".into();
        p.ctime = 1050 + 86_400 * 3;
        let j = judge(vec![p]);
        assert_eq!(j.confirmed.len(), 1, "{:?}", j);
        assert!(j.confirmed[0]
            .disguise
            .contains(&Disguise::KernelThreadName));
    }

    #[test]
    fn name_disguise_ignores_package_temp_names_truncation_and_process_titles() {
        let base = |comm: &str, argv0: &str, link: &str| {
            let mut p = hacker();
            p.comm = comm.into();
            p.argv0 = argv0.into();
            p.exe_link = link.into();
            disguise_of(&p)
        };
        assert!(base(
            "sshd",
            "/usr/sbin/sshd",
            "/usr/sbin/sshd;5fa0c1d2 (deleted)"
        )
        .is_empty());
        assert!(base(
            "systemd-journal",
            "/usr/lib/systemd/systemd-journald",
            "/usr/lib/systemd/systemd-journald (deleted)"
        )
        .is_empty());
        assert!(base(
            "nginx",
            "nginx: master process /usr/sbin/nginx",
            "/usr/sbin/nginx (deleted)"
        )
        .is_empty());
        assert!(base(
            "mydaemon",
            "/usr/local/bin/mydaemon",
            "/usr/local/bin/mydaemon.new (deleted)"
        )
        .is_empty());
        assert_eq!(
            base("sshd", "/tmp/.x/a", "/tmp/.x/a (deleted)"),
            vec![Disguise::NameMismatch, Disguise::StagingDir("/tmp".into()),]
        );
        assert_eq!(
            base("a", "/usr/bin/.hidden", "/usr/bin/.hidden (deleted)"),
            vec![Disguise::NameMismatch, Disguise::HiddenName]
        );
    }

    #[test]
    fn inbound_connections_internal_only_and_loopback_are_handled() {
        let mut p = hacker();
        p.sockets[0].local_port_listening = true;
        let j = judge(vec![p]);
        assert!(j.confirmed.is_empty(), "{:?}", j);
        assert_eq!(j.pending.len(), 1, "刪得快，所以仍是待確認");
        let mut q = hacker();
        q.sockets = vec![sock("10.0.0.5", "01")];
        let j = judge(vec![q]);
        assert!(j.confirmed.is_empty());
        assert_eq!(j.pending[0].internal_out.len(), 1);
        let mut r = hacker();
        r.sockets = vec![sock("127.0.0.1", "01")];
        r.ctime = 1050 + 86_400;
        r.comm = "systemd-fakemal".into();
        let j = judge(vec![r]);
        assert!(j.confirmed.is_empty() && j.pending.is_empty(), "{:?}", j);
    }

    #[test]
    fn programs_that_are_not_really_deleted_hidden_or_in_other_namespaces_are_skipped() {
        let mut still_linked = hacker();
        still_linked.pid = 1;
        still_linked.nlink = 1;
        let mut no_fstat = hacker();
        no_fstat.pid = 2;
        no_fstat.fstat_ok = false;
        let mut other_ns = hacker();
        other_ns.pid = 3;
        other_ns.same_ns = false;
        let o = obs_with(vec![still_linked, no_fstat, other_ns, hacker()]);
        let mut procs = ProcJudgement::default();
        procs.confirmed.push(HiddenProc {
            info: crate::model::Unlisted {
                pid: 7585,
                ..Default::default()
            },
            via_kill: true,
            via_cgroup: true,
            via_sched: false,
            via_timer: false,
            is_kernel_thread: false,
        });
        let j = judge_deleted(&o, &procs);
        assert!(j.confirmed.is_empty() && j.pending.is_empty() && j.quiet.is_empty());
        assert_eq!(j.unsettled, 2, "連結數不是 0、問不到檔案資訊 → 不判斷");
    }

    #[test]
    fn old_recordings_and_unknown_start_time_do_not_crash_or_overreport() {
        let mut o = obs_with(vec![hacker()]);
        o.deleted_scan.ran = false;
        let j = judge_deleted(&o, &ProcJudgement::default());
        assert!(!j.ran && j.confirmed.is_empty());
        let mut o2 = obs_with(vec![hacker()]);
        o2.meta.btime = 0;
        let j2 = judge_deleted(&o2, &ProcJudgement::default());
        assert!(j2.updated.is_empty());
        assert!(j2.confirmed.is_empty(), "{:?}", j2);
        assert_eq!(j2.pending.len(), 1);
        assert_eq!(j2.pending[0].secs_to_delete, None);
    }
}
