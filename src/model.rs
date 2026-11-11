#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unlisted {
    pub pid: u32,
    pub via_kill: bool,
    pub via_cgroup: bool,
    pub via_sched: bool,
    pub via_timer: bool,
    pub starttime: u64,
    pub ppid: Option<u32>,
    pub comm: String,
    pub exe: Option<String>,
    pub cmdline: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcSample {
    pub t_ms: u64,
    pub n_listed: usize,
    pub n_alive: usize,
    pub n_cgroup: usize,
    pub sched_read: bool,
    pub sched_trusted: bool,
    pub n_sched: usize,
    pub n_timer: usize,
    pub unlisted: Vec<Unlisted>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Meta {
    pub hostname: String,
    pub kernel: String,
    pub os: String,
    pub epoch: u64,
    pub clk_tck: u64,
    pub btime: u64,
    pub is_root: bool,
    pub pid_max: u32,
    pub uptime_s: f64,
    pub elapsed_ms: u64,
    pub scanner_sha256: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModSample {
    pub t_ms: u64,
    pub nl_before: i64,
    pub nl_mid: i64,
    pub nl_after: i64,
    pub n_list1: usize,
    pub n_list2: usize,
    pub n_sub: usize,
    pub vanished: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModLists {
    pub proc_before: Vec<String>,
    pub proc_after: Vec<String>,
    pub sys_before: Vec<String>,
    pub sys_after: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadLine {
    pub name: String,
    pub text: String,
    pub epoch: Option<u64>,
    pub seq: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogCopy {
    pub source: String,
    pub readable: bool,
    pub records: u64,
    pub first_seq: Option<u64>,
    pub seq_gaps: u64,
    pub boot_banner: bool,
    pub min_epoch: Option<u64>,
    pub files: usize,
    pub skipped: usize,
    pub unread: usize,
    pub load_lines: Vec<LoadLine>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameCheck {
    pub name: String,
    pub stat_ok: bool,
    pub initstate: String,
    pub taint: String,
    pub text_addr: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnSample {
    pub t_ms: u64,
    pub inuse4: i64,
    pub tw: i64,
    pub inuse6: i64,
    pub e4: i64,
    pub w4: i64,
    pub y4: i64,
    pub e6: i64,
    pub w6: i64,
    pub y6: i64,
    pub su4: i64,
    pub sl4: i64,
    pub su6: i64,
    pub sl6: i64,
    pub su_after: i64,
    pub ru4: i64,
    pub rl4: i64,
    pub ru6: i64,
    pub rl6: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortKey {
    pub proto: Proto,
    pub port: u16,
}

impl PortKey {
    pub fn tcp(port: u16) -> Self {
        PortKey {
            proto: Proto::Tcp,
            port,
        }
    }
    pub fn udp(port: u16) -> Self {
        PortKey {
            proto: Proto::Udp,
            port,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldSocket {
    pub pid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub fd: u32,
    pub inode: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturePair {
    pub proto: Proto,
    pub a: String,
    pub b: String,
    pub count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerQuery {
    pub pid: u32,
    pub fd: u32,
    pub local: String,
    pub peer: String,
    pub error: Option<String>,
    pub state: Option<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnFacts {
    pub listed_ports_before: Vec<PortKey>,
    pub listed_ports_after: Vec<PortKey>,
    pub inuse_ports_pass1: Vec<PortKey>,
    pub inuse_ports_pass2: Vec<PortKey>,
    pub recheck_vanished: Vec<PortKey>,
    pub recheck_rounds: u32,
    pub port_local_addrs: Vec<(PortKey, Vec<String>)>,
    pub held: Vec<HeldSocket>,
    pub visible_held: Vec<HeldSocket>,
    pub visible_capped: bool,
    pub conntrack_present: bool,
    pub conntrack_lines: Vec<String>,
    pub capture_ran: bool,
    pub capture_secs: u32,
    pub capture_pairs: Vec<CapturePair>,
    pub ptrace_ran: bool,
    pub peer_queries: Vec<PeerQuery>,
    pub metrics_ran: bool,
    pub tcp_metrics: Vec<String>,
    pub visible_remotes: Vec<String>,
    pub attempts: u32,
    pub patrol_limit_secs: u32,
    pub patrol_ran: bool,
    pub patrol_ms: u64,
    pub patrol_samples: u32,
    pub patrol_rounds: u32,
    pub patrol_caught: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionFile {
    pub user: Option<String>,
    pub service: Option<String>,
    pub kind: Option<String>,
    pub remote_host: Option<String>,
    pub tty: Option<String>,
    pub state: Option<String>,
    pub realtime_us: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginFacts {
    pub pid: u32,
    pub loginuid: Option<u32>,
    pub sessionid: Option<u32>,
    pub cgroup: Option<String>,
    pub ssh_connection: Option<String>,
    pub ssh_tty: Option<String>,
    pub session_file: Option<SessionFile>,
    pub unit_checked: bool,
    pub unit_files: Vec<String>,
}

pub const ID_UNSET: u32 = 4_294_967_295;

impl OriginFacts {
    pub fn service_unit(&self) -> Option<&str> {
        self.cgroup
            .as_deref()?
            .split('/')
            .find(|c| c.len() > ".service".len() && c.ends_with(".service"))
    }

    pub fn scope_session(&self) -> Option<u32> {
        self.cgroup.as_deref()?.split('/').find_map(|c| {
            c.strip_prefix("session-")?
                .strip_suffix(".scope")?
                .parse::<u32>()
                .ok()
        })
    }

    pub fn has_login_identity(&self) -> bool {
        matches!(self.loginuid, Some(u) if u != ID_UNSET)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileInfo {
    Ok {
        size: u64,
        mtime: i64,
        ctime: i64,
        nlink: u64,
    },
    Err(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcEvidence {
    pub pid: u32,
    pub uid: Option<(u32, u32)>,
    pub gid: Option<(u32, u32)>,
    pub tracer_pid: Option<u32>,
    pub exe_open_error: Option<String>,
    pub exe_bytes: Option<u64>,
    pub exe_sha256: Option<String>,
    pub exe_read_error: Option<String>,
    pub exe_info: Option<FileInfo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawFile {
    pub ino: u64,
    pub kind: char,
    pub size: u64,
    pub links: u32,
    pub mode: u32,
    pub mtime: i64,
    pub ctime: i64,
    pub crtime: Option<i64>,
    pub sha256: Option<String>,
    pub link_target: Option<String>,
    pub content: Option<String>,
    pub content_truncated: bool,
}

pub const RAW_CONTENT_MAX: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawLookup {
    Unavailable(String),
    NotFound,
    Found(RawFile),
}

impl Default for RawLookup {
    fn default() -> Self {
        RawLookup::Unavailable(String::new())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawFileFact {
    pub path: String,
    pub vfs_error: Option<String>,
    pub vfs_content: Option<String>,
    pub vfs_content_truncated: bool,
    pub raw: RawLookup,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditLogin {
    pub ses: u32,
    pub epoch: u64,
    pub uid: Option<u32>,
    pub exe: String,
    pub hostname: String,
    pub addr: String,
    pub terminal: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginData {
    pub ran: bool,
    pub items: Vec<OriginFacts>,
    pub evidence: Vec<ProcEvidence>,
    pub raw_files: Vec<RawFileFact>,
    pub audit_ran: bool,
    pub audit_files: usize,
    pub audit_unread: usize,
    pub audit_min_epoch: Option<u64>,
    pub audit_logins: Vec<AuditLogin>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskWalk {
    pub dirs: u64,
    pub entries: u64,
    pub fs_only: u64,
    pub dir_errors: u64,
    pub skipped_mounts: u64,
    pub truncated: bool,
    pub unsettled: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiskStatus {
    Walked(DiskWalk),
    Unavailable(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskDevice {
    pub mount_point: String,
    pub source: String,
    pub fstype: String,
    pub status: DiskStatus,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HiddenFile {
    pub path: String,
    pub dir: String,
    pub name: String,
    pub lstat_error: Option<String>,
    pub raw: RawFile,
    pub children: Vec<String>,
    pub children_total: usize,
}

pub const HIDDEN_FILES_MAX: usize = 200;
pub const HIDDEN_CHILDREN_MAX: usize = 20;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcCover {
    pub mount_point: String,
    pub pid: u32,
    pub fstype: String,
    pub source: String,
    pub alive: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirCover {
    pub path: String,
    pub fstype: String,
    pub source: String,
    pub total: usize,
    pub names: Vec<String>,
}

pub const UNSETTLED_DIRS_MAX: usize = 5;
pub const COVER_NAMES_MAX: usize = 10;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskScan {
    pub ran: bool,
    pub devices: Vec<DiskDevice>,
    pub rounds: u32,
    pub candidates: usize,
    pub vanished: usize,
    pub hidden: Vec<HiddenFile>,
    pub hidden_total: usize,
    pub proc_covers: Vec<ProcCover>,
    pub dir_covers: Vec<DirCover>,
    pub unsettled_dirs: Vec<String>,
    pub cold_secs: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExeContradiction {
    pub pid: u32,
    pub comm: String,
    pub ppid: Option<u32>,
    pub starttime: u64,
    pub exe: String,
    pub cmdline: String,
    pub evidence: ProcEvidence,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PathNow {
    #[default]
    Unknown,
    Missing,
    File {
        ino: u64,
        dev: u64,
        ctime: i64,
        mtime: i64,
    },
    Other,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcSocket {
    pub proto: Proto,
    pub v6: bool,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub local_port_listening: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeletedProc {
    pub pid: u32,
    pub ppid: u32,
    pub uid: Option<u32>,
    pub comm: String,
    pub argv0: String,
    pub cmdline: String,
    pub exe_link: String,
    pub starttime: u64,
    pub fstat_ok: bool,
    pub ino: u64,
    pub dev: u64,
    pub nlink: u64,
    pub size: u64,
    pub mtime: i64,
    pub ctime: i64,
    pub sha256: Option<String>,
    pub sha_note: Option<String>,
    pub crtime: Option<i64>,
    pub crtime_note: Option<String>,
    pub argv0_path: String,
    pub argv0_now: PathNow,
    pub link_now: PathNow,
    pub same_ns: bool,
    pub sockets: Vec<ProcSocket>,
    pub sockets_capped: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeletedScan {
    pub ran: bool,
    pub checked: usize,
    pub other_ns: usize,
    pub items: Vec<DeletedProc>,
    pub omitted: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExeScan {
    pub ran: bool,
    pub checked: usize,
    pub candidates: usize,
    pub vanished: usize,
    pub items: Vec<ExeContradiction>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentMismatch {
    pub path: String,
    pub vfs_size: u64,
    pub vfs_sha256: String,
    pub raw_size: u64,
    pub raw_sha256: String,
    pub first_diff: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentScan {
    pub ran: bool,
    pub checked: usize,
    pub skipped_recent: usize,
    pub skipped_big: usize,
    pub skipped_unreadable: usize,
    pub candidates: usize,
    pub vanished: usize,
    pub roots: Vec<String>,
    pub unavailable: Vec<String>,
    pub items: Vec<ContentMismatch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAddr {
    pub iface: String,
    pub addr: std::net::Ipv4Addr,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalAddrs {
    pub ran: bool,
    pub items: Vec<LocalAddr>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Observation {
    pub meta: Meta,
    pub proc_samples: Vec<ProcSample>,
    pub mod_samples: Vec<ModSample>,
    pub mod_lists: ModLists,
    pub logs: Vec<LogCopy>,
    pub name_checks: Vec<NameCheck>,
    pub conn_samples: Vec<ConnSample>,
    pub conn: ConnFacts,
    pub origin: OriginData,
    pub disk: DiskScan,
    pub exe_scan: ExeScan,
    pub deleted_scan: DeletedScan,
    pub content_scan: ContentScan,
    pub local_addrs: LocalAddrs,
}
