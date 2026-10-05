// engine.rs -- orchestration: candidate producer + N verifier threads,
// checkpoint/resume sessions, live stats, benchmark mode. Port of Engine.cs.
use crate::archive;
use crate::attacks::{
    CandidateSource, CombinatorSource, DictionarySource, MaskSource, SourcePosition,
};
use crate::result;
use crate::session::{self, SessionState};
use crate::verifier::{self, Verifier};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct CrackConfig {
    pub archive_path: String,
    pub mode: String, // dict | mask | comb
    pub dict_files: Vec<String>,
    pub dict_file_b: Option<String>,
    pub presets: Vec<String>,
    pub mask: Option<String>,
    pub custom_sets: [String; 4],
    pub mask_min: usize,
    pub mask_max: i64, // -1 = full mask length
    pub threads: u32,  // 0 = auto
    pub checkpoint_enabled: bool,
    pub resume_requested: bool,
    pub max_tries: i64,
    pub user_tool: Option<String>,
    pub quiet: bool,
    pub out_file: Option<String>,
    pub dedupe: bool,
    /// GUI process mode: where session.json lives. None = next to the exe
    /// (the CLI default). The GUI pins this to its own folder so sessions
    /// stay interoperable with the built-in C# engine's resume dialog.
    pub session_file: Option<String>,
}

impl CrackConfig {
    pub fn params_hash(&self) -> String {
        let mut sb = String::new();
        sb.push_str(&format!("mode={};", self.mode));
        for f in &self.dict_files {
            sb.push_str(&format!("w={};", f));
        }
        if let Some(b) = &self.dict_file_b {
            sb.push_str(&format!("w2={};", b));
        }
        for p in &self.presets {
            sb.push_str(&format!("r={};", p));
        }
        if let Some(m) = &self.mask {
            sb.push_str(&format!("m={};", m));
        }
        sb.push_str(&format!("min={};max={};", self.mask_min, self.mask_max));
        for i in 0..4 {
            sb.push_str(&format!("c{}={};", i, self.custom_sets[i]));
        }
        let mut h = Sha256::new();
        h.update(sb.as_bytes());
        let d = h.finalize();
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct CrackResult {
    pub found: bool,
    pub password: String,
    pub error: Option<String>,
    pub warning: Option<String>,
    pub cancelled: bool,
    pub maxed_out: bool,
    pub tried: i64,
    pub elapsed_sec: f64,
    pub result_file: Option<String>,
}

pub struct EngineStats {
    pub tried: AtomicI64,
    pub base_tried: AtomicI64,
    pub total: AtomicI64, // -1 = unknown
    pub phase: Mutex<String>,
    pub current: Mutex<String>,
    pub current_tag: Mutex<String>,
    pub done: AtomicBool,
}

impl EngineStats {
    pub fn new() -> Self {
        EngineStats {
            tried: AtomicI64::new(0),
            base_tried: AtomicI64::new(0),
            total: AtomicI64::new(-1),
            phase: Mutex::new("准备中".into()),
            current: Mutex::new(String::new()),
            current_tag: Mutex::new(String::new()),
            done: AtomicBool::new(false),
        }
    }
    pub fn add_tried(&self) {
        self.tried.fetch_add(1, Ordering::Relaxed);
    }
    pub fn reached(&self, n: i64) -> bool {
        self.tried.load(Ordering::Relaxed) >= n
    }
}

/// content fingerprint of every dictionary feeding the run (size+mtime);
/// a changed dictionary invalidates the session. The mtime is expressed as
/// .NET DateTime.Ticks (100 ns since 0001-01-01) so a session saved by the
/// C# build resumes under the Rust build and vice versa (spec §7.2).
pub fn dict_fingerprint(cfg: &CrackConfig) -> Option<String> {
    if cfg.mode == "mask" {
        return Some(String::new());
    }
    let mut files: Vec<&String> = Vec::new();
    if cfg.mode == "comb" {
        if let Some(a) = cfg.dict_files.get(0) {
            files.push(a);
        }
        if let Some(b) = &cfg.dict_file_b {
            files.push(b);
        }
    } else {
        files.extend(cfg.dict_files.iter());
    }
    let mut sb = String::new();
    for f in files {
        if f == "-" {
            sb.push_str("stdin;");
            continue;
        }
        let md = std::fs::metadata(f).ok()?;
        let mtime = dotnet_ticks(&md.modified().ok()?);
        sb.push_str(&format!("{}:{};", md.len(), mtime));
    }
    Some(sb)
}

/// SystemTime -> .NET DateTime.Ticks (100 ns units since 0001-01-01, the
/// value DateTime.LastWriteTimeUtc.Ticks reports). 621355968000000000 is the
/// tick offset of the Unix epoch; on Windows the underlying filetime has
/// exactly 100 ns resolution so the value matches the C# build bit-for-bit.
fn dotnet_ticks(t: &std::time::SystemTime) -> u128 {
    const UNIX_EPOCH_TICKS: u128 = 621_355_968_000_000_000;
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => UNIX_EPOCH_TICKS + d.as_nanos() / 100,
        Err(e) => {
            let before = e.duration();
            UNIX_EPOCH_TICKS.saturating_sub(before.as_nanos() / 100)
        }
    }
}

fn count_mask_tokens(mask: &str) -> usize {
    let chars: Vec<char> = mask.chars().collect();
    let mut n = 0;
    let mut lit = false;
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() {
            let c = chars[i + 1];
            if "lud?sahH1234".contains(c) {
                n += 1;
                i += 2;
                lit = false;
                continue;
            }
            if c == '?' {
                i += 2;
                lit = true;
                continue;
            }
        }
        if !lit {
            n += 1;
            lit = true;
        }
        i += 1;
    }
    n.max(1)
}

pub struct CrackEngine {
    cfg: CrackConfig,
    pub stats: Arc<EngineStats>,
    pub log_note: Arc<Mutex<String>>,
}

impl CrackEngine {
    pub fn new(cfg: CrackConfig) -> Self {
        CrackEngine { cfg, stats: Arc::new(EngineStats::new()), log_note: Arc::new(Mutex::new(String::new())) }
    }

    fn build_source(&self) -> Result<Box<dyn CandidateSource + Send>, String> {
        match self.cfg.mode.as_str() {
            "mask" => {
                let mask = self.cfg.mask.clone().ok_or("掩码为空。")?;
                let max_len = if self.cfg.mask_max > 0 {
                    self.cfg.mask_max as usize
                } else {
                    count_mask_tokens(&mask)
                };
                Ok(Box::new(MaskSource::new(&mask, &self.cfg.custom_sets, self.cfg.mask_min, max_len)))
            }
            "comb" => {
                let a = self.cfg.dict_files.get(0).cloned().ok_or("组合模式需要两个字典文件。")?;
                let b = self.cfg.dict_file_b.clone().ok_or("组合模式需要两个字典文件。")?;
                if a != "-" && !Path::new(&a).exists() {
                    return Err(format!("字典文件不存在: {}", a));
                }
                if !Path::new(&b).exists() {
                    return Err(format!("字典文件不存在: {}", b));
                }
                Ok(Box::new(CombinatorSource::new(a, b)))
            }
            _ => {
                if self.cfg.dict_files.is_empty() {
                    return Err("没有指定字典文件。".into());
                }
                for f in &self.cfg.dict_files {
                    if f != "-" && !Path::new(f).exists() {
                        return Err(format!("字典文件不存在: {}", f));
                    }
                }
                Ok(Box::new(DictionarySource::new(
                    self.cfg.dict_files.clone(),
                    self.cfg.presets.clone(),
                    self.cfg.dedupe,
                )))
            }
        }
    }

    /// Runs a full crack attempt. Never panics for per-candidate errors.
    /// `external` is the Ctrl+C cancel flag.
    pub fn run(&self, external: Arc<AtomicBool>) -> CrackResult {
        let mut res = CrackResult::default();
        let sw = Instant::now();
        let archive = std::fs::canonicalize(&self.cfg.archive_path)
            .map(|p| {
                let s = p.display().to_string();
                s.strip_prefix(r"\\?\").map(|x| x.to_string()).unwrap_or(s)
            })
            .unwrap_or_else(|_| self.cfg.archive_path.clone());
        // File.Exists in C# is "exists and is a regular file", so a directory
        // takes the "不存在" branch just like a missing archive
        let apath = Path::new(&archive);
        if !apath.exists() || apath.is_dir() {
            res.error = Some(format!("压缩包文件不存在: {}", archive));
            return res;
        }

        let info = archive::parse(&archive);
        if let Some(err) = &info.open_error {
            // C# Engine: "解析压缩包失败: " + ex.Message
            res.error = Some(format!("解析压缩包失败: {}", err));
            return res;
        }

        // pick the verifier: native first, else the 7z/rar spawn fallback
        let verifier_obj: Box<dyn Verifier + Send + Sync> = match verifier::create_native(&info, &archive) {
            Some(v) => v,
            None => {
                let tool = self
                    .cfg
                    .user_tool
                    .clone()
                    .filter(|t| !t.is_empty() && Path::new(t).exists())
                    .or_else(crate::tool::ToolLocator::find_extractor);
                match tool {
                    Some(t) => Box::new(crate::tool::SpawnVerifier::new(t, archive.clone())),
                    None => {
                        res.error = Some("未找到可用的解压工具（7z.exe / rar.exe），无法测试该压缩包。".into());
                        return res;
                    }
                }
            }
        };

        // pre-flight: an unencrypted archive must error out, not "crack"
        use archive::ArchiveKind;
        if info.kind == ArchiveKind::Rar5 && info.rar5.is_none() {
            res.error = Some("该压缩包没有密码保护，无需破解。".into());
            return res;
        }
        if info.kind == ArchiveKind::Zip && info.zip.is_none() && info.detect_note.contains("no encrypted entry") {
            res.error = Some("该压缩包没有密码保护（或未检测到加密条目）。".into());
            return res;
        }
        // non-native path: probe with an empty password - exit 0 means no
        // password was needed, so there is nothing to crack
        if !verifier_obj.native() && verifier_obj.verify("") {
            res.error = Some("该压缩包没有密码保护，无需破解。".into());
            return res;
        }

        let params_hash = self.cfg.params_hash();
        let dict_fp = dict_fingerprint(&self.cfg);

        let mut source = match self.build_source() {
            Ok(s) => s,
            Err(e) => {
                res.error = Some(format!("构造攻击计划失败: {}", e));
                return res;
            }
        };

        let mut pos = SourcePosition::default();
        let sess_path: PathBuf = match &self.cfg.session_file {
            Some(p) => PathBuf::from(p),
            None => session::session_path(),
        };
        let mut sess: Option<SessionState> = None;
        let mut session_save_failed = false;
        if self.cfg.checkpoint_enabled {
            if self.cfg.resume_requested {
                sess = SessionState::load(&sess_path);
            } else {
                let _ = std::fs::remove_file(&sess_path);
            }
            if let Some(s) = &sess {
                if !s.matches(&archive, &params_hash, dict_fp.as_deref()) {
                    sess = None;
                    *self.log_note.lock().unwrap() = "已忽略不匹配的历史会话".into();
                }
            }
            if let Some(s) = &sess {
                pos.file_idx = s.file_idx;
                pos.line_idx = s.line_idx;
                pos.seg = s.seg;
                pos.counter = s.counter;
                pos.idx_a = s.idx_a;
                pos.idx_b = s.idx_b;
                *self.stats.phase.lock().unwrap() = format!("续跑: {}", s.save_time_text);
            }
        }

        if let Some(total) = source.total() {
            self.stats.total.store(total as i64, Ordering::Relaxed);
        }
        let threads = if self.cfg.threads == 0 {
            let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as i64;
            (cores - 2).clamp(1, 32) as u32
        } else {
            self.cfg.threads
        };
        let mut session_tried = 0i64;
        if let Some(s) = &sess {
            // rewind a safety margin so queued/mid-Verify candidates are
            // re-tried, never skipped
            let margin = (threads as i64) * 8 + threads as i64 + 16;
            pos.line_idx = if pos.line_idx > margin { pos.line_idx - margin } else { 0 };
            pos.counter = if pos.counter > margin as u64 { pos.counter - margin as u64 } else { 0 };
            pos.idx_b = if pos.idx_b > margin { pos.idx_b - margin } else { 0 };
            pos.idx_a = if pos.idx_a > margin { pos.idx_a - margin } else { 0 };
            if pos.idx_a < s.idx_a {
                pos.idx_b = 0; // earlier A line: B restarts
            }
            session_tried = s.tried_all;
        }
        self.stats.base_tried.store(session_tried, Ordering::Relaxed);
        {
            let phase = self.stats.phase.lock().unwrap().clone();
            if !phase.starts_with("续跑") {
                *self.stats.phase.lock().unwrap() = verifier_obj.describe();
            }
        }

        // producer/consumer via a bounded channel (capacity threads*8)
        let (tx, rx) = crossbeam_channel::bounded::<crate::attacks::Candidate>((threads * 8) as usize);
        let cancel = Arc::new(AtomicBool::new(false));
        let hit_password = Arc::new(Mutex::new(Option::<String>::None));
        let producer_error = Arc::new(Mutex::new(Option::<String>::None));

        // bridge external -> internal cancel, the Rust counterpart of the
        // C# linked CancellationTokenSource: the candidate sources' loops
        // only watch the internal flag, and with mutation presets a single
        // line can fan out up to 100k candidates, so an external stop
        // (Ctrl+C / GUI cancel event) that only reached the emit closure
        // would leave the producer discarding candidates for hours
        {
            let external_bridge = external.clone();
            let cancel_bridge = cancel.clone();
            std::thread::spawn(move || {
                while !cancel_bridge.load(Ordering::Relaxed) {
                    if external_bridge.load(Ordering::Relaxed) {
                        cancel_bridge.store(true, Ordering::Relaxed);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
        }

        // live position shared producer -> checkpoint thread
        let live_pos = Arc::new(Mutex::new(pos.clone()));
        let live_pos_prod = live_pos.clone();

        let cancel_prod = cancel.clone();
        let cancel_emit = cancel.clone();
        let external_emit = external.clone();
        let producer_error_prod = producer_error.clone();
        // the encoding plan note is produced during enumeration inside the
        // producer thread; carry it back through a shared slot (the C# build
        // just reads the shared source object after the producer finished)
        let plan_note: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let plan_note_prod = plan_note.clone();
        let producer = std::thread::spawn(move || {
            let mut local_pos = live_pos_prod.lock().unwrap().clone();
            // the emit closure writes the live position before each send; to
            // avoid a borrow conflict we keep local_pos outside the closure
            // and pass both in explicitly.
            {
                let live_pos_prod = &live_pos_prod;
                let tx = &tx;
                let mut emit = move |mut cand: crate::attacks::Candidate, pos: &SourcePosition| {
                    // stop feeding once a hit / max-tries / Ctrl+C cancelled
                    // the run: the workers have gone away and a blocking send
                    // into the bounded queue would deadlock the join. The
                    // C# side relied on queue.Add(cand, ct) throwing.
                    if cancel_emit.load(Ordering::Relaxed) || external_emit.load(Ordering::Relaxed) {
                        return;
                    }
                    *live_pos_prod.lock().unwrap() = pos.clone();
                    // bounded send with a cancel-aware retry loop: workers
                    // can be wedged past the timeout (e.g. a slow spawn
                    // verifier), and a candidate dropped here is also skipped
                    // by --resume (live_pos already advanced past it), so
                    // retry until it is delivered or the run is over. A bare
                    // send() would re-introduce the M3 deadlock: a cancel
                    // arriving after the consumers exited would block the
                    // producer forever.
                    loop {
                        match tx.send_timeout(cand, Duration::from_millis(100)) {
                            Ok(()) => break,
                            Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => return,
                            Err(crossbeam_channel::SendTimeoutError::Timeout(pending)) => {
                                cand = pending;
                                if cancel_emit.load(Ordering::Relaxed) || external_emit.load(Ordering::Relaxed) {
                                    return;
                                }
                            }
                        }
                    }
                };
                source.enumerate_with_pos(&mut local_pos, &cancel_prod, &mut emit);
            }
            *live_pos_prod.lock().unwrap() = local_pos;
            if let Some(n) = source.plan_note() {
                *plan_note_prod.lock().unwrap() = Some(n);
            }
            // tx dropped here (via the closure capture ending) closes the channel
            let _ = &producer_error_prod;
        });

        let max_tries = self.cfg.max_tries;
        let maxed_out = Arc::new(AtomicBool::new(false));
        let worker_error = Arc::new(Mutex::new(Option::<String>::None));
        let v: Arc<dyn Verifier + Send + Sync> = verifier_obj.into();
        let mut workers = Vec::new();
        for _ in 0..threads {
            let rx = rx.clone();
            let v = v.clone();
            let stats = self.stats.clone();
            let cancel = cancel.clone();
            let external = external.clone();
            let hit = hit_password.clone();
            let maxed = maxed_out.clone();
            let werr = worker_error.clone();
            workers.push(std::thread::spawn(move || {
                for cand in rx.iter() {
                    if (cancel.load(Ordering::Relaxed) || external.load(Ordering::Relaxed))
                        && hit.lock().unwrap().is_some()
                    {
                        return;
                    }
                    *stats.current.lock().unwrap() = cand.pw.clone();
                    *stats.current_tag.lock().unwrap() = cand.tag.clone();
                    stats.add_tried();
                    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| v.verify(&cand.pw)))
                        .unwrap_or_else(|_| {
                            *werr.lock().unwrap() = Some("verify panicked".into());
                            false
                        });
                    if ok {
                        {
                            let mut h = hit.lock().unwrap();
                            if h.is_none() {
                                *h = Some(cand.pw.clone());
                            }
                        }
                        cancel.store(true, Ordering::Relaxed);
                        return;
                    }
                    if max_tries > 0 && stats.reached(max_tries) {
                        maxed.store(true, Ordering::Relaxed);
                        cancel.store(true, Ordering::Relaxed);
                        return;
                    }
                    if external.load(Ordering::Relaxed) {
                        return;
                    }
                }
            }));
        }

        // checkpoint thread: snapshot every 3 s
        let checkpoint_stop = Arc::new(AtomicBool::new(false));
        let checkpoint_handle = if self.cfg.checkpoint_enabled {
            let stats = self.stats.clone();
            let live_pos = live_pos.clone();
            let hit = hit_password.clone();
            let archive = archive.clone();
            let params_hash = params_hash.clone();
            let dict_fp = dict_fp.clone();
            let sess_path = sess_path.clone();
            let stop = checkpoint_stop.clone();
            let save_failed = Arc::new(AtomicBool::new(false));
            let save_failed_clone = save_failed.clone();
            let handle = std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // sleep in short slices so the final join after a hit or
                    // stop does not add up to a full 3 s tail to the reported
                    // elapsed time (the C# build wakes its timer instead)
                    for _ in 0..30 {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if !stats.done.load(Ordering::Relaxed) && hit.lock().unwrap().is_none() {
                        let p = live_pos.lock().unwrap().clone();
                        let s = SessionState {
                            archive: archive.clone(),
                            params: params_hash.clone(),
                            dictfp: dict_fp.clone(),
                            tried_all: stats.base_tried.load(Ordering::Relaxed) + stats.tried.load(Ordering::Relaxed),
                            file_idx: p.file_idx,
                            line_idx: p.line_idx,
                            seg: p.seg,
                            counter: p.counter,
                            idx_a: p.idx_a,
                            idx_b: p.idx_b,
                            save_time_text: now_text(),
                        };
                        if !s.save(&sess_path) {
                            save_failed_clone.store(true, Ordering::Relaxed);
                        }
                    }
                }
            });
            Some((handle, save_failed))
        } else {
            None
        };

        for w in workers {
            let _ = w.join();
        }
        let _ = producer.join();
        checkpoint_stop.store(true, Ordering::Relaxed);
        if let Some((h, sf)) = checkpoint_handle {
            let _ = h.join();
            if sf.load(Ordering::Relaxed) {
                session_save_failed = true;
            }
        }
        self.stats.done.store(true, Ordering::Relaxed);

        res.tried = self.stats.base_tried.load(Ordering::Relaxed) + self.stats.tried.load(Ordering::Relaxed);
        res.elapsed_sec = sw.elapsed().as_secs_f64();
        let hit = hit_password.lock().unwrap().clone();
        res.cancelled = external.load(Ordering::Relaxed) && hit.is_none();
        res.maxed_out = maxed_out.load(Ordering::Relaxed);

        if let Some(pw) = hit {
            res.found = true;
            res.password = pw.clone();
            res.result_file = self.write_result_file(&archive, &pw);
            let _ = std::fs::remove_file(&sess_path);
        } else if res.cancelled || res.maxed_out {
            if self.cfg.checkpoint_enabled {
                let p = live_pos.lock().unwrap().clone();
                let s = SessionState {
                    archive: archive.clone(),
                    params: params_hash.clone(),
                    dictfp: dict_fp.clone(),
                    tried_all: res.tried,
                    file_idx: p.file_idx,
                    line_idx: p.line_idx,
                    seg: p.seg,
                    counter: p.counter,
                    idx_a: p.idx_a,
                    idx_b: p.idx_b,
                    save_time_text: now_text(),
                };
                if !s.save(&sess_path) {
                    session_save_failed = true;
                }
            }
            if let Some(e) = producer_error.lock().unwrap().clone() {
                res.error = Some(format!("候选生成失败: {}", e));
            } else if let Some(e) = worker_error.lock().unwrap().clone() {
                res.error = Some(format!("验证线程错误: {}", e));
            }
        } else {
            let _ = std::fs::remove_file(&sess_path);
            if let Some(e) = producer_error.lock().unwrap().clone() {
                res.error = Some(format!("候选生成失败: {}", e));
            } else if let Some(e) = worker_error.lock().unwrap().clone() {
                res.error = Some(format!("验证线程错误: {}", e));
            }
        }
        if session_save_failed && !res.found {
            res.warning = Some("会话/进度文件写入失败（exe 目录可能只读），断点续跑不可用。".into());
        }
        // C# Engine.Run: LogNote = ((DictionarySource)source).LastPlanNote --
        // an unconditional overwrite for dictionary runs (the session-
        // mismatch note above is replaced by the encoding plan note, exactly
        // like the C# build); other sources leave the note untouched
        if let Some(note) = plan_note.lock().unwrap().clone() {
            *self.log_note.lock().unwrap() = note;
        }
        res
    }

    fn write_result_file(&self, archive: &str, password: &str) -> Option<String> {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        let stem = Path::new(archive).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let default_path = exe_dir.join(format!("{}_password.txt", stem));
        if let Some(out) = &self.cfg.out_file {
            let p = PathBuf::from(out);
            if result::write_result_text(&p, password).is_ok() {
                return Some(out.clone());
            }
        }
        if result::write_result_text(&default_path, password).is_ok() {
            return Some(default_path.display().to_string());
        }
        None
    }
}

fn now_text() -> String {
    // local time "HH:mm:ss", matching the C# SaveTimeText stamp shown by
    // the "续跑: ..." phase line. GetLocalTime on Windows keeps the stamp
    // identical to the C# build's DateTime.Now; other platforms fall back
    // to UTC (cosmetic difference only).
    #[cfg(windows)]
    {
        #[repr(C)]
        struct SystemTime {
            year: u16,
            month: u16,
            day_of_week: u16,
            day: u16,
            hour: u16,
            minute: u16,
            second: u16,
            milliseconds: u16,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetLocalTime(out: *mut SystemTime);
        }
        let mut st = SystemTime { year: 0, month: 0, day_of_week: 0, day: 0, hour: 0, minute: 0, second: 0, milliseconds: 0 };
        unsafe { GetLocalTime(&mut st) };
        format!("{:02}:{:02}:{:02}", st.hour, st.minute, st.second)
    }
    #[cfg(not(windows))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
    }
}

// ------------------------------------------------------------------
// Benchmark (from the M2 step).
pub fn bench_measure(
    verifier: &Arc<dyn Verifier + Send + Sync>,
    threads: u32,
    seconds: u32,
) -> f64 {
    let threads = if threads == 0 {
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as i64;
        (cores - 2).clamp(1, 32) as u32
    } else {
        threads
    };
    let total = Arc::new(AtomicU64::new(0));
    let deadline = Duration::from_secs(seconds as u64);
    let start = Instant::now();
    let mut handles = Vec::new();
    for t in 0..threads {
        let v = verifier.clone();
        let total = total.clone();
        handles.push(std::thread::spawn(move || {
            let mut mine: u64 = 0;
            let mut seed: u64 = (t as u64).wrapping_mul(7919).wrapping_add(13);
            while start.elapsed() < deadline {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let pwd = format!("{:016x}", seed);
                let _ = v.verify(&pwd);
                mine += 1;
            }
            total.fetch_add(mine, Ordering::Relaxed);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let elapsed = start.elapsed().as_secs_f64();
    total.load(Ordering::Relaxed) as f64 / elapsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionState;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dceng-{}-{}", tag, std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    }

    #[test]
    fn dict_fp_deterministic_and_content_sensitive() {
        let dir = temp_dir("fp");
        let f = dir.join("d.txt");
        std::fs::write(&f, "one\n").unwrap();
        let mut cfg = CrackConfig { mode: "dict".into(), dict_files: vec![f.display().to_string()], ..Default::default() };
        let fp1 = dict_fingerprint(&cfg).unwrap();
        assert_eq!(fp1, dict_fingerprint(&cfg).unwrap(), "fp deterministic");
        // a fingerprint must look like the C# build's size:Ticks pairs
        assert!(fp1.ends_with(';') && fp1.contains(':'), "fp shape: {}", fp1);
        let ticks: u128 = fp1.split(';').next().unwrap().split(':').nth(1).unwrap().parse().unwrap();
        assert!(ticks > 630_000_000_000_000_000, "ticks in .NET range: {}", ticks);
        // rewrite with different content: size changes, so must the fp
        std::fs::write(&f, "one\ntwo\nthree\n").unwrap();
        assert_ne!(fp1, dict_fingerprint(&cfg).unwrap(), "fp changes with content");

        // old sessions saved without a dictfp are rejected for dict runs
        let old = SessionState { archive: "a.rar".into(), params: "p".into(), ..Default::default() };
        assert!(!old.matches("a.rar", "p", Some(&fp1)), "old session (no fp) rejected for dict");
        // fingerprint unavailable: keep the lenient behavior
        assert!(old.matches("a.rar", "p", None), "null fp keeps lenient");
        let with_fp = SessionState { archive: "a.rar".into(), params: "p".into(), dictfp: Some(fp1.clone()), ..Default::default() };
        assert!(with_fp.matches("a.rar", "p", Some(&fp1)), "matching fp accepted");

        cfg.mode = "mask".into();
        assert_eq!(dict_fingerprint(&cfg), Some(String::new()), "mask fp empty");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dict_fp_comb_and_stdin_shapes() {
        let dir = temp_dir("fpc");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "x\n").unwrap();
        std::fs::write(&b, "y\n").unwrap();
        let cfg = CrackConfig {
            mode: "comb".into(),
            dict_files: vec![a.display().to_string()],
            dict_file_b: Some(b.display().to_string()),
            ..Default::default()
        };
        let fp = dict_fingerprint(&cfg).unwrap();
        // A and B both feed the fingerprint, in that order
        assert_eq!(fp.matches(':').count(), 2);
        let stdin_cfg = CrackConfig { mode: "dict".into(), dict_files: vec!["-".into()], ..Default::default() };
        assert_eq!(dict_fingerprint(&stdin_cfg), Some("stdin;".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dotnet_ticks_matches_clr() {
        // DateTime(1970,1,1).UtcTicks == 621355968000000000
        let t = std::time::UNIX_EPOCH;
        assert_eq!(dotnet_ticks(&t), 621_355_968_000_000_000);
        // 2026-01-01T00:00:00Z -> 621355968000000000 + 56 years of seconds
        // (1767225600 s; leap days included) - guards against a unit slip
        let d = std::time::Duration::from_secs(1_767_225_600);
        assert_eq!(dotnet_ticks(&(t + d)), 621_355_968_000_000_000 + 1_767_225_600u128 * 10_000_000);
    }

    #[test]
    fn now_text_is_clock_shaped() {
        let s = now_text();
        assert_eq!(s.len(), 8, "HH:mm:ss shape");
        assert_eq!(&s[2..3], ":", "colon at 2");
        assert_eq!(&s[5..6], ":", "colon at 5");
    }
}
