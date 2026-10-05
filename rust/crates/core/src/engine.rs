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
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
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
/// a changed dictionary invalidates the session.
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
        let mtime = md
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos();
        sb.push_str(&format!("{}:{};", md.len(), mtime));
    }
    Some(sb)
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
        if !Path::new(&archive).exists() {
            res.error = Some(format!("压缩包文件不存在: {}", archive));
            return res;
        }

        let info = archive::parse(&archive);

        let verifier_obj: Box<dyn Verifier + Send + Sync> = match verifier::create_native(&info, &archive) {
            Some(v) => v,
            None => {
                // external-tool fallback is M4; report unsupported for now
                res.error = Some(format!(
                    "该压缩包不支持原生验证（{}）。外部工具回退尚未实现（M4）。",
                    info.detect_note
                ));
                return res;
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
        let sess_path = session::session_path();
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

        // live position shared producer -> checkpoint thread
        let live_pos = Arc::new(Mutex::new(pos.clone()));
        let live_pos_prod = live_pos.clone();

        let cancel_prod = cancel.clone();
        let cancel_emit = cancel.clone();
        let external_emit = external.clone();
        let producer_error_prod = producer_error.clone();
        let producer = std::thread::spawn(move || {
            let mut local_pos = live_pos_prod.lock().unwrap().clone();
            // the emit closure writes the live position before each send; to
            // avoid a borrow conflict we keep local_pos outside the closure
            // and pass both in explicitly.
            {
                let live_pos_prod = &live_pos_prod;
                let tx = &tx;
                let mut emit = move |cand: crate::attacks::Candidate, pos: &SourcePosition| {
                    // stop feeding once a hit / max-tries / Ctrl+C cancelled
                    // the run: the workers have gone away and a blocking send
                    // into the bounded queue would deadlock the join. The
                    // C# side relied on queue.Add(cand, ct) throwing.
                    if cancel_emit.load(Ordering::Relaxed) || external_emit.load(Ordering::Relaxed) {
                        return;
                    }
                    *live_pos_prod.lock().unwrap() = pos.clone();
                    // bounded send with a cancel-aware timeout so a vanishing
                    // consumer can never wedge the producer
                    let _ = tx.send_timeout(cand, Duration::from_millis(100));
                };
                source.enumerate_with_pos(&mut local_pos, &cancel_prod, &mut emit);
            }
            *live_pos_prod.lock().unwrap() = local_pos;
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
                    std::thread::sleep(Duration::from_millis(3000));
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
        if external.load(Ordering::Relaxed) && hit_password.lock().unwrap().is_none() {
            // honour external cancel inside producer too
        }
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
            if result::write_result_text(&p, password, "").is_ok() {
                return Some(out.clone());
            }
        }
        if result::write_result_text(&default_path, password, "").is_ok() {
            return Some(default_path.display().to_string());
        }
        None
    }
}

fn now_text() -> String {
    // local time "yyyy-MM-dd HH:mm:ss"; good enough for a checkpoint stamp
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{}s", secs % 1000000)
}

// ------------------------------------------------------------------
// Benchmark (from the M2 step).
use crate::verifier::Verifier as _BenchVerifier;
use std::sync::atomic::AtomicU64 as _AtomicU64;
use std::time::Duration as _Duration;

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
    let total = Arc::new(_AtomicU64::new(0));
    let deadline = _Duration::from_secs(seconds as u64);
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

// silence the unused-import helper alias when only bench uses them
#[allow(unused_imports)]
use _BenchVerifier as _BenchVerifierUsed;
