// attacks.rs -- candidate generation: dictionary (multi-encoding sweep +
// mutation presets), mask/brute force, combinator. Port of Attacks.cs.
//
// Unlike the C# IEnumerable pull model, sources here push candidates into a
// callback so the engine's producer thread can stream them into the queue
// without a second generator thread. Each source exposes a serializable
// SourcePosition for checkpoint/resume.
use crate::encoding;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct SourcePosition {
    pub file_idx: i64,
    pub line_idx: i64,
    pub seg: i64,       // mask: current expanded length
    pub counter: u64,   // mask: odometer
    pub idx_a: i64,     // combinator
    pub idx_b: i64,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub pw: String,
    pub tag: String,
}

pub trait CandidateSource {
    /// Push candidates into `emit`, resuming from `pos`; honour `cancel`.
    /// `emit` receives each candidate plus a reference to the live position
    /// so the engine can checkpoint mid-stream.
    fn enumerate_with_pos(
        &mut self,
        pos: &mut SourcePosition,
        cancel: &Arc<AtomicBool>,
        emit: &mut dyn FnMut(Candidate, &SourcePosition),
    );

    fn total(&mut self) -> Option<u64>;
    fn describe(&self) -> String;
    fn position_text(&self, pos: &SourcePosition) -> String;

    /// encoding plan note reported by the "未找到密码。（编码方案: …）" line;
    /// only the dictionary source produces one (C# reads
    /// DictionarySource.LastPlanNote in Engine.Run and leaves LogNote alone
    /// for the other sources)
    fn plan_note(&self) -> Option<String> {
        None
    }
}

// ------------------------------------------------------------------
// raw byte line splitter shared by the dictionary and combinator sources:
// 0x0A can never appear inside a UTF-8/GBK multibyte char, so byte-level
// splitting is safe for the sweep encodings. Port of RawLines.
pub struct RawLines {
    idx: i64,
}

impl RawLines {
    pub fn new() -> Self {
        RawLines { idx: 0 }
    }

    /// Stream raw lines from `r`, resuming at `start_offset` (e.g. past a
    /// UTF-8 BOM). Tolerates CRLF/LF and a missing trailing newline.
    pub fn enumerate<R: Read + Seek>(
        &mut self,
        r: &mut R,
        start_offset: u64,
        cancel: &Arc<AtomicBool>,
        f: &mut dyn FnMut(&[u8], i64),
    ) {
        if start_offset > 0 {
            let _ = r.seek(SeekFrom::Start(start_offset));
        }
        let mut buf = vec![0u8; 1 << 20];
        let mut fill = 0usize;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let n = match r.read(&mut buf[fill..]) {
                Ok(n) => n,
                Err(_) => 0,
            };
            let eof = n == 0;
            let end = fill + n;
            let mut start = 0usize;
            let mut i = 0usize;
            while i < end {
                if buf[i] == 0x0A {
                    let mut len = i - start;
                    if len > 0 && buf[start + len - 1] == 0x0D {
                        len -= 1;
                    }
                    let idx = self.idx;
                    self.idx += 1;
                    f(&buf[start..start + len], idx);
                    start = i + 1;
                }
                i += 1;
            }
            let keep = end - start;
            if !eof && keep == end && end == buf.len() {
                buf.resize(buf.len() * 2, 0); // single line longer than the buffer: grow
                fill = end;
                continue;
            }
            if eof {
                let mut len = keep;
                if len > 0 && buf[start + len - 1] == 0x0D {
                    len -= 1;
                }
                if len > 0 {
                    let idx = self.idx;
                    f(&buf[start..start + len], idx);
                }
                return;
            }
            buf.copy_within(start..end, 0);
            fill = keep;
        }
    }
}

// ------------------------------------------------------------------
// mutation presets - chained. Port of Rules.
pub struct Rules;

impl Rules {
    pub const PRESET_NAMES: [&'static str; 6] = ["years", "digits", "leet", "rev", "cap", "double"];

    pub fn apply(preset: &str, w: &str, out: &mut Vec<String>) {
        if w.is_empty() {
            return;
        }
        match preset {
            "years" => {
                let y_max = current_year() + 1;
                for y in 1980..=y_max {
                    out.push(format!("{}{}", w, y));
                }
            }
            "digits" => {
                for d in 0..=9u8 {
                    out.push(format!("{}{}", w, (b'0' + d) as char));
                }
                for d in 0..=99u32 {
                    out.push(format!("{}{:02}", w, d));
                }
            }
            "leet" => {
                let t: String = w
                    .chars()
                    .map(|c| match c {
                        'a' => '@',
                        'e' => '3',
                        'o' => '0',
                        'i' => '1',
                        's' => '5',
                        'g' => '9',
                        't' => '7',
                        x => x,
                    })
                    .collect();
                if t != w {
                    out.push(t);
                }
            }
            "rev" => {
                let t: String = w.chars().rev().collect();
                if t != w {
                    out.push(t);
                }
            }
            "cap" => {
                let mut chars = w.chars();
                if let Some(first) = chars.next() {
                    let t: String = first.to_uppercase().collect::<String>() + chars.as_str();
                    if t != w {
                        out.push(t);
                    }
                }
            }
            "double" => out.push(format!("{}{}", w, w)),
            _ => {}
        }
    }
}

fn current_year() -> i32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // days -> civil year (Howard Hinnant's algorithm), good enough for a year bound
    let z = (secs / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let year = y + if mp >= 10 { 1 } else { 0 };
    year as i32
}

fn sanitize(s: &str) -> Option<&str> {
    if s.is_empty() {
        return None;
    }
    if s.starts_with(';') {
        return None;
    }
    if s == "\u{FEFF}" {
        return None;
    }
    Some(s)
}

fn count_lines(path: &str) -> u64 {
    let mut count = 0u64;
    let mut in_line = false;
    if let Ok(mut f) = File::open(path) {
        let mut buf = [0u8; 1 << 16];
        while let Ok(n) = f.read(&mut buf) {
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                if b == 0x0A {
                    count += 1;
                    in_line = false;
                } else {
                    in_line = true;
                }
            }
        }
    }
    count + if in_line { 1 } else { 0 }
}

// ------------------------------------------------------------------
const MUTATION_CAP: usize = 100000;

pub struct DictionarySource {
    files: Vec<String>,
    presets: Vec<String>,
    global: Option<HashSet<String>>,
    counted_total: i64,
    pub last_plan_note: String,
}

impl DictionarySource {
    pub fn new(files: Vec<String>, presets: Vec<String>, dedupe: bool) -> Self {
        DictionarySource {
            files,
            presets,
            global: if dedupe { Some(HashSet::new()) } else { None },
            counted_total: -1,
            last_plan_note: String::new(),
        }
    }

    /// Chained mutations over the base words (word -> word+year ->
    /// word+year+digits). Mutants carry the tag of their base word and join
    /// the dedupe set as they are emitted; the MutationCap bounds fan-out.
    fn mutate_chained(
        &mut self,
        base: &[(String, String)],
        emitted: &mut HashSet<String>,
        pos: &SourcePosition,
        emit: &mut dyn FnMut(Candidate, &SourcePosition),
    ) {
        let mut frontier: Vec<(String, String)> = base.to_vec();
        let mut scratch = Vec::new();
        for pi in 0..self.presets.len() {
            if emitted.len() >= MUTATION_CAP {
                return;
            }
            let mut next: Vec<(String, String)> = Vec::new();
            for (w, tag) in &frontier {
                scratch.clear();
                Rules::apply(&self.presets[pi], w, &mut scratch);
                for m in &scratch {
                    if emitted.contains(m) {
                        continue;
                    }
                    if let Some(g) = &mut self.global {
                        if !g.insert(m.clone()) {
                            continue;
                        }
                    }
                    if emitted.len() >= MUTATION_CAP {
                        return;
                    }
                    emitted.insert(m.clone());
                    next.push((m.clone(), tag.clone()));
                    emit(Candidate { pw: m.clone(), tag: tag.clone() }, pos);
                }
            }
            frontier = next;
        }
    }
}

impl CandidateSource for DictionarySource {
    fn plan_note(&self) -> Option<String> {
        Some(self.last_plan_note.clone())
    }

    fn total(&mut self) -> Option<u64> {
        // with mutation presets each line fans out content-dependently; unknown
        if !self.presets.is_empty() {
            return None;
        }
        if self.counted_total < 0 {
            let mut t = 0u64;
            for f in &self.files {
                if f == "-" {
                    self.counted_total = -1;
                    return None; // stdin: unknown length
                }
                t += count_lines(f);
            }
            self.counted_total = t as i64;
        }
        Some(self.counted_total as u64)
    }

    fn describe(&self) -> String {
        let mut parts: Vec<String> = self
            .files
            .iter()
            .map(|f| {
                if f == "-" {
                    "(stdin)".to_string()
                } else {
                    Path::new(f).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| f.clone())
                }
            })
            .collect();
        let mut s = parts.join(", ");
        if !self.presets.is_empty() {
            s.push_str(" + ");
            s.push_str(&self.presets.join("/"));
        }
        parts.clear();
        s
    }

    fn position_text(&self, pos: &SourcePosition) -> String {
        format!("文件 {}/{} 行 {}", pos.file_idx + 1, self.files.len(), pos.line_idx)
    }

    fn enumerate_with_pos(
        &mut self,
        pos: &mut SourcePosition,
        cancel: &Arc<AtomicBool>,
        emit: &mut dyn FnMut(Candidate, &SourcePosition),
    ) {
        for fi in 0..self.files.len() {
            if (fi as i64) < pos.file_idx {
                continue;
            }
            pos.file_idx = fi as i64;
            let path = self.files[fi].clone();
            let (mut stream, plan) = if path == "-" {
                let mut data = Vec::new();
                let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut data);
                let total = data.len() as u64;
                let p = encoding::plan_bytes(&data[..data.len().min(262144)], total);
                (std::io::Cursor::new(data), p)
            } else {
                if !Path::new(&path).exists() {
                    continue;
                }
                let p = encoding::plan_file(&path);
                let f = match File::open(&path) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                // unify the stream type: wrap the file in a cursor-like box
                let mut data = Vec::new();
                let mut f = f;
                let _ = f.read_to_end(&mut data);
                (std::io::Cursor::new(data), p)
            };
            self.last_plan_note = plan.note.clone();
            let utf16 = plan.encs.len() == 1 && plan.encs[0].is_utf16();

            if utf16 {
                // UTF-16 bytes can contain 0x0A inside a character: decode whole
                // then split lines. StreamReader semantics: the BOM is consumed.
                let enc = plan.encs[0];
                let tag = enc.label();
                let mut all = Vec::new();
                let _ = stream.read_to_end(&mut all);
                let body = encoding::strip_utf16_bom(&all[plan.bom_skip as usize..]);
                if let Some(text) = encoding::decode(enc, body) {
                    let mut line_idx = 0i64;
                    for line in text.lines() {
                        if cancel.load(Ordering::Relaxed) {
                            return;
                        }
                        if line_idx < pos.line_idx {
                            line_idx += 1;
                            continue;
                        }
                        pos.line_idx = line_idx;
                        line_idx += 1;
                        let line = line.strip_suffix('\r').unwrap_or(line);
                        let t = match sanitize(line) {
                            Some(t) => t.to_string(),
                            None => continue,
                        };
                        if let Some(g) = &mut self.global {
                            if !g.insert(t.clone()) {
                                continue;
                            }
                        }
                        let mut base = vec![(t.clone(), tag.to_string())];
                        emit(Candidate { pw: t.clone(), tag: tag.to_string() }, pos);
                        if !self.presets.is_empty() {
                            let mut emitted: HashSet<String> = base.iter().map(|(w, _)| w.clone()).collect();
                            self.mutate_chained(&base, &mut emitted, pos, emit);
                            base.clear();
                        }
                    }
                }
            } else {
                let encs = plan.encs.clone();
                let bom_skip = plan.bom_skip;
                let mut rl = RawLines::new();
                let mut line_events: Vec<(Vec<u8>, i64)> = Vec::new();
                rl.enumerate(&mut stream, bom_skip, cancel, &mut |seg, idx| {
                    line_events.push((seg.to_vec(), idx));
                });
                for (bytes, idx) in line_events {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    if idx < pos.line_idx {
                        continue;
                    }
                    pos.line_idx = idx;
                    // decode under every planned encoding, per-line dedup
                    let mut base: Vec<(String, String)> = Vec::new();
                    let mut emitted: HashSet<String> = HashSet::new();
                    for &enc in &encs {
                        if let Some(s) = encoding::decode(enc, &bytes) {
                            if let Some(t) = sanitize(&s) {
                                let t = t.to_string();
                                if !emitted.contains(&t) {
                                    let dup = match &mut self.global {
                                        Some(g) => !g.insert(t.clone()),
                                        None => false,
                                    };
                                    if !dup {
                                        let tag = enc.label().to_string();
                                        emitted.insert(t.clone());
                                        base.push((t.clone(), tag.clone()));
                                        emit(Candidate { pw: t, tag }, pos);
                                    }
                                }
                            }
                        }
                    }
                    if !self.presets.is_empty() {
                        self.mutate_chained(&base, &mut emitted, pos, emit);
                    }
                }
            }
            pos.line_idx = 0;
        }
    }
}

// ------------------------------------------------------------------
struct MaskToken {
    fixed: Option<String>,
    set: Option<Vec<char>>,
}

pub struct MaskSource {
    tokens: Vec<MaskToken>,
    min_len: usize,
    max_len: usize,
    space_per_len: Vec<u64>,
    total_space: u64,
}

impl MaskSource {
    pub fn new(mask: &str, custom_sets: &[String; 4], min_len: usize, max_len: usize) -> Self {
        let mut tokens = Vec::new();
        let chars: Vec<char> = mask.chars().collect();
        let mut lit = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '?' && i + 1 < chars.len() {
                let n = chars[i + 1];
                if let Some(set) = resolve_set(n, custom_sets) {
                    if !lit.is_empty() {
                        tokens.push(MaskToken { fixed: Some(std::mem::take(&mut lit)), set: None });
                    }
                    tokens.push(MaskToken { fixed: None, set: Some(set) });
                    i += 2;
                    continue;
                }
                if n == '?' {
                    lit.push('?');
                    i += 2;
                    continue;
                }
            }
            lit.push(c);
            i += 1;
        }
        if !lit.is_empty() {
            tokens.push(MaskToken { fixed: Some(lit), set: None });
        }

        let full = tokens.len();
        let min_len = min_len.max(1);
        let mut max_len = if max_len < min_len { min_len } else { max_len };
        if max_len > full {
            max_len = full;
        }
        let mut space_per_len = vec![0u64; max_len + 1];
        let mut total_space: u64 = 0;
        for l in min_len..=max_len {
            let mut space: u64 = 1;
            let mut overflow = false;
            for t in 0..l {
                if let Some(set) = &tokens[t].set {
                    let size = set.len() as u64;
                    if size == 0 {
                        continue;
                    }
                    if space > u64::MAX / size {
                        overflow = true;
                        break;
                    }
                    space *= size;
                }
            }
            space_per_len[l] = if overflow { u64::MAX } else { space };
            if overflow || total_space > u64::MAX - space_per_len[l] {
                total_space = u64::MAX;
            } else {
                total_space += space_per_len[l];
            }
        }
        MaskSource { tokens, min_len, max_len, space_per_len, total_space }
    }

    fn describe_mask(&self) -> String {
        let mut sb = String::new();
        for t in &self.tokens {
            if let Some(f) = &t.fixed {
                sb.push_str(f);
            } else if let Some(set) = &t.set {
                match set.len() {
                    10 => sb.push_str("?d"),
                    26 => sb.push_str(if set[0] == 'a' { "?l" } else { "?u" }),
                    16 => sb.push_str("?h"),
                    32 => sb.push_str("?s"),
                    95 => sb.push_str("?a"),
                    _ => {
                        sb.push_str("?[");
                        sb.extend(set.iter());
                        sb.push(']');
                    }
                }
            }
        }
        sb
    }
}

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

fn resolve_set(code: char, custom_sets: &[String; 4]) -> Option<Vec<char>> {
    match code {
        'l' => Some(chars("abcdefghijklmnopqrstuvwxyz")),
        'u' => Some(chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
        'd' => Some(chars("0123456789")),
        's' => Some(chars("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")),
        'a' => Some(chars("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")),
        'h' => Some(chars("0123456789abcdef")),
        'H' => Some(chars("0123456789ABCDEF")),
        '1'..='4' => {
            let s = &custom_sets[(code as usize) - ('1' as usize)];
            if s.is_empty() {
                None
            } else {
                Some(chars(s))
            }
        }
        _ => None,
    }
}

impl CandidateSource for MaskSource {
    fn total(&mut self) -> Option<u64> {
        if self.total_space >= u64::MAX {
            None
        } else {
            Some(self.total_space)
        }
    }
    fn describe(&self) -> String {
        format!("掩码 {} 长度 {}-{}", self.describe_mask(), self.min_len, self.max_len)
    }
    fn position_text(&self, pos: &SourcePosition) -> String {
        format!("长度 {} 进度 {}", pos.seg, pos.counter)
    }

    fn enumerate_with_pos(
        &mut self,
        pos: &mut SourcePosition,
        cancel: &Arc<AtomicBool>,
        emit: &mut dyn FnMut(Candidate, &SourcePosition),
    ) {
        let saved_seg = pos.seg;
        let saved_counter = pos.counter;
        for len in self.min_len..=self.max_len {
            if (len as i64) < saved_seg {
                continue;
            }
            pos.seg = len as i64;
            let space = self.space_per_len[len];
            let start: u64 = if len as i64 == saved_seg { saved_counter } else { 0 };
            let mut slots: Vec<usize> = Vec::new();
            let mut char_count = 0usize;
            let mut char_pos: Vec<usize> = Vec::new();
            for t in 0..len {
                let tok = &self.tokens[t];
                if tok.set.is_some() {
                    slots.push(t);
                    char_pos.push(char_count);
                    char_count += 1;
                } else if let Some(f) = &tok.fixed {
                    char_count += f.chars().count();
                }
            }
            let mut buf: Vec<char> = vec!['\0'; char_count];
            let sizes: Vec<usize> = slots.iter().map(|&s| self.tokens[s].set.as_ref().unwrap().len()).collect();
            let mut counter = start;
            while counter < space {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                let mut c = counter;
                for i in (0..slots.len()).rev() {
                    let set = self.tokens[slots[i]].set.as_ref().unwrap();
                    buf[char_pos[i]] = set[(c % sizes[i] as u64) as usize];
                    c /= sizes[i] as u64;
                }
                // render fixed tokens whole around the charset slots
                let mut out: Vec<char> = Vec::with_capacity(char_count);
                let mut slot_idx = 0;
                for t in 0..len {
                    let tok = &self.tokens[t];
                    if let Some(f) = &tok.fixed {
                        out.extend(f.chars());
                    } else {
                        out.push(buf[char_pos[slot_idx]]);
                        slot_idx += 1;
                    }
                }
                pos.counter = counter;
                emit(Candidate { pw: out.into_iter().collect(), tag: String::new() }, pos);
                counter += 1;
            }
            pos.counter = 0;
        }
    }
}

// ------------------------------------------------------------------
pub struct CombinatorSource {
    file_a: String,
    file_b: String,
    b_lines: Option<Vec<String>>,
    count_total: i64,
}

impl CombinatorSource {
    pub fn new(file_a: String, file_b: String) -> Self {
        CombinatorSource { file_a, file_b, b_lines: None, count_total: -1 }
    }

    // B is fully loaded: every line under every planned encoding, deduped
    // globally (the same encoding sweep the dictionary source uses).
    fn load_b(&mut self) -> &Vec<String> {
        if self.b_lines.is_none() {
            let mut lines = Vec::new();
            let mut seen = HashSet::new();
            let plan = encoding::plan_file(&self.file_b);
            if let Ok(mut f) = File::open(&self.file_b) {
                let mut data = Vec::new();
                let _ = f.read_to_end(&mut data);
                let body = &data[plan.bom_skip as usize..];
                if plan.encs.len() == 1 && plan.encs[0].is_utf16() {
                    let body = encoding::strip_utf16_bom(body);
                    if let Some(text) = encoding::decode(plan.encs[0], body) {
                        for line in text.lines() {
                            let line = line.strip_suffix('\r').unwrap_or(line);
                            if let Some(t) = sanitize(line) {
                                if seen.insert(t.to_string()) {
                                    lines.push(t.to_string());
                                }
                            }
                        }
                    }
                } else {
                    for raw in body.split(|&b| b == 0x0A) {
                        let raw = if raw.last() == Some(&0x0D) { &raw[..raw.len() - 1] } else { raw };
                        for &enc in &plan.encs {
                            if let Some(s) = encoding::decode(enc, raw) {
                                if let Some(t) = sanitize(&s) {
                                    if seen.insert(t.to_string()) {
                                        lines.push(t.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            self.b_lines = Some(lines);
        }
        self.b_lines.as_ref().unwrap()
    }
}

impl CandidateSource for CombinatorSource {
    fn total(&mut self) -> Option<u64> {
        if self.count_total < 0 {
            let a = count_lines(&self.file_a);
            let b = self.load_b().len() as u64;
            self.count_total = if a > 0 && b > 0 && a > u64::MAX / b { u64::MAX as i64 } else { (a * b) as i64 };
        }
        Some(self.count_total as u64)
    }
    fn describe(&self) -> String {
        let an = Path::new(&self.file_a).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let bn = Path::new(&self.file_b).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        format!("{} × {}", an, bn)
    }
    fn position_text(&self, pos: &SourcePosition) -> String {
        format!("A行 {} B行 {}", pos.idx_a, pos.idx_b)
    }

    fn enumerate_with_pos(
        &mut self,
        pos: &mut SourcePosition,
        cancel: &Arc<AtomicBool>,
        emit: &mut dyn FnMut(Candidate, &SourcePosition),
    ) {
        let b = self.load_b().clone();
        let plan = encoding::plan_file(&self.file_a);
        let saved_a = pos.idx_a;
        let saved_b = pos.idx_b;
        let mut b_resume_pending = true;

        let mut data = Vec::new();
        if let Ok(mut f) = File::open(&self.file_a) {
            let _ = f.read_to_end(&mut data);
        }
        let utf16a = plan.encs.len() == 1 && plan.encs[0].is_utf16();
        if utf16a {
            let body = encoding::strip_utf16_bom(&data[plan.bom_skip as usize..]);
            if let Some(text) = encoding::decode(plan.encs[0], body) {
                let mut idx_a = 0i64;
                for line in text.lines() {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    if idx_a < saved_a {
                        idx_a += 1;
                        continue;
                    }
                    pos.idx_a = idx_a;
                    let line = line.strip_suffix('\r').unwrap_or(line);
                    idx_a += 1;
                    let ta = match sanitize(line) {
                        Some(t) => t.to_string(),
                        None => continue,
                    };
                    let start_b = if b_resume_pending && pos.idx_a == saved_a { saved_b } else { 0 };
                    if pos.idx_a == saved_a {
                        b_resume_pending = false;
                    }
                    for ib in start_b..b.len() as i64 {
                        if cancel.load(Ordering::Relaxed) {
                            return;
                        }
                        pos.idx_b = ib;
                        emit(Candidate { pw: format!("{}{}", ta, b[ib as usize]), tag: String::new() }, pos);
                    }
                    pos.idx_b = 0;
                }
            }
        } else {
            let body = &data[plan.bom_skip as usize..];
            let mut idx_a = -1i64;
            for raw in body.split(|&b| b == 0x0A) {
                idx_a += 1;
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                if idx_a < saved_a {
                    continue;
                }
                let raw = if raw.last() == Some(&0x0D) { &raw[..raw.len() - 1] } else { raw };
                if raw.is_empty() && idx_a as usize > 0 && body.last() == Some(&0x0A) {
                    // trailing empty segment after final newline
                }
                pos.idx_a = idx_a;
                let mut variants: HashSet<String> = HashSet::new();
                for &enc in &plan.encs {
                    if let Some(s) = encoding::decode(enc, raw) {
                        if let Some(t) = sanitize(&s) {
                            let ta = t.to_string();
                            if variants.contains(&ta) {
                                continue;
                            }
                            variants.insert(ta.clone());
                            let start_b = if b_resume_pending && idx_a == saved_a { saved_b } else { 0 };
                            if idx_a == saved_a {
                                b_resume_pending = false;
                            }
                            for ib in start_b..b.len() as i64 {
                                if cancel.load(Ordering::Relaxed) {
                                    return;
                                }
                                pos.idx_b = ib;
                                emit(Candidate { pw: format!("{}{}", ta, b[ib as usize]), tag: String::new() }, pos);
                            }
                            pos.idx_b = 0;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::plan_bytes;
    use std::io::Write;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("dcatt-{}-{}", tag, std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    }

    fn collect(src: &mut dyn CandidateSource) -> Vec<String> {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut pos = SourcePosition::default();
        let mut out = Vec::new();
        src.enumerate_with_pos(&mut pos, &cancel, &mut |c, _p| out.push(c.pw));
        out
    }

    // ---- mask (C# TestMaskSource) ------------------------------------

    fn mask_source(mask: &str, sets: &[&str; 4], min: usize, max: usize) -> MaskSource {
        let arr = [sets[0].to_string(), sets[1].to_string(), sets[2].to_string(), sets[3].to_string()];
        MaskSource::new(mask, &arr, min, max)
    }

    #[test]
    fn mask_digits() {
        let mut m = mask_source("?d?d", &["", "", "", ""], 2, 2);
        assert_eq!(m.total(), Some(100));
        let v = collect(&mut m);
        assert_eq!(v[0], "00");
        assert_eq!(v[1], "01");
        assert_eq!(v[99], "99");
    }

    #[test]
    fn mask_prefix() {
        // "ab?d" is 2 tokens (fixed "ab" + charset "d"); length counts tokens
        let v = collect(&mut mask_source("ab?d", &["", "", "", ""], 2, 2));
        assert_eq!(v.len(), 10);
        assert_eq!(v[0], "ab0");
        assert_eq!(v[9], "ab9");
    }

    #[test]
    fn mask_min_max_and_custom_and_overflow() {
        let mut m2 = mask_source("?d?d?d", &["", "", "", ""], 1, 2);
        assert_eq!(m2.total(), Some(110), "lengths 1+2 over ?d?d?d");
        let mut m3 = mask_source("ab?1", &["xy", "", "", ""], 2, 2);
        assert_eq!(m3.total(), Some(2), "custom set of 2");
        // ?a x 16 overflows u64 -> unknown total
        let mut big = mask_source(
            "?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a",
            &["", "", "", ""],
            1,
            16,
        );
        assert_eq!(big.total(), None, "total overflow -> None");
    }

    // ---- rules (C# TestRules) ----------------------------------------

    #[test]
    fn rules_years_dynamic() {
        let y_max = current_year() + 1;
        let mut out = Vec::new();
        Rules::apply("years", "w", &mut out);
        assert_eq!(out.len() as i32, y_max - 1980 + 1, "years dynamic count");
        assert!(out.contains(&format!("w{}", y_max)), "years includes current+1");
    }

    #[test]
    fn rules_digits() {
        let mut out = Vec::new();
        Rules::apply("digits", "pw", &mut out);
        assert!(out.contains(&"pw0".to_string()));
        assert!(out.contains(&"pw99".to_string()));
        assert_eq!(out.len(), 110);
    }

    #[test]
    fn rules_empty_word_no_output() {
        for p in Rules::PRESET_NAMES {
            let mut out = Vec::new();
            Rules::apply(p, "", &mut out);
            assert!(out.is_empty(), "empty word no output for {}", p);
        }
    }

    #[test]
    fn rules_leet_rev_cap() {
        let mut out = Vec::new();
        Rules::apply("leet", "password", &mut out);
        assert_eq!(out, vec!["p@55w0rd".to_string()]);
        out.clear();
        Rules::apply("rev", "abc", &mut out);
        assert_eq!(out, vec!["cba".to_string()]);
        out.clear();
        Rules::apply("cap", "abc", &mut out);
        assert_eq!(out, vec!["Abc".to_string()]);
    }

    // ---- dictionary source (C# TestDictionarySource) ------------------

    #[test]
    fn dict_bom_file() {
        let dir = temp_dir("bom");
        let bom = dir.join("bom.txt");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice("alpha\r\nbeta\n".as_bytes());
        std::fs::write(&bom, &bytes).unwrap();
        let mut src = DictionarySource::new(vec![bom.display().to_string()], vec![], false);
        let got = collect(&mut src);
        assert_eq!(got.len(), 2, "bom file line count");
        assert_eq!(got[0], "alpha", "bom stripped from first line");
        assert_eq!(got[1], "beta");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dict_gbk_chinese() {
        let dir = temp_dir("gbk");
        let gbk = dir.join("gbk.txt");
        let (b, _, _) = encoding_rs::GBK.encode("密码test\n");
        std::fs::write(&gbk, &*b).unwrap();
        let mut src = DictionarySource::new(vec![gbk.display().to_string()], vec![], false);
        let got = collect(&mut src);
        assert_eq!(got, vec!["密码test".to_string()], "gbk decode");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dict_chained_mutations() {
        let dir = temp_dir("chain");
        let plain = dir.join("p.txt");
        std::fs::write(&plain, "foo\n").unwrap();
        let mut src =
            DictionarySource::new(vec![plain.display().to_string()], vec!["years".into(), "digits".into()], false);
        let got = collect(&mut src);
        assert!(got.contains(&"foo".to_string()), "base word present");
        assert!(got.contains(&"foo1999".to_string()), "year suffix");
        assert!(got.contains(&"foo19990".to_string()), "chained year+digit");
        assert_eq!(got.iter().position(|w| w == "foo"), Some(0), "no cross dup: base first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dict_dedupe_collapses_repeated_file() {
        let dir = temp_dir("dedupe");
        let plain = dir.join("p.txt");
        std::fs::write(&plain, "foo\nbar\n").unwrap();
        let mut single = DictionarySource::new(vec![plain.display().to_string()], vec![], false);
        let mut dupe =
            DictionarySource::new(vec![plain.display().to_string(), plain.display().to_string()], vec![], true);
        assert_eq!(collect(&mut dupe).len(), collect(&mut single).len(), "dedupe collapses repeated file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn combinator_pair_and_total() {
        let dir = temp_dir("comb");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        let mut ab = vec![0xEF_u8, 0xBB, 0xBF];
        ab.extend_from_slice(b"x\n");
        std::fs::write(&a, &ab).unwrap();
        let mut bb = vec![0xEF_u8, 0xBB, 0xBF];
        bb.extend_from_slice(b"y\n");
        std::fs::write(&b, &bb).unwrap();
        let mut comb = CombinatorSource::new(a.display().to_string(), b.display().to_string());
        let got = collect(&mut comb);
        assert!(got.contains(&"xy".to_string()), "combinator pair");
        assert_eq!(comb.total(), Some(1), "combinator total");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- UTF-16 dictionary + rules (C# TestUtf16Rules) -----------------

    #[test]
    fn utf16_dict_runs_mutation_presets() {
        let dir = temp_dir("u16");
        let p = dir.join("u16.txt");
        let mut bytes = vec![0xFF_u8, 0xFE];
        for unit in "foo\r\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&p, &bytes).unwrap();
        let mut src = DictionarySource::new(vec![p.display().to_string()], vec!["digits".into()], false);
        let got = collect(&mut src);
        assert!(!got.is_empty() && got[0] == "foo", "utf16 base word first");
        assert!(got.contains(&"foo0".to_string()), "utf16 single-digit suffix");
        assert!(got.contains(&"foo99".to_string()), "utf16 double-digit suffix");
        assert_eq!(got.len(), 111, "utf16 fan-out 111");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- raw line splitter (C# TestRawLines) ---------------------------

    #[test]
    fn raw_lines_crlf_lf_no_trailing() {
        let dir = temp_dir("rl");
        let f = dir.join("lines.txt");
        std::fs::write(&f, b"ab\r\ncd\nef").unwrap();
        let mut file = File::open(&f).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut got: Vec<(String, i64)> = Vec::new();
        RawLines::new().enumerate(&mut file, 0, &cancel, &mut |seg, idx| {
            got.push((String::from_utf8_lossy(seg).into_owned(), idx));
        });
        assert_eq!(got.len(), 3, "crlf/lf/no-trailing");
        assert_eq!(got[0], ("ab".to_string(), 0));
        assert_eq!(got[1], ("cd".to_string(), 1));
        assert_eq!(got[2], ("ef".to_string(), 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn raw_lines_longer_than_initial_buffer() {
        let dir = temp_dir("big");
        let f = dir.join("big.txt");
        let payload = vec![b'x'; 3 << 20];
        {
            let mut fh = File::create(&f).unwrap();
            fh.write_all(&payload).unwrap();
        }
        let mut file = File::open(&f).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut got: Vec<usize> = Vec::new();
        RawLines::new().enumerate(&mut file, 0, &cancel, &mut |seg, _idx| got.push(seg.len()));
        assert_eq!(got.len(), 1, "one line");
        assert_eq!(got[0], payload.len(), "line longer than 1MB buffer survives");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- encoding plan (C# TestEncodingPlan) ---------------------------

    #[test]
    fn encoding_plan_utf8_bom() {
        let p = plan_bytes(&[0xEF, 0xBB, 0xBF, 0x61], 4);
        assert_eq!(p.note, "UTF-8 (BOM)");
        assert_eq!(p.bom_skip, 3);
    }

    #[test]
    fn encoding_plan_utf16le_bom() {
        let p = plan_bytes(&[0xFF, 0xFE, 0x61, 0x00], 4);
        assert_eq!(p.note, "UTF-16LE (BOM)");
        assert_eq!(p.bom_skip, 0);
    }

    #[test]
    fn encoding_plan_gbk_only() {
        let (b, _, _) = encoding_rs::GBK.encode("密码");
        let p = plan_bytes(&b, b.len() as u64);
        assert_eq!(p.note, "ANSI(GBK)");
    }

    #[test]
    fn encoding_plan_ascii_dual_sweep() {
        let p = plan_bytes(b"abc", 3);
        assert_eq!(p.note, "UTF-8 + ANSI(GBK)");
    }
}
