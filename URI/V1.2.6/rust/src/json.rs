//! Minimal JSON reader/writer — just enough for the conformance vector files.
//!
//! Why in-crate: the vectors must replay without pulling `serde_json` into the
//! default build (zero-dependency identity). This parser covers standard JSON
//! (objects, arrays, strings with escapes, numbers, bools, null) and —
//! importantly — keeps numbers as their RAW TEXT: the frame vectors carry
//! `timestamp_ns` values around 1.76e18, which a `f64` round-trip would
//! silently corrupt (53-bit mantissa). Parsing integers as `u128` keeps the
//! replay bit-exact.

use std::fmt;

/// A parsed JSON value. Numbers keep their original text.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    // ---- accessors ------------------------------------------------------

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// Exact integer read from the raw number text (no float round-trip).
    pub fn as_u128(&self) -> Option<u128> {
        match self {
            Json::Num(s) => s.parse::<u128>().ok(),
            _ => None,
        }
    }

    /// Canonical JSON: UTF-8, sorted keys, `,`/`:` separators, no whitespace.
    /// Used for the envelope signing input (SPEC §5.2).
    pub fn canonical(&self) -> String {
        match self {
            Json::Null => "null".to_string(),
            Json::Bool(b) => b.to_string(),
            Json::Num(s) => s.clone(),
            Json::Str(s) => json_quote(s),
            Json::Arr(a) => {
                let items: Vec<String> = a.iter().map(|v| v.canonical()).collect();
                format!("[{}]", items.join(","))
            }
            Json::Obj(pairs) => {
                let mut keys: Vec<&(String, Json)> = pairs.iter().collect();
                keys.sort_by(|a, b| a.0.cmp(&b.0));
                let items: Vec<String> = keys
                    .iter()
                    .map(|(k, v)| format!("{}:{}", json_quote(k), v.canonical()))
                    .collect();
                format!("{{{}}}", items.join(","))
            }
        }
    }
}

impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

pub fn parse(src: &str) -> Result<Json, String> {
    let mut p = Parser { src: src.as_bytes(), pos: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.src.len() {
        return Err(format!("trailing data at byte {}", p.pos));
    }
    Ok(v)
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", b as char, self.pos))
        }
    }

    fn literal(&mut self, word: &str, val: Json) -> Result<Json, String> {
        if self.src[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(val)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("unexpected byte at byte {}", self.pos)),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let val = self.value()?;
            pairs.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(pairs));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or("unterminated escape")?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&cp) {
                                // high surrogate — must pair
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                    self.expect(b'u')?;
                                    let lo = self.hex4()?;
                                    let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    char::from_u32(c).ok_or("invalid surrogate pair")?
                                } else {
                                    return Err("lone high surrogate".into());
                                }
                            } else {
                                char::from_u32(cp).ok_or("invalid \\u escape")?
                            };
                            out.push(ch);
                        }
                        _ => return Err(format!("bad escape at byte {}", self.pos)),
                    }
                }
                _ => {
                    // Re-decode UTF-8 sequences from the source.
                    let start = self.pos - 1;
                    let mut end = self.pos;
                    while end < self.src.len() && self.src[end] != b'"' && self.src[end] != b'\\' {
                        end += 1;
                    }
                    let chunk = std::str::from_utf8(&self.src[start..end])
                        .map_err(|_| "invalid UTF-8 in string")?;
                    out.push_str(chunk);
                    self.pos = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.src.len() {
            return Err("truncated \\u escape".into());
        }
        let s = std::str::from_utf8(&self.src[self.pos..self.pos + 4])
            .map_err(|_| "bad \\u escape")?;
        let cp = u32::from_str_radix(s, 16).map_err(|_| "bad \\u escape")?;
        self.pos += 4;
        Ok(cp)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-' => self.pos += 1,
                _ => break,
            }
        }
        if start == self.pos {
            return Err("empty number".into());
        }
        let text = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| "bad number")?
            .to_string();
        // Reject nothing here — the vector file uses plain integers; as_u128
        // simply returns None for floats, and the replay never reads floats.
        Ok(Json::Num(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_preserves_big_integers() {
        let doc = parse(r#"{"ts": 1760000000000000000, "ok": true, "list": [1, 2]}"#).unwrap();
        assert_eq!(doc.get("ts").unwrap().as_u128(), Some(1_760_000_000_000_000_000));
        assert_eq!(doc.get("ok").unwrap().as_bool(), Some(true));
        assert_eq!(doc.get("list").unwrap().as_arr().unwrap().len(), 2);
    }

    #[test]
    fn canonical_sorts_keys() {
        let doc = parse(r#"{"b":1,"a":"x","payload":{"d":2,"c":3}}"#).unwrap();
        assert_eq!(doc.canonical(), r#"{"a":"x","b":1,"payload":{"c":3,"d":2}}"#);
    }

    #[test]
    fn escapes_decode() {
        let doc = parse(r#"{"s":"a\"b\\c\nd"}"#).unwrap();
        assert_eq!(doc.get("s").unwrap().as_str(), Some("a\"b\\c\nd"));
    }
}
