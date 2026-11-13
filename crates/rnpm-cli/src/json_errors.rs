//! npm's EJSONPARSE wording: V8's `JSON.parse` messages, rewritten by
//! json-parse-even-better-errors.

/// Validate `text` like V8's JSON parser and return its error message, if any.
fn v8_json_error(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut p = Parser { s: &chars, i: 0 };
    let result = p.value().and_then(|_| {
        p.ws();
        if p.i < chars.len() {
            Err(p.at("Unexpected non-whitespace character after JSON"))
        } else {
            Ok(())
        }
    });
    result.err()
}

struct Parser<'a> {
    s: &'a [char],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], ' ' | '\t' | '\n' | '\r') {
            self.i += 1;
        }
    }

    fn at(&self, what: &str) -> String {
        let (mut line, mut col) = (1, 1);
        for c in &self.s[..self.i.min(self.s.len())] {
            if *c == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
        format!("{what} in JSON at position {} (line {line} column {col})", self.i)
    }

    fn unexpected(&self) -> String {
        if self.i >= self.s.len() {
            return "Unexpected end of JSON input".into();
        }
        let token = self.s[self.i];
        let len = self.s.len();
        let src = |a: usize, b: usize| self.s[a..b].iter().collect::<String>();
        const CONTEXT: usize = 10;
        let snippet = if len < CONTEXT * 2 + 1 {
            format!("\"{}\"", src(0, len))
        } else {
            let start = self.i.saturating_sub(CONTEXT);
            let end = (self.i + CONTEXT).min(len);
            match (self.i < CONTEXT, end >= len) {
                (true, _) => format!("\"{}\"...", src(0, end)),
                (false, true) => format!("...\"{}\"", src(start, len)),
                (false, false) => format!("...\"{}\"...", src(start, end)),
            }
        };
        format!("Unexpected token '{token}', {snippet} is not valid JSON")
    }

    fn value(&mut self) -> Result<(), String> {
        self.ws();
        match self.s.get(self.i) {
            Some('{') => self.object(),
            Some('[') => self.array(),
            Some('"') => self.string(),
            Some('-' | '0'..='9') => self.number(),
            Some('t') => self.literal("true"),
            Some('f') => self.literal("false"),
            Some('n') => self.literal("null"),
            _ => Err(self.unexpected()),
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), String> {
        for expected in word.chars() {
            if self.s.get(self.i) != Some(&expected) {
                return Err(self.unexpected());
            }
            self.i += 1;
        }
        Ok(())
    }

    fn string(&mut self) -> Result<(), String> {
        self.i += 1;
        loop {
            match self.s.get(self.i) {
                None => return Err(self.at("Unterminated string")),
                Some('"') => {
                    self.i += 1;
                    return Ok(());
                }
                Some('\\') => {
                    self.i += 1;
                    match self.s.get(self.i) {
                        Some('"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') => self.i += 1,
                        Some('u') => {
                            for _ in 0..4 {
                                self.i += 1;
                                if !self.s.get(self.i).is_some_and(|c| c.is_ascii_hexdigit()) {
                                    return Err(self.at("Bad Unicode escape"));
                                }
                            }
                            self.i += 1;
                        }
                        _ => return Err(self.at("Bad escaped character")),
                    }
                }
                Some(c) if (*c as u32) < 0x20 => {
                    return Err(self.at("Bad control character in string literal"))
                }
                Some(_) => self.i += 1,
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while self.s.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<(), String> {
        if self.s.get(self.i) == Some(&'-') {
            self.i += 1;
            if !self.s.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                return Err(self.at("No number after minus sign"));
            }
        }
        if self.s.get(self.i) == Some(&'0') {
            self.i += 1;
        } else {
            self.digits();
        }
        if self.s.get(self.i) == Some(&'.') {
            self.i += 1;
            if self.digits() == 0 {
                return Err(self.at("Unterminated fractional number"));
            }
        }
        if matches!(self.s.get(self.i), Some('e' | 'E')) {
            self.i += 1;
            if matches!(self.s.get(self.i), Some('+' | '-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(self.at("Exponent part is missing a number"));
            }
        }
        Ok(())
    }

    fn object(&mut self) -> Result<(), String> {
        self.i += 1;
        self.ws();
        if self.s.get(self.i) == Some(&'}') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.ws();
            match self.s.get(self.i) {
                Some('"') => self.string()?,
                None => return Err(self.unexpected()),
                Some(_) => return Err(self.at("Expected double-quoted property name")),
            }
            self.ws();
            match self.s.get(self.i) {
                Some(':') => self.i += 1,
                _ => return Err(self.at("Expected ':' after property name")),
            }
            self.value()?;
            self.ws();
            match self.s.get(self.i) {
                Some(',') => self.i += 1,
                Some('}') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(self.at("Expected ',' or '}' after property value")),
            }
        }
    }

    fn array(&mut self) -> Result<(), String> {
        self.i += 1;
        self.ws();
        if self.s.get(self.i) == Some(&']') {
            self.i += 1;
            return Ok(());
        }
        loop {
            self.value()?;
            self.ws();
            match self.s.get(self.i) {
                Some(',') => self.i += 1,
                Some(']') => {
                    self.i += 1;
                    return Ok(());
                }
                _ => return Err(self.at("Expected ',' or ']' after array element")),
            }
        }
    }
}

fn hexify(c: char) -> String {
    let h = format!("{:X}", c as u32);
    format!("0x{}{h}", if h.len() % 2 == 1 { "0" } else { "" })
}

/// `JSONParseError` message for invalid JSON text, or `None` when it parses.
pub fn json_parse_error_message(text: &str) -> Option<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut msg = v8_json_error(text)?;
    if text.is_empty() {
        return Some(format!("{msg} while parsing empty string"));
    }
    if let Some(rest) = msg.strip_prefix("Unexpected token '") {
        let token = rest.chars().next().unwrap_or(' ');
        let after = &rest[token.len_utf8()..];
        let after = after.strip_prefix('\'').unwrap_or(after);
        let token_json = serde_json::to_string(&token.to_string()).unwrap_or_default();
        msg = format!("Unexpected token {token_json} ({}){after}", hexify(token));
    }
    let chars: Vec<char> = text.chars().collect();
    let err_idx = msg
        .split(" position ")
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|d| d.parse::<usize>().ok())
        .or_else(|| msg.starts_with("Unexpected end of JSON").then(|| chars.len() - 1));
    const CONTEXT: usize = 20;
    let Some(err_idx) = err_idx else {
        let head: String = chars.iter().take(CONTEXT * 2).collect();
        return Some(format!("{msg} while parsing '{head}'"));
    };
    let start = err_idx.saturating_sub(CONTEXT);
    let start = if err_idx <= CONTEXT { 0 } else { start };
    let end = if err_idx + CONTEXT >= chars.len() { chars.len() } else { err_idx + CONTEXT };
    let slice = format!(
        "{}{}{}",
        if start > 0 { "..." } else { "" },
        chars[start..end].iter().collect::<String>(),
        if end == chars.len() { "" } else { "..." }
    );
    let near = if slice == text { "" } else { "near " };
    Some(format!(
        "{msg} while parsing {near}{}",
        serde_json::to_string(&slice).unwrap_or_default()
    ))
}

/// npm's EJSONPARSE block for an invalid package.json.
pub fn package_json_error(text: &str) -> Option<String> {
    let message = json_parse_error_message(text)?;
    Some(format!(
        "npm error code EJSONPARSE\nnpm error JSON.parse Invalid package.json: JSONParseError: {message}\nnpm error JSON.parse Failed to parse JSON data.\nnpm error JSON.parse Note: package.json must be actual JSON, not just JavaScript."
    ))
}

#[cfg(test)]
mod tests {
    use super::json_parse_error_message as m;

    #[test]
    fn matches_npm_wording() {
        assert_eq!(
            m("{\"name\":").unwrap(),
            "Unexpected end of JSON input while parsing \"{\\\"name\\\":\""
        );
        assert_eq!(
            m("{\"name\":}").unwrap(),
            "Unexpected token \"}\" (0x7D), \"{\"name\":}\" is not valid JSON while parsing '{\"name\":}'"
        );
        assert_eq!(
            m("{\"name\":\"a\",}").unwrap(),
            "Expected double-quoted property name in JSON at position 12 (line 1 column 13) while parsing \"{\\\"name\\\":\\\"a\\\",}\""
        );
        assert_eq!(
            m("{\"name\":\"a\"").unwrap(),
            "Expected ',' or '}' after property value in JSON at position 11 (line 1 column 12) while parsing \"{\\\"name\\\":\\\"a\\\"\""
        );
        assert_eq!(m("").unwrap(), "Unexpected end of JSON input while parsing empty string");
        assert_eq!(
            m("{\"name\":\"a\",\"version\":\"1.0.0\",\"description\":\"a long description here\", oops}").unwrap(),
            "Expected double-quoted property name in JSON at position 71 (line 1 column 72) while parsing near \"... description here\\\", oops}\""
        );
        assert!(m("{\"a\":[1,2,{\"b\":null}]}").is_none());
    }
}
