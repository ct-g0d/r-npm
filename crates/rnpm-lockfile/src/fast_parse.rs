use crate::model::{LockfilePackage, LockfileV3, PackageBin, PackageEngines};
use rnpm_core::manifest::BundledDependencies;
use rnpm_core::PlatformList;
use std::collections::BTreeMap;

struct FastLockfileScanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> FastLockfileScanner<'a> {
    #[inline]
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b' ' || matches!(b, b'\n' | b'\r' | b'\t') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    #[inline]
    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.bytes.get(self.pos).copied()
    }

    #[inline]
    fn expect_byte(&mut self, expected: u8) -> Option<()> {
        self.skip_ws();
        if *self.bytes.get(self.pos)? == expected {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    #[inline]
    fn read_plain_str(&mut self) -> Option<&'a str> {
        self.skip_ws();
        if *self.bytes.get(self.pos)? != b'"' {
            return None;
        }
        self.pos += 1;
        let start = self.pos;
        let rest = &self.bytes[start..];
        let idx = rest.iter().position(|&b| b == b'"' || b == b'\\' || b < 0x20)?;
        if rest[idx] != b'"' {
            return None;
        }
        self.pos = start + idx + 1;
        // SAFETY: `self.bytes` originates from a valid `&str`, and both boundaries are ASCII `"`.
        Some(unsafe { std::str::from_utf8_unchecked(&self.bytes[start..start + idx]) })
    }

    #[inline]
    fn read_bool(&mut self) -> Option<bool> {
        self.skip_ws();
        let rest = &self.bytes[self.pos..];
        if rest.starts_with(b"true") {
            self.pos += 4;
            Some(true)
        } else if rest.starts_with(b"false") {
            self.pos += 5;
            Some(false)
        } else {
            None
        }
    }

    #[inline]
    fn read_null(&mut self) -> Option<()> {
        self.skip_ws();
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Some(())
        } else {
            None
        }
    }

    #[inline]
    fn read_u32_simple(&mut self) -> Option<u32> {
        self.skip_ws();
        let start = self.pos;
        let first = *self.bytes.get(start)?;
        if !first.is_ascii_digit() {
            return None;
        }
        if first == b'0' {
            self.pos += 1;
            if self
                .bytes
                .get(self.pos)
                .is_some_and(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E'))
            {
                return None;
            }
            return Some(0);
        }
        let mut val: u64 = 0;
        while let Some(&c) = self.bytes.get(self.pos) {
            if c.is_ascii_digit() {
                val = val.checked_mul(10)?.checked_add((c - b'0') as u64)?;
                self.pos += 1;
            } else if matches!(c, b'.' | b'e' | b'E') {
                return None;
            } else {
                break;
            }
        }
        u32::try_from(val).ok()
    }

    #[inline]
    fn read_string_vec(&mut self) -> Option<Vec<String>> {
        self.expect_byte(b'[')?;
        let mut out = Vec::new();
        if self.peek()? == b']' {
            self.pos += 1;
            return Some(out);
        }
        loop {
            out.push(self.read_plain_str()?.to_owned());
            match self.peek()? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Some(out);
                }
                _ => return None,
            }
        }
    }

    #[inline]
    fn read_string_btree_with_raw<const CAPTURE_RAW: bool>(
        &mut self,
    ) -> Option<(BTreeMap<String, String>, Option<serde_json::Value>)> {
        self.expect_byte(b'{')?;
        let mut pkg_map = BTreeMap::new();
        let mut raw_map = if CAPTURE_RAW {
            Some(serde_json::Map::with_capacity(4))
        } else {
            None
        };
        if self.peek()? == b'}' {
            self.pos += 1;
            return Some((pkg_map, raw_map.map(serde_json::Value::Object)));
        }
        loop {
            let k = self.read_plain_str()?;
            self.expect_byte(b':')?;
            let v = self.read_plain_str()?;
            if let Some(ref mut rm) = raw_map {
                rm.insert(k.to_owned(), serde_json::Value::String(v.to_owned()));
            }
            pkg_map.insert(k.to_owned(), v.to_owned());
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return Some((pkg_map, raw_map.map(serde_json::Value::Object)));
                }
                _ => return None,
            }
        }
    }

    fn read_serde_value(&mut self, depth: u8) -> Option<serde_json::Value> {
        if depth > 24 {
            return None;
        }
        let b = self.peek()?;
        match b {
            b'"' => self
                .read_plain_str()
                .map(|s| serde_json::Value::String(s.to_owned())),
            b't' | b'f' => self.read_bool().map(serde_json::Value::Bool),
            b'n' => {
                self.read_null()?;
                Some(serde_json::Value::Null)
            }
            b'[' => {
                self.pos += 1;
                let mut arr = Vec::new();
                if self.peek()? == b']' {
                    self.pos += 1;
                    return Some(serde_json::Value::Array(arr));
                }
                loop {
                    arr.push(self.read_serde_value(depth + 1)?);
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some(serde_json::Value::Array(arr));
                        }
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                let mut map = serde_json::Map::with_capacity(4);
                if self.peek()? == b'}' {
                    self.pos += 1;
                    return Some(serde_json::Value::Object(map));
                }
                loop {
                    let k = self.read_plain_str()?;
                    self.expect_byte(b':')?;
                    let v = self.read_serde_value(depth + 1)?;
                    map.insert(k.to_owned(), v);
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some(serde_json::Value::Object(map));
                        }
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                if b == b'-' {
                    self.pos += 1;
                }
                let first = *self.bytes.get(self.pos)?;
                if !first.is_ascii_digit() {
                    return None;
                }
                if first == b'0' {
                    if b == b'-' {
                        return None;
                    }
                    self.pos += 1;
                    if self.bytes.get(self.pos).is_some_and(|c| c.is_ascii_digit()) {
                        return None;
                    }
                } else {
                    while self.bytes.get(self.pos).is_some_and(|c| c.is_ascii_digit()) {
                        self.pos += 1;
                    }
                }
                if self
                    .bytes
                    .get(self.pos)
                    .is_some_and(|&c| matches!(c, b'.' | b'e' | b'E'))
                {
                    return None;
                }
                let s = std::str::from_utf8(&self.bytes[start..self.pos]).ok()?;
                if b == b'-' {
                    let v: i64 = s.parse().ok()?;
                    Some(serde_json::Value::Number(serde_json::Number::from(v)))
                } else {
                    let v: u64 = s.parse().ok()?;
                    Some(serde_json::Value::Number(serde_json::Number::from(v)))
                }
            }
            _ => None,
        }
    }

    fn skip_plain_value(&mut self, depth: u8) -> Option<()> {
        if depth > 24 {
            return None;
        }
        match self.peek()? {
            b'"' => {
                self.read_plain_str()?;
                Some(())
            }
            b't' | b'f' => {
                self.read_bool()?;
                Some(())
            }
            b'n' => self.read_null(),
            b'[' => {
                self.pos += 1;
                if self.peek()? == b']' {
                    self.pos += 1;
                    return Some(());
                }
                loop {
                    self.skip_plain_value(depth + 1)?;
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                if self.peek()? == b'}' {
                    self.pos += 1;
                    return Some(());
                }
                loop {
                    self.read_plain_str()?;
                    self.expect_byte(b':')?;
                    self.skip_plain_value(depth + 1)?;
                    match self.peek()? {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let b = self.bytes[self.pos];
                if b == b'-' {
                    self.pos += 1;
                }
                let first = *self.bytes.get(self.pos)?;
                if !first.is_ascii_digit() {
                    return None;
                }
                if first == b'0' {
                    if b == b'-' {
                        return None;
                    }
                    self.pos += 1;
                    if self.bytes.get(self.pos).is_some_and(|c| c.is_ascii_digit()) {
                        return None;
                    }
                } else {
                    while self.bytes.get(self.pos).is_some_and(|c| c.is_ascii_digit()) {
                        self.pos += 1;
                    }
                }
                if self
                    .bytes
                    .get(self.pos)
                    .is_some_and(|&c| matches!(c, b'.' | b'e' | b'E'))
                {
                    return None;
                }
                Some(())
            }
            _ => None,
        }
    }

    fn read_package<const CAPTURE_RAW: bool>(&mut self) -> Option<LockfilePackage> {
        self.expect_byte(b'{')?;
        let mut pkg = LockfilePackage::default();
        let mut raw_map = if CAPTURE_RAW {
            Some(serde_json::Map::with_capacity(12))
        } else {
            None
        };
        let mut seen: u32 = 0;

        if self.peek()? == b'}' {
            self.pos += 1;
            if let Some(rm) = raw_map {
                pkg.raw_value = Some(serde_json::Value::Object(rm));
            }
            return Some(pkg);
        }

        loop {
            let ks = self.read_plain_str()?;
            self.expect_byte(b':')?;

            macro_rules! fast_str_opt {
                ($field:ident, $bit:expr) => {{
                    if (seen & (1 << $bit)) != 0 {
                        return None;
                    }
                    seen |= 1 << $bit;
                    let v = match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            None
                        }
                        _ => Some(self.read_plain_str()?.to_owned()),
                    };
                    if let Some(ref mut rm) = raw_map {
                        let rv = match &v {
                            Some(s) => serde_json::Value::String(s.clone()),
                            None => serde_json::Value::Null,
                        };
                        rm.insert(ks.to_owned(), rv);
                    }
                    pkg.$field = v;
                }};
            }

            macro_rules! fast_bool_opt {
                ($field:ident, $bit:expr) => {{
                    if (seen & (1 << $bit)) != 0 {
                        return None;
                    }
                    seen |= 1 << $bit;
                    let v = match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            None
                        }
                        _ => Some(self.read_bool()?),
                    };
                    if let Some(ref mut rm) = raw_map {
                        let rv = match v {
                            Some(b) => serde_json::Value::Bool(b),
                            None => serde_json::Value::Null,
                        };
                        rm.insert(ks.to_owned(), rv);
                    }
                    pkg.$field = v;
                }};
            }

            macro_rules! fast_map_opt {
                ($field:ident, $bit:expr) => {{
                    if (seen & (1 << $bit)) != 0 {
                        return None;
                    }
                    seen |= 1 << $bit;
                    match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Null);
                            }
                            pkg.$field = None;
                        }
                        _ => {
                            let (m, rv) = self.read_string_btree_with_raw::<CAPTURE_RAW>()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), rv?);
                            }
                            pkg.$field = Some(m);
                        }
                    }
                }};
            }

            macro_rules! fast_platform {
                ($field:ident, $bit:expr) => {{
                    if (seen & (1 << $bit)) != 0 {
                        return None;
                    }
                    seen |= 1 << $bit;
                    match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Null);
                            }
                            pkg.$field = None;
                        }
                        b'"' => {
                            let s = self.read_plain_str()?.to_owned();
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::String(s.clone()));
                            }
                            pkg.$field = Some(PlatformList::from(s));
                        }
                        b'[' => {
                            let list = self.read_string_vec()?;
                            if let Some(ref mut rm) = raw_map {
                                let arr = list
                                    .iter()
                                    .map(|s| serde_json::Value::String(s.clone()))
                                    .collect();
                                rm.insert(ks.to_owned(), serde_json::Value::Array(arr));
                            }
                            pkg.$field = Some(PlatformList::from(list));
                        }
                        _ => return None,
                    }
                }};
            }

            match ks {
                "name" => fast_str_opt!(name, 0),
                "version" => fast_str_opt!(version, 1),
                "resolved" => fast_str_opt!(resolved, 2),
                "integrity" | "_integrity" => fast_str_opt!(integrity, 3),
                "link" => fast_bool_opt!(link, 4),
                "dev" => fast_bool_opt!(dev, 5),
                "optional" => fast_bool_opt!(optional, 6),
                "devOptional" => fast_bool_opt!(dev_optional, 7),
                "peer" => fast_bool_opt!(peer, 8),
                "peerOptional" => fast_bool_opt!(peer_optional, 9),
                "inBundle" | "bundled" => fast_bool_opt!(in_bundle, 10),
                "hasInstallScript" => fast_bool_opt!(has_install_script, 11),
                "hasShrinkwrap" | "_hasShrinkwrap" => fast_bool_opt!(has_shrinkwrap, 12),
                "extraneous" => fast_bool_opt!(extraneous, 13),
                "license" => {
                    if (seen & (1 << 14)) != 0 {
                        return None;
                    }
                    seen |= 1 << 14;
                    match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Null);
                            }
                            pkg.license = None;
                        }
                        b'"' => {
                            let s = self.read_plain_str()?.to_owned();
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::String(s.clone()));
                            }
                            pkg.license = if s.is_empty() { None } else { Some(s) };
                        }
                        _ => return None,
                    }
                }
                "os" => fast_platform!(os, 15),
                "cpu" => fast_platform!(cpu, 16),
                "libc" => fast_platform!(libc, 17),
                "dependencies" => fast_map_opt!(dependencies, 18),
                "bin" => {
                    if (seen & (1 << 19)) != 0 {
                        return None;
                    }
                    seen |= 1 << 19;
                    match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Null);
                            }
                            pkg.bin = None;
                        }
                        b'"' => {
                            let s = self.read_plain_str()?.to_owned();
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::String(s.clone()));
                            }
                            pkg.bin = Some(PackageBin::Single(s));
                        }
                        b'{' => {
                            let (m, rv) = self.read_string_btree_with_raw::<CAPTURE_RAW>()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), rv?);
                            }
                            pkg.bin = Some(PackageBin::Map(m));
                        }
                        _ => return None,
                    }
                }
                "devDependencies" => fast_map_opt!(dev_dependencies, 20),
                "engines" => {
                    if (seen & (1 << 21)) != 0 {
                        return None;
                    }
                    seen |= 1 << 21;
                    match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Null);
                            }
                            pkg.engines = None;
                        }
                        b'"' => {
                            let s = self.read_plain_str()?.to_owned();
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::String(s.clone()));
                            }
                            pkg.engines = Some(PackageEngines::String(s));
                        }
                        b'{' => {
                            let (m, rv) = self.read_string_btree_with_raw::<CAPTURE_RAW>()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), rv?);
                            }
                            pkg.engines = Some(PackageEngines::Map(m));
                        }
                        _ => return None,
                    }
                }
                "optionalDependencies" => fast_map_opt!(optional_dependencies, 22),
                "peerDependencies" => fast_map_opt!(peer_dependencies, 23),
                "peerDependenciesMeta" => {
                    if (seen & (1 << 24)) != 0 {
                        return None;
                    }
                    seen |= 1 << 24;
                    match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Null);
                            }
                            pkg.peer_dependencies_meta = None;
                        }
                        b'{' => {
                            let val = self.read_serde_value(0)?;
                            let parsed = match &val {
                                serde_json::Value::Object(m) => {
                                    m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                                }
                                _ => return None,
                            };
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), val);
                            }
                            pkg.peer_dependencies_meta = Some(parsed);
                        }
                        _ => return None,
                    }
                }
                "bundleDependencies" | "bundledDependencies" => {
                    if (seen & (1 << 25)) != 0 {
                        return None;
                    }
                    seen |= 1 << 25;
                    match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Null);
                            }
                            pkg.bundle_dependencies = None;
                        }
                        b't' | b'f' => {
                            let b = self.read_bool()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Bool(b));
                            }
                            pkg.bundle_dependencies = Some(BundledDependencies::Boolean(b));
                        }
                        b'[' => {
                            let list = self.read_string_vec()?;
                            if let Some(ref mut rm) = raw_map {
                                let arr = list
                                    .iter()
                                    .map(|s| serde_json::Value::String(s.clone()))
                                    .collect();
                                rm.insert(ks.to_owned(), serde_json::Value::Array(arr));
                            }
                            pkg.bundle_dependencies = Some(BundledDependencies::List(list));
                        }
                        _ => return None,
                    }
                }
                "workspaces" => {
                    if (seen & (1 << 26)) != 0 {
                        return None;
                    }
                    seen |= 1 << 26;
                    match self.peek()? {
                        b'n' => {
                            self.read_null()?;
                            if let Some(ref mut rm) = raw_map {
                                rm.insert(ks.to_owned(), serde_json::Value::Null);
                            }
                            pkg.workspaces = None;
                        }
                        b'[' => {
                            let list = self.read_string_vec()?;
                            if let Some(ref mut rm) = raw_map {
                                let arr = list
                                    .iter()
                                    .map(|s| serde_json::Value::String(s.clone()))
                                    .collect();
                                rm.insert(ks.to_owned(), serde_json::Value::Array(arr));
                            }
                            pkg.workspaces = Some(list);
                        }
                        _ => return None,
                    }
                }
                _ => {
                    let val = self.read_serde_value(0)?;
                    let is_dir = ks == "directories";
                    let is_falsy_deprecated = ks == "deprecated"
                        && (val == serde_json::Value::Bool(false) || val.is_null() || val == "");
                    if is_dir || is_falsy_deprecated {
                        if is_falsy_deprecated {
                            pkg.extra.remove("deprecated");
                        }
                        if let Some(ref mut rm) = raw_map {
                            rm.insert(ks.to_owned(), val);
                        }
                    } else {
                        if let Some(ref mut rm) = raw_map {
                            rm.insert(ks.to_owned(), val.clone());
                        }
                        pkg.extra.insert(ks.to_owned(), val);
                    }
                }
            }

            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    pkg.normalize_flags_keeping_raw();
                    if let Some(rm) = raw_map {
                        pkg.raw_value = Some(serde_json::Value::Object(rm));
                    }
                    return Some(pkg);
                }
                _ => return None,
            }
        }
    }
}

pub(crate) fn try_parse_lockfile_v3_fast(content: &str, capture_raw: bool) -> Option<LockfileV3> {
    let mut r = FastLockfileScanner {
        bytes: content.as_bytes(),
        pos: 0,
    };
    r.expect_byte(b'{')?;
    let mut name: Option<String> = None;
    let mut version: Option<Option<String>> = None;
    let mut lockfile_version: Option<u32> = None;
    let mut requires: Option<Option<bool>> = None;
    let mut packages: Option<BTreeMap<String, LockfilePackage>> = None;

    if r.peek()? == b'}' {
        r.pos += 1;
        r.skip_ws();
        if r.pos != r.bytes.len() {
            return None;
        }
        return Some(LockfileV3 {
            name: String::new(),
            version: None,
            lockfile_version: crate::migration::default_lockfile_version(),
            requires: None,
            packages: BTreeMap::new(),
        });
    }

    loop {
        let key = r.read_plain_str()?;
        r.expect_byte(b':')?;
        match key {
            "name" => {
                if name.is_some() {
                    return None;
                }
                name = Some(r.read_plain_str()?.to_owned());
            }
            "version" => {
                if version.is_some() {
                    return None;
                }
                version = Some(match r.peek()? {
                    b'n' => {
                        r.read_null()?;
                        None
                    }
                    _ => Some(r.read_plain_str()?.to_owned()),
                });
            }
            "lockfileVersion" => {
                if lockfile_version.is_some() {
                    return None;
                }
                lockfile_version = Some(r.read_u32_simple()?);
            }
            "requires" => {
                if requires.is_some() {
                    return None;
                }
                requires = Some(match r.peek()? {
                    b'n' => {
                        r.read_null()?;
                        None
                    }
                    _ => Some(r.read_bool()?),
                });
            }
            "packages" => {
                if packages.is_some() {
                    return None;
                }
                r.expect_byte(b'{')?;
                let mut pkgs = BTreeMap::new();
                if r.peek()? != b'}' {
                    if capture_raw {
                        loop {
                            let pkg_key = r.read_plain_str()?;
                            r.expect_byte(b':')?;
                            let pkg = r.read_package::<true>()?;
                            pkgs.insert(pkg_key.to_owned(), pkg);
                            match r.peek()? {
                                b',' => r.pos += 1,
                                b'}' => break,
                                _ => return None,
                            }
                        }
                    } else {
                        loop {
                            let pkg_key = r.read_plain_str()?;
                            r.expect_byte(b':')?;
                            let pkg = r.read_package::<false>()?;
                            pkgs.insert(pkg_key.to_owned(), pkg);
                            match r.peek()? {
                                b',' => r.pos += 1,
                                b'}' => break,
                                _ => return None,
                            }
                        }
                    }
                }
                r.pos += 1;
                packages = Some(pkgs);
            }
            _ => r.skip_plain_value(0)?,
        }

        match r.peek()? {
            b',' => r.pos += 1,
            b'}' => {
                r.pos += 1;
                r.skip_ws();
                if r.pos != r.bytes.len() {
                    return None;
                }
                return Some(LockfileV3 {
                    name: name.unwrap_or_default(),
                    version: version.unwrap_or(None),
                    lockfile_version: lockfile_version
                        .unwrap_or_else(crate::migration::default_lockfile_version),
                    requires: requires.unwrap_or(None),
                    packages: packages.unwrap_or_default(),
                });
            }
            _ => return None,
        }
    }
}
