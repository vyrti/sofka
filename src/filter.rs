//! Structured row-filter grammar.
//!
//! Plain text with no structured markers stays what it always was: one fuzzy
//! pattern over "namespace name", falling back to each rendered column cell
//! (so `/10.96` finds a Service by its CLUSTER-IP). Once any structured marker
//! appears, the input is split on whitespace and every term must match
//! (terms are AND-ed, optionally with `&&`; `||` and parentheses combine groups):
//!
//! - `text`                   fuzzy match (namespace + name + any column cell)
//! - `!text`                  inverse fuzzy match
//! - `-l app=api,env=prod`    Kubernetes label selector (sent server-side)
//! - `-f spec.nodeName=n1`    Kubernetes field selector (sent server-side)
//! - `status=CrashLoopBackOff` column equality (case-insensitive)
//! - `cpu>500m` `memory>1Gi` `restarts>=5` `age<2h` typed comparisons
//!
//! Comparison operators: `=` (or `==`), `!=`, `>`, `>=`, `<`, `<=`. The
//! value's type follows the key: `cpu` parses CPU quantities (millicores),
//! `mem`/`memory` memory quantities (bytes), `age` durations (`90s`, `2h`,
//! `1d2h`); any other key compares numerically when the value is a number
//! and as case-insensitive text otherwise. Parsing never fails hard — a
//! broken term is skipped and reported via [`Structured::error`] so the
//! table doesn't blank out mid-keystroke. Enter keeps malformed input open.
//! Quotes preserve spaces in values; parentheses preserve label-selector sets.

/// The parsed form of the filter input.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedFilter {
    /// The whole input is one fuzzy pattern (no structured markers) — the
    /// original `/text` behavior, kept byte-for-byte compatible.
    Fuzzy(String),
    Structured(Structured),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Structured {
    /// Locally-evaluated terms, AND-ed together.
    pub terms: Vec<Term>,
    /// Combined `-l` selectors, ready for the Kubernetes API.
    pub labels: Option<String>,
    /// Combined `-f` selectors, ready for the Kubernetes API.
    pub fields: Option<String>,
    /// First malformed term, for surfacing in the UI.
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    Fuzzy(String),
    NotFuzzy(String),
    Cmp(Cmp),
    All(Vec<Term>),
    Any(Vec<Term>),
    Not(Vec<Term>),
}

impl Term {
    pub fn metrics_sensitive(&self) -> bool {
        match self {
            Self::Cmp(Cmp {
                value: CmpValue::Cpu(_) | CmpValue::Mem(_),
                ..
            }) => true,
            Self::All(terms) | Self::Any(terms) | Self::Not(terms) => {
                terms.iter().any(Self::metrics_sensitive)
            }
            _ => false,
        }
    }

    pub fn time_sensitive(&self) -> bool {
        match self {
            Self::Cmp(Cmp {
                value: CmpValue::Duration(_),
                ..
            }) => true,
            Self::All(terms) | Self::Any(terms) | Self::Not(terms) => {
                terms.iter().any(Self::time_sensitive)
            }
            _ => false,
        }
    }

    fn fuzzy_needle(&self) -> Option<&str> {
        match self {
            Self::Fuzzy(text) => Some(text),
            Self::All(terms) | Self::Any(terms) => terms.iter().find_map(Self::fuzzy_needle),
            _ => None,
        }
    }
}

/// One `key<op>value` column comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct Cmp {
    /// Lowercased column key (`status`, `cpu`, `restarts`, …).
    pub key: String,
    pub op: Op,
    pub value: CmpValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Op {
    /// Apply the operator to an already-computed `actual.cmp(&wanted)`.
    pub fn eval(self, ord: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::*;
        match self {
            Op::Eq => ord == Equal,
            Op::Ne => ord != Equal,
            Op::Gt => ord == Greater,
            Op::Ge => ord != Less,
            Op::Lt => ord == Less,
            Op::Le => ord != Greater,
        }
    }
}

/// A comparison value, typed at parse time from the key it belongs to.
#[derive(Debug, Clone, PartialEq)]
pub enum CmpValue {
    /// Plain number (`restarts>=5`).
    Num(f64),
    /// CPU quantity in millicores (`cpu>500m`).
    Cpu(i64),
    /// Memory quantity in bytes (`memory>1Gi`).
    Mem(i64),
    /// Duration in seconds (`age<2h`).
    Duration(i64),
    /// Anything else: case-insensitive text comparison. Stored pre-folded to
    /// lowercase — the comparison runs per object per rebuild, so folding the
    /// needle once at parse time keeps it out of that loop.
    Str(String),
}

impl ParsedFilter {
    pub fn labels(&self) -> Option<&str> {
        match self {
            ParsedFilter::Fuzzy(_) => None,
            ParsedFilter::Structured(s) => s.labels.as_deref(),
        }
    }

    pub fn fields(&self) -> Option<&str> {
        match self {
            ParsedFilter::Fuzzy(_) => None,
            ParsedFilter::Structured(s) => s.fields.as_deref(),
        }
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            ParsedFilter::Fuzzy(_) => None,
            ParsedFilter::Structured(s) => s.error.as_deref(),
        }
    }

    /// The pattern NAME-cell highlighting should mark: the legacy fuzzy
    /// pattern, or the first positive fuzzy term of a structured filter.
    pub fn fuzzy_needle(&self) -> Option<&str> {
        match self {
            ParsedFilter::Fuzzy(pat) => (!pat.is_empty()).then_some(pat.as_str()),
            ParsedFilter::Structured(s) => s.terms.iter().find_map(Term::fuzzy_needle),
        }
    }
}

pub fn parse(input: &str) -> ParsedFilter {
    let trimmed = input.trim();
    if trimmed.is_empty() || !is_structured(trimmed) {
        return ParsedFilter::Fuzzy(trimmed.to_string());
    }

    ParsedFilter::Structured(match tokenize(trimmed) {
        Ok(tokens) => parse_tokens(&tokens, 0),
        Err(error) => Structured {
            error: Some(error),
            ..Structured::default()
        },
    })
}

fn parse_tokens(tokens: &[String], depth: usize) -> Structured {
    if depth > 32 {
        return Structured {
            error: Some("filter nesting exceeds 32 levels".into()),
            ..Structured::default()
        };
    }
    if tokens.iter().any(|t| t == "||") {
        let mut branches = Vec::new();
        for branch in tokens.split(|t| t == "||") {
            let parsed = parse_tokens(branch, depth + 1);
            let error = if branch.is_empty() {
                Some("expected terms on both sides of ||".into())
            } else if parsed.labels.is_some() || parsed.fields.is_some() {
                Some("place selectors outside OR groups: -l app=api (a || b)".into())
            } else {
                parsed.error
            };
            if let Some(error) = error {
                return Structured {
                    error: Some(error),
                    ..Structured::default()
                };
            }
            branches.push(Term::All(parsed.terms));
        }
        return Structured {
            terms: vec![Term::Any(branches)],
            ..Structured::default()
        };
    }
    let mut terms = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut error: Option<String> = None;
    let fail = |slot: &mut Option<String>, msg: String| {
        if slot.is_none() {
            *slot = Some(msg);
        }
    };

    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        i += 1;
        let group = tok
            .strip_prefix("!(")
            .map(|s| (s, true))
            .or_else(|| tok.strip_prefix('(').map(|s| (s, false)));
        if let Some((inner, inverse)) = group {
            let parsed = inner
                .strip_suffix(')')
                .ok_or("unclosed group".to_string())
                .and_then(tokenize)
                .map(|tokens| parse_tokens(&tokens, depth + 1));
            match parsed {
                Ok(s) if s.labels.is_some() || s.fields.is_some() => fail(
                    &mut error,
                    "selectors must be outside Boolean groups".into(),
                ),
                Ok(s) if s.error.is_some() => fail(&mut error, s.error.unwrap()),
                Ok(s) if s.terms.is_empty() => fail(&mut error, "empty Boolean group".into()),
                Ok(s) => terms.push(if inverse {
                    Term::Not(s.terms)
                } else {
                    Term::All(s.terms)
                }),
                Err(e) => fail(&mut error, e),
            }
            continue;
        }
        if tok == "&&" {
            if i == 1 || i == tokens.len() || tokens[i] == "&&" {
                fail(&mut error, "expected terms on both sides of &&".into());
            }
            continue;
        }
        // `-l <sel>` / `-f <sel>`, or attached (`-lapp=api`).
        if tok == "-l" || tok == "-f" {
            match tokens.get(i) {
                Some(sel) if !sel.starts_with('-') && sel != "&&" => {
                    let mut sel = sel.clone();
                    i += 1;
                    if tok == "-l" && tokens.get(i).is_some_and(|s| s == "in" || s == "notin") {
                        sel.push(' ');
                        sel.push_str(&tokens[i]);
                        i += 1;
                        if let Some(set) = tokens.get(i).filter(|s| s.starts_with('(')) {
                            sel.push(' ');
                            sel.push_str(set);
                            i += 1;
                        } else {
                            fail(&mut error, "expected selector set in parentheses".into());
                            continue;
                        }
                    }
                    if sel.is_empty() || (tok == "-f" && !sel.contains('=')) {
                        fail(&mut error, format!("invalid selector after {tok}"));
                        continue;
                    }
                    if tok == "-l" {
                        &mut labels
                    } else {
                        &mut fields
                    }
                    .push(sel);
                }
                _ => fail(&mut error, format!("expected selector after {tok}")),
            }
            continue;
        }
        if let Some(sel) = attached_selector(tok, "-l") {
            labels.push(sel.to_string());
            continue;
        }
        if let Some(sel) = attached_selector(tok, "-f") {
            fields.push(sel.to_string());
            continue;
        }
        if let Some((key, op, value)) = split_cmp(tok) {
            if value.is_empty() {
                fail(&mut error, format!("missing value in '{tok}'"));
                continue;
            }
            match typed_value(key, value) {
                Ok(v) => terms.push(Term::Cmp(Cmp {
                    key: key.to_ascii_lowercase(),
                    op,
                    value: v,
                })),
                Err(e) => fail(&mut error, e),
            }
            continue;
        }
        if let Some(pat) = tok.strip_prefix('!') {
            if pat.is_empty() {
                fail(&mut error, "expected text after '!'".into());
            } else {
                terms.push(Term::NotFuzzy(pat.to_string()));
            }
            continue;
        }
        terms.push(Term::Fuzzy(tok.to_string()));
    }

    Structured {
        terms,
        labels: (!labels.is_empty()).then(|| labels.join(",")),
        fields: (!fields.is_empty()).then(|| fields.join(",")),
        error,
    }
}

/// Whether any token flips the input from a single legacy fuzzy pattern into
/// the structured grammar. Mirrors the markers `parse` acts on.
fn is_structured(input: &str) -> bool {
    input.contains("&&")
        || input.contains("||")
        || input.split_whitespace().any(|tok| {
            tok == "&&"
                || tok == "-l"
                || tok == "-f"
                || attached_selector(tok, "-l").is_some()
                || attached_selector(tok, "-f").is_some()
                || tok.starts_with('!')
                || tok.starts_with('(')
                || split_cmp(tok.trim_start_matches('(')).is_some()
        })
}

fn tokenize(input: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut depth = 0usize;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
                if depth > 0 {
                    token.push(c);
                }
            } else {
                token.push(c);
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
            if depth > 0 {
                token.push(c);
            }
        } else if c == '(' {
            depth += 1;
            token.push(c);
        } else if c == ')' {
            depth = depth.checked_sub(1).ok_or("unexpected ')' in filter")?;
            token.push(c);
        } else if depth == 0 && matches!(c, '&' | '|') && chars.peek() == Some(&c) {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
            chars.next();
            tokens.push(format!("{c}{c}"));
        } else if c.is_whitespace() && depth == 0 {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(c);
        }
    }
    if quote.is_some() || depth != 0 {
        return Err("unclosed quote or selector set".into());
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    Ok(tokens)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceQuery {
    pub resource: String,
    pub namespace: Option<String>,
    pub context: Option<String>,
    pub filter: String,
}

impl ResourceQuery {
    /// Scope options precede `/filter`; everything after the slash belongs to
    /// the row grammar, including whitespace and selector flags.
    pub fn parse(input: &str) -> Result<Self, String> {
        let (scope, filter) = input.split_once(" /").unwrap_or((input, ""));
        let mut words = scope.split_whitespace();
        let resource = words.next().ok_or("expected resource")?.to_string();
        let mut query = Self {
            resource,
            namespace: None,
            context: None,
            filter: filter.into(),
        };
        while let Some(word) = words.next() {
            let slot = match word {
                "-n" | "--namespace" => &mut query.namespace,
                "--context" => &mut query.context,
                _ if !word.starts_with('-') && query.namespace.is_none() => {
                    query.namespace = Some(word.into());
                    continue;
                }
                _ => return Err(format!("unexpected scope argument '{word}'")),
            };
            let value = words
                .next()
                .filter(|s| !s.starts_with('-'))
                .ok_or_else(|| format!("expected value after {word}"))?;
            if slot.is_some() {
                return Err(format!("duplicate {word}"));
            }
            *slot = Some(value.into());
        }
        if let Some(error) = parse(filter).error() {
            return Err(error.into());
        }
        Ok(query)
    }
}

/// The selector of an attached `-l`/`-f` form (`-lapp=api`). Requires an `=`
/// so ordinary fuzzy text starting with those letters isn't swallowed.
fn attached_selector<'a>(tok: &'a str, flag: &str) -> Option<&'a str> {
    tok.strip_prefix(flag).filter(|rest| rest.contains('='))
}

/// Split `key<op>value` at the operator following a valid key. `None` when
/// the token has no operator or no leading key — i.e. plain fuzzy text.
fn split_cmp(tok: &str) -> Option<(&str, Op, &str)> {
    if !tok
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let key_end =
        tok.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))?;
    let (key, rest) = tok.split_at(key_end);
    let (op, value) = if let Some(v) = rest.strip_prefix("!=") {
        (Op::Ne, v)
    } else if let Some(v) = rest.strip_prefix(">=") {
        (Op::Ge, v)
    } else if let Some(v) = rest.strip_prefix("<=") {
        (Op::Le, v)
    } else if let Some(v) = rest.strip_prefix("==") {
        (Op::Eq, v)
    } else if let Some(v) = rest.strip_prefix('=') {
        (Op::Eq, v)
    } else if let Some(v) = rest.strip_prefix('>') {
        (Op::Gt, v)
    } else {
        (Op::Lt, rest.strip_prefix('<')?)
    };
    Some((key, op, value))
}

/// Fold a comparison needle once at parse time.
///
/// Whole-string lowercasing is required for non-ASCII text because it applies
/// context-sensitive mappings such as Greek final sigma. ASCII uses its
/// cheaper equivalent; the resulting `String` is retained in `CmpValue`.
fn fold_lower(s: &str) -> String {
    if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        s.to_lowercase()
    }
}

/// Compare a cell with a needle already returned by [`fold_lower`].
///
/// The common ASCII path performs no per-cell allocation. If either operand is
/// non-ASCII, use whole-string lowercasing to preserve the case-insensitive
/// behavior that structured filters had before the ASCII optimization.
pub fn cmp_folded_lower(cell: &str, want: &str) -> std::cmp::Ordering {
    if cell.is_ascii() && want.is_ascii() {
        cell.bytes()
            .map(|byte| byte.to_ascii_lowercase())
            .cmp(want.bytes())
    } else {
        cell.to_lowercase().as_str().cmp(want)
    }
}

/// Type a comparison value from its key: quantities for `cpu`/`mem`/`memory`,
/// durations for `age`, and number-or-text for everything else.
fn typed_value(key: &str, raw: &str) -> Result<CmpValue, String> {
    match key.to_ascii_lowercase().as_str() {
        "cpu" => parse_cpu(raw)
            .map(CmpValue::Cpu)
            .ok_or_else(|| format!("bad cpu quantity '{raw}'")),
        "mem" | "memory" => parse_mem(raw)
            .map(CmpValue::Mem)
            .ok_or_else(|| format!("bad memory quantity '{raw}'")),
        "age" => parse_duration(raw)
            .map(CmpValue::Duration)
            .ok_or_else(|| format!("bad duration '{raw}'")),
        _ => match raw.parse::<f64>() {
            Ok(value) if value.is_finite() => Ok(CmpValue::Num(value)),
            Ok(_) => Err(format!("non-finite number '{raw}'")),
            Err(_) if key.eq_ignore_ascii_case("restarts") => {
                Err(format!("bad restart count '{raw}'"))
            }
            Err(_) => Ok(CmpValue::Str(fold_lower(raw))),
        },
    }
}

/// Numeric columns may append annotations, but missing cells are not zero.
pub fn cell_number(cell: &str) -> Option<f64> {
    let number = cell
        .trim()
        .split([' ', '/', '('])
        .next()?
        .parse::<f64>()
        .ok()?;
    number.is_finite().then_some(number)
}

/// CPU quantity → millicores: `250m` → 250, `1` → 1000, `500000000n` → 500.
/// Unlike [`crate::columns::parse_cpu_milli`] this rejects garbage instead of
/// defaulting to 0, so a typo can be reported.
fn parse_cpu(s: &str) -> Option<i64> {
    let s = s.trim();
    let (num, scale) = match s.chars().last()? {
        'n' => (&s[..s.len() - 1], 1.0 / 1_000_000.0),
        'u' => (&s[..s.len() - 1], 1.0 / 1_000.0),
        'm' => (&s[..s.len() - 1], 1.0),
        _ => (s, 1000.0),
    };
    let v: f64 = num.parse().ok()?;
    (v >= 0.0 && (v * scale).is_finite() && v * scale < i64::MAX as f64)
        .then(|| (v * scale).round() as i64)
}

/// Memory quantity → bytes: `1Gi`, `512Mi`, `2000000`. Validating twin of
/// [`crate::columns::parse_mem_bytes`].
fn parse_mem(s: &str) -> Option<i64> {
    let s = s.trim();
    let suffixes: &[(&str, f64)] = &[
        ("Ki", 1024.0),
        ("Mi", 1024.0 * 1024.0),
        ("Gi", 1024.0 * 1024.0 * 1024.0),
        ("Ti", 1024.0f64.powi(4)),
        ("K", 1e3),
        ("M", 1e6),
        ("G", 1e9),
        ("T", 1e12),
    ];
    for (suf, mult) in suffixes {
        if let Some(num) = s.strip_suffix(suf) {
            let v: f64 = num.trim().parse().ok()?;
            return (v >= 0.0 && (v * mult).is_finite() && v * mult < i64::MAX as f64)
                .then(|| (v * mult) as i64);
        }
    }
    let v: f64 = s.parse().ok()?;
    (v >= 0.0 && v.is_finite() && v < i64::MAX as f64).then_some(v as i64)
}

/// Duration → seconds: `90s`, `2h`, `1d2h`, `1h30m`, bare `300` (seconds).
/// Units: s, m, h, d, w.
fn parse_duration(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(v) = s.parse::<i64>() {
        return (v >= 0).then_some(v);
    }
    let mut total = 0i64;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return None,
        };
        if num.is_empty() {
            return None;
        }
        total = total.checked_add(num.parse::<i64>().ok()?.checked_mul(unit)?)?;
        num.clear();
    }
    // Trailing digits without a unit (`2h30`) are malformed.
    num.is_empty().then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_precedence_groups_and_inverse() {
        let s = structured("api || worker && !canary");
        assert_eq!(s.error, None);
        assert_eq!(
            s.terms,
            vec![Term::Any(vec![
                Term::All(vec![Term::Fuzzy("api".into())]),
                Term::All(vec![
                    Term::Fuzzy("worker".into()),
                    Term::NotFuzzy("canary".into())
                ]),
            ])]
        );
        let s = structured("-l app=api (status=Running||age>2h) !(restarts>=5)");
        assert_eq!(s.error, None);
        assert_eq!(s.labels.as_deref(), Some("app=api"));
        assert!(s.terms.iter().any(Term::time_sensitive));
        assert_eq!(structured("(name='api server' || !canary)").error, None);
        for input in [
            "api ||",
            "|| api",
            "api || || worker",
            "status=Running && ()",
            "-l app=api || worker",
            "!(-l app=api)",
            "(status=Running)junk",
        ] {
            assert!(parse(input).error().is_some(), "{input}");
        }
        let deep = format!("{}age>2h{}", "(".repeat(40), ")".repeat(40));
        assert!(parse(&deep).error().is_some());
    }

    #[test]
    fn numeric_validation_and_well_known_fields() {
        for input in ["restarts=NaN", "restarts>inf", "restarts>=oops"] {
            assert!(parse(input).error().is_some(), "{input}");
        }
        assert_eq!(cell_number("-"), None);
        assert_eq!(cell_number("NaN"), None);
        assert_eq!(cell_number("5 (2m ago)"), Some(5.0));
        assert_eq!(
            structured("spec.nodeName=node-3 metadata.namespace=prod status.phase=Running")
                .terms
                .len(),
            3
        );
    }

    #[test]
    fn sets_quotes_and_explicit_and() {
        let s = structured("-l app in (api, worker),env=prod && status=Running");
        assert_eq!(s.labels.as_deref(), Some("app in (api, worker),env=prod"));
        assert_eq!(s.terms.len(), 1);
        assert_eq!(s.error, None);
        assert_eq!(
            structured("-l 'app notin (api, worker)' !canary")
                .labels
                .as_deref(),
            Some("app notin (api, worker)")
        );
        assert_eq!(
            structured("name='api server'").terms,
            vec![Term::Cmp(Cmp {
                key: "name".into(),
                op: Op::Eq,
                value: CmpValue::Str("api server".into())
            })]
        );
        for input in [
            "-l app in (api",
            "-l app in",
            "-l 'app=api",
            "-l -f metadata.name=api",
            "-f spec.nodeName",
            "status=Running &&",
            "&& api",
        ] {
            assert!(parse(input).error().is_some(), "{input}");
        }
    }

    #[test]
    fn resource_queries_validate_scope_and_filter() {
        assert_eq!(
            ResourceQuery::parse("pods -n prod --context west /-l app=api age<2h").unwrap(),
            ResourceQuery {
                resource: "pods".into(),
                namespace: Some("prod".into()),
                context: Some("west".into()),
                filter: "-l app=api age<2h".into(),
            }
        );
        assert_eq!(
            ResourceQuery::parse("pods all /kube system")
                .unwrap()
                .filter,
            "kube system"
        );
        for input in [
            "pods -n",
            "pods --context",
            "pods -n -x",
            "pods prod extra /api",
            "pods /cpu>oops",
        ] {
            assert!(ResourceQuery::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn quantities_and_durations_reject_overflow() {
        for input in [
            "cpu>inf",
            "cpu>1e100",
            "memory>inf",
            "memory>1e100Gi",
            "age<9223372036854775807w",
        ] {
            assert!(parse(input).error().is_some(), "{input}");
        }
    }

    fn structured(input: &str) -> Structured {
        match parse(input) {
            ParsedFilter::Structured(s) => s,
            other => panic!("expected structured parse for '{input}', got {other:?}"),
        }
    }

    #[test]
    fn plain_text_stays_one_legacy_fuzzy_pattern() {
        assert_eq!(parse(""), ParsedFilter::Fuzzy(String::new()));
        assert_eq!(parse("api"), ParsedFilter::Fuzzy("api".into()));
        // Spaces included: the whole string is the pattern, as before.
        assert_eq!(
            parse("kube system dns"),
            ParsedFilter::Fuzzy("kube system dns".into())
        );
        // Leading/trailing whitespace is not part of the pattern.
        assert_eq!(parse("  api "), ParsedFilter::Fuzzy("api".into()));
        // A lone dash or dashed name is still fuzzy text, not a flag.
        assert_eq!(parse("-longname"), ParsedFilter::Fuzzy("-longname".into()));
    }

    #[test]
    fn inverse_term() {
        let s = structured("!canary");
        assert_eq!(s.terms, vec![Term::NotFuzzy("canary".into())]);
        assert_eq!(s.error, None);
    }

    #[test]
    fn label_selector_variants() {
        let s = structured("-l app=api,env=prod");
        assert_eq!(s.labels.as_deref(), Some("app=api,env=prod"));
        assert!(s.terms.is_empty());
        assert_eq!(s.error, None);

        // Attached form and repeated flags joining with a comma.
        let s = structured("-lapp=api -l env=prod");
        assert_eq!(s.labels.as_deref(), Some("app=api,env=prod"));

        // Bare-key (existence) selectors work in the spaced form.
        let s = structured("-l app");
        assert_eq!(s.labels.as_deref(), Some("app"));
    }

    #[test]
    fn field_selector() {
        let s = structured("-f spec.nodeName=node-3");
        assert_eq!(s.fields.as_deref(), Some("spec.nodeName=node-3"));
        assert_eq!(s.labels, None);
        assert!(s.terms.is_empty());
    }

    /// `CmpValue::Str` is stored pre-folded: the comparison is
    /// case-insensitive, so the needle is lowercased once here rather than
    /// once per object per rebuild.
    #[test]
    fn status_equality_and_inequality() {
        let s = structured("status=CrashLoopBackOff");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "status".into(),
                op: Op::Eq,
                value: CmpValue::Str("crashloopbackoff".into()),
            })]
        );

        let s = structured("status!=Running");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "status".into(),
                op: Op::Ne,
                value: CmpValue::Str("running".into()),
            })]
        );
    }

    #[test]
    fn typed_quantity_comparisons() {
        let s = structured("cpu>500m");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "cpu".into(),
                op: Op::Gt,
                value: CmpValue::Cpu(500),
            })]
        );

        let s = structured("cpu>=1");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "cpu".into(),
                op: Op::Ge,
                value: CmpValue::Cpu(1000),
            })]
        );

        let s = structured("memory>1Gi");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "memory".into(),
                op: Op::Gt,
                value: CmpValue::Mem(1024 * 1024 * 1024),
            })]
        );

        let s = structured("mem<=512Mi");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "mem".into(),
                op: Op::Le,
                value: CmpValue::Mem(512 * 1024 * 1024),
            })]
        );

        let s = structured("restarts>=5");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "restarts".into(),
                op: Op::Ge,
                value: CmpValue::Num(5.0),
            })]
        );
    }

    #[test]
    fn age_durations() {
        let s = structured("age<2h");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "age".into(),
                op: Op::Lt,
                value: CmpValue::Duration(7_200),
            })]
        );

        let s = structured("age>1d2h");
        assert_eq!(
            s.terms,
            vec![Term::Cmp(Cmp {
                key: "age".into(),
                op: Op::Gt,
                value: CmpValue::Duration(93_600),
            })]
        );
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration("90s"), Some(90));
        assert_eq!(parse_duration("2h"), Some(7_200));
        assert_eq!(parse_duration("1h30m"), Some(5_400));
        assert_eq!(parse_duration("1w"), Some(604_800));
        assert_eq!(parse_duration("300"), Some(300));
        assert_eq!(parse_duration("2h30"), None); // trailing digits, no unit
        assert_eq!(parse_duration("xyz"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn quantity_parsing() {
        assert_eq!(parse_cpu("250m"), Some(250));
        assert_eq!(parse_cpu("1"), Some(1_000));
        assert_eq!(parse_cpu("1.5"), Some(1_500));
        assert_eq!(parse_cpu("500000000n"), Some(500));
        assert_eq!(parse_cpu("abc"), None);
        assert_eq!(parse_mem("1Ki"), Some(1_024));
        assert_eq!(parse_mem("512Mi"), Some(512 * 1024 * 1024));
        assert_eq!(parse_mem("2000000"), Some(2_000_000));
        assert_eq!(parse_mem("1Xi"), None);
    }

    #[test]
    fn terms_combine_with_and_semantics() {
        let s = structured("api !canary -l app=api status=Running");
        assert_eq!(s.labels.as_deref(), Some("app=api"));
        assert_eq!(s.error, None);
        assert_eq!(
            s.terms,
            vec![
                Term::Fuzzy("api".into()),
                Term::NotFuzzy("canary".into()),
                Term::Cmp(Cmp {
                    key: "status".into(),
                    op: Op::Eq,
                    value: CmpValue::Str("running".into()),
                }),
            ]
        );
    }

    #[test]
    fn malformed_terms_report_without_blanking() {
        // Mid-typing states must degrade to "term skipped + error", never a
        // hard failure.
        let s = structured("-l");
        assert_eq!(s.labels, None);
        assert!(s.error.as_deref().is_some_and(|e| e.contains("-l")));

        let s = structured("cpu>");
        assert!(s.terms.is_empty());
        assert!(s.error.as_deref().is_some_and(|e| e.contains("cpu>")));

        let s = structured("cpu>abc");
        assert!(s.terms.is_empty());
        assert!(s.error.as_deref().is_some_and(|e| e.contains("abc")));

        let s = structured("age<soon");
        assert!(s.error.as_deref().is_some_and(|e| e.contains("soon")));

        let s = structured("! api");
        assert_eq!(s.terms, vec![Term::Fuzzy("api".into())]);
        assert!(s.error.is_some());
    }

    #[test]
    fn fuzzy_needle_prefers_first_positive_term() {
        assert_eq!(parse("khc").fuzzy_needle(), Some("khc"));
        assert_eq!(parse("").fuzzy_needle(), None);
        assert_eq!(parse("!x khc status=Running").fuzzy_needle(), Some("khc"));
        assert_eq!(parse("-l app=api").fuzzy_needle(), None);
    }

    #[test]
    fn unicode_comparisons_fold_mixed_case_in_both_directions() {
        for (cell, raw_needle) in [("ΟΔΟΣ", "οδος"), ("οδος", "ΟΔΟΣ")] {
            let CmpValue::Str(needle) = typed_value("name", raw_needle).expect("typed") else {
                panic!("expected a text comparison");
            };
            assert_eq!(
                cmp_folded_lower(cell, &needle),
                std::cmp::Ordering::Equal,
                "cell={cell:?}, needle={raw_needle:?}"
            );
        }
    }

    #[test]
    fn ascii_comparisons_remain_case_insensitive() {
        let CmpValue::Str(needle) = typed_value("status", "rUnNiNg").expect("typed") else {
            panic!("expected a text comparison");
        };
        assert_eq!(
            cmp_folded_lower("RUNNING", &needle),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn server_side_selectors_only_from_l_and_f() {
        for local in ["api", "status=Running", "!x cpu>1"] {
            let p = parse(local);
            assert_eq!(p.labels(), None, "{local}");
            assert_eq!(p.fields(), None, "{local}");
        }
        assert_eq!(parse("-l app=api").labels(), Some("app=api"));
        assert_eq!(
            parse("-f spec.nodeName=n1").fields(),
            Some("spec.nodeName=n1")
        );
    }
}
