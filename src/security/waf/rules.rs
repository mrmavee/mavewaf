//! Rule engine logic.
//!
//! Implements score-based request filtering using regex and literal comparisons.

use aho_corasick::AhoCorasick;
use percent_encoding::percent_decode_str;
use regex::RegexSet;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use tracing::debug;

const BLOCK_SCORE: u32 = 100;

/// Request zones to inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Zone {
    Path,
    Query,
    Body,
    Cookie,
}

/// A detection rule with score assignment.
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,
    pub zones: Vec<Zone>,
    pub scores: Vec<(String, u32)>,
}

/// Score-based rule evaluation engine.
#[derive(Clone)]
pub struct RuleEngine {
    literal_rules: Arc<Vec<Rule>>,
    regex_rules: Arc<Vec<Rule>>,
    ac: Arc<AhoCorasick>,
    regex_set: Arc<RegexSet>,
    thresholds: HashMap<String, u32>,
}

/// Evaluation result from the rule engine.
#[derive(Debug)]
pub struct EvalResult {
    pub blocked: bool,
    pub scores: HashMap<String, u32>,
    pub matched_rules: Vec<u32>,
}

type CachedRules = (
    Arc<Vec<Rule>>,
    Arc<Vec<Rule>>,
    Arc<AhoCorasick>,
    Arc<RegexSet>,
);

static CACHED_RULES: OnceLock<CachedRules> = OnceLock::new();

impl RuleEngine {
    /// Creates a new engine with default detection rules.
    ///
    /// # Panics
    ///
    /// Panics if any default rule contains an invalid regex pattern (compile-time invariant).
    #[must_use]
    pub fn new() -> Self {
        let (lit_rules, rx_rules, ac, regex_set) = CACHED_RULES
            .get_or_init(|| {
                let (lit_patterns, lit_rules, rx_patterns, rx_rules) = Self::default_rules();
                debug!(
                    literal_count = lit_rules.len(),
                    regex_count = rx_rules.len(),
                    "Rule engine initialized"
                );

                let ac =
                    AhoCorasick::new(lit_patterns).expect("Failed to build Aho-Corasick automaton");
                let regex_set = RegexSet::new(rx_patterns).expect("Failed to build RegexSet");

                (
                    Arc::new(lit_rules),
                    Arc::new(rx_rules),
                    Arc::new(ac),
                    Arc::new(regex_set),
                )
            })
            .clone();

        let thresholds = HashMap::from([
            ("SQL".into(), 8),
            ("XSS".into(), 8),
            ("RFI".into(), 8),
            ("TRAVERSAL".into(), 4),
            ("EVADE".into(), 4),
        ]);

        Self {
            literal_rules: lit_rules,
            regex_rules: rx_rules,
            ac,
            regex_set,
            thresholds,
        }
    }

    /// Evaluates request parts against defined rules.
    #[must_use]
    pub fn evaluate(&self, path: &str, query: &str, body: &str, cookie: &str) -> EvalResult {
        let mut scores: HashMap<String, u32> = HashMap::new();
        let mut matched_rules = Vec::new();

        let path_dec = percent_decode_str(path).decode_utf8_lossy();
        let query_dec = percent_decode_str(query)
            .decode_utf8_lossy()
            .replace('+', " ");
        let body_dec = percent_decode_str(body)
            .decode_utf8_lossy()
            .replace('+', " ");
        let cookie_dec = percent_decode_str(cookie).decode_utf8_lossy();

        let inputs = [
            (Zone::Path, path_dec.as_ref()),
            (Zone::Query, query_dec.as_ref()),
            (Zone::Body, body_dec.as_ref()),
            (Zone::Cookie, cookie_dec.as_ref()),
        ];

        for (zone, content) in inputs {
            if content.is_empty() {
                continue;
            }

            for mat in self.ac.find_iter(content) {
                let rule_idx = mat.pattern().as_usize();
                if let Some(rule) = self
                    .literal_rules
                    .get(rule_idx)
                    .filter(|r| r.zones.contains(&zone))
                {
                    if !matched_rules.contains(&rule.id) {
                        matched_rules.push(rule.id);
                        debug!(rule_id = rule.id, "Literal rule matched");
                    }
                    for (cat, score) in &rule.scores {
                        *scores.entry(cat.clone()).or_default() += *score;
                    }
                }
            }

            for idx in self.regex_set.matches(content) {
                if let Some(rule) = self
                    .regex_rules
                    .get(idx)
                    .filter(|r| r.zones.contains(&zone))
                {
                    if !matched_rules.contains(&rule.id) {
                        matched_rules.push(rule.id);
                        debug!(rule_id = rule.id, "Regex rule matched");
                    }
                    for (cat, score) in &rule.scores {
                        *scores.entry(cat.clone()).or_default() += *score;
                    }
                }
            }
        }

        let blocked = scores.values().any(|&s| s >= BLOCK_SCORE)
            || self
                .thresholds
                .iter()
                .any(|(cat, thresh)| scores.get(cat).copied().unwrap_or(0) >= *thresh);

        EvalResult {
            blocked,
            scores,
            matched_rules,
        }
    }

    fn default_rules() -> (Vec<String>, Vec<Rule>, Vec<String>, Vec<Rule>) {
        let mut lit_patterns = Vec::new();
        let mut lit_rules = Vec::new();
        let mut rx_patterns = Vec::new();
        let mut rx_rules = Vec::new();

        let all_rules = [
            Self::sql_rules(),
            Self::xss_rules(),
            Self::rfi_rules(),
            Self::traversal_rules(),
            Self::evade_rules(),
        ]
        .concat();

        for (pattern, rule, is_regex) in all_rules {
            if is_regex {
                rx_patterns.push(pattern);
                rx_rules.push(rule);
            } else {
                lit_patterns.push(pattern);
                lit_rules.push(rule);
            }
        }

        (lit_patterns, lit_rules, rx_patterns, rx_rules)
    }

    fn sql_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::lit(1010, "(", &[Zone::Cookie], &[("SQL", 4), ("XSS", 8)]),
            Self::lit(1011, ")", &[Zone::Cookie], &[("SQL", 4), ("XSS", 8)]),
            Self::rx(
                2001,
                r"(?i)\b(union\s+(all\s+)?select)\b",
                &[Zone::Query, Zone::Body],
                &[("SQL", 8)],
            ),
            Self::rx(
                2101,
                r"(?i)(?:'|\d|\)|@@)\s*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|--|#|/\*)",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 8)],
            ),
            Self::rx(
                2102,
                r"(?i);\s*(?:--|#|/\*|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|UNION|TRUNCATE|DECLARE)",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("SQL", 8)],
            ),
            Self::rx(
                2103,
                r"(?i)(?:'|\d|\)|@@)\s*\|\||\|\|\s*(?:'|\d|@)|'\s*\||\|\s*'",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 8)],
            ),
            Self::rx(
                2104,
                r"(?i)(?:'|\d|\)|@@)\s*&&|&&\s*(?:'|\d|@|!|\()|'\s*&|&\s*'",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 8)],
            ),
            Self::rx(
                2105,
                r"(?i)@@[a-z_][a-z0-9_]*",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("SQL", 8)],
            ),
        ]
    }

    fn rfi_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::lit(
                1102,
                "ftp://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
            Self::lit(
                1103,
                "php://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
            Self::lit(
                1108,
                "phar://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
            Self::lit(
                1109,
                "file://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
            Self::lit(
                1110,
                "gopher://",
                &[Zone::Query, Zone::Body, Zone::Cookie],
                &[("RFI", 8)],
            ),
        ]
    }

    fn traversal_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::rx(
                2200,
                r"(?:\.\.[/|\\])",
                &[Zone::Query, Zone::Path, Zone::Cookie, Zone::Body],
                &[("TRAVERSAL", 4)],
            ),
            Self::rx(
                2201,
                r"(?:[a-zA-Z]:\\)",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
            Self::rx(
                2202,
                r"(?:\.{2,}/+)+",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 8)],
            ),
            Self::rx(
                2203,
                r"\.\.;/",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 8)],
            ),
            Self::rx(
                2204,
                r"(?i)%2e%2e",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 8)],
            ),
            Self::lit(
                1202,
                "/etc/passwd",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
            Self::lit(
                1203,
                "c:\\",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
            Self::lit(
                1204,
                "cmd.exe",
                &[Zone::Query, Zone::Path, Zone::Body, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
        ]
    }

    fn xss_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::rx(
                2300,
                r"(?i)<[a-z/!?]",
                &[Zone::Query, Zone::Path, Zone::Cookie, Zone::Body],
                &[("XSS", 8)],
            ),
            Self::rx(
                2301,
                r"(?i)String\.from(Char|Code)",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("XSS", 8)],
            ),
            Self::rx(
                2302,
                r"(?i)javascript:\s*//",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("XSS", 8)],
            ),
            Self::rx(
                2303,
                r"(?i)data:[^,]+;base64",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("XSS", 8)],
            ),
            Self::rx(
                2003,
                r"(?i)<script[^>]*>",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("XSS", 8)],
            ),
            Self::rx(
                2004,
                r"(?i)(on\w+\s*=)",
                &[Zone::Query, Zone::Body],
                &[("XSS", 4)],
            ),
            Self::rx(
                2005,
                r"(?i)(javascript|vbscript|data):",
                &[Zone::Query, Zone::Body, Zone::Path],
                &[("XSS", 8)],
            ),
        ]
    }

    fn evade_rules() -> Vec<(String, Rule, bool)> {
        vec![Self::lit(
            1401,
            "%U",
            &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
            &[("EVADE", 4)],
        )]
    }

    fn lit(id: u32, pattern: &str, zones: &[Zone], scores: &[(&str, u32)]) -> (String, Rule, bool) {
        (
            pattern.into(),
            Rule {
                id,
                zones: zones.to_vec(),
                scores: scores.iter().map(|(k, v)| ((*k).into(), *v)).collect(),
            },
            false,
        )
    }

    fn rx(id: u32, pattern: &str, zones: &[Zone], scores: &[(&str, u32)]) -> (String, Rule, bool) {
        (
            pattern.into(),
            Rule {
                id,
                zones: zones.to_vec(),
                scores: scores.iter().map(|(k, v)| ((*k).into(), *v)).collect(),
            },
            true,
        )
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_evaluation() {
        let engine = RuleEngine::new();

        let eval = engine.evaluate("/search", "q=UNION SELECT", "", "");

        assert!(eval.blocked);
        assert!(*eval.scores.get("SQL").unwrap() >= 8);
        assert!(!eval.matched_rules.is_empty());
    }

    #[test]
    fn test_default_rules_integrity() {
        let (lit_patterns, lit_rules, rx_patterns, rx_rules) = RuleEngine::default_rules();
        assert!(!lit_patterns.is_empty());
        assert_eq!(lit_patterns.len(), lit_rules.len());
        assert!(!rx_patterns.is_empty());
        assert_eq!(rx_patterns.len(), rx_rules.len());

        let engine = RuleEngine::new();
        assert!(!engine.literal_rules.is_empty());
    }

    #[test]
    fn test_xss_detection() {
        let engine = RuleEngine::new();
        let eval = engine.evaluate("/?q=<script>alert(1)</script>", "", "", "");
        assert!(eval.blocked);
        assert!(*eval.scores.get("XSS").unwrap_or(&0) >= 8);
    }

    #[test]
    fn test_path_traversal_detection() {
        let engine = RuleEngine::new();
        let eval = engine.evaluate("/../../etc/passwd", "", "", "");
        assert!(eval.blocked);
        assert!(*eval.scores.get("TRAVERSAL").unwrap_or(&0) >= 4);
    }

    #[test]
    fn test_context_aware_sqli_false_positives() {
        let engine = RuleEngine::new();

        let safe_inputs = [
            "shoes|bags",
            "a&&b",
            "I'm happy",
            "Hello; world",
            "search=A & B",
            "Hello -- World",
            "user@example.com",
            "/* inline comment */",
        ];

        for input in safe_inputs {
            let eval = engine.evaluate("", &format!("q={input}"), "", "");
            assert!(
                !eval.blocked,
                "False positive blocked: '{input}'. matched_rules: {:?}",
                eval.matched_rules
            );
        }

        let malicious_inputs = [
            "1; DROP TABLE users",
            "1'; DROP TABLE users",
            "' || 'a'='a",
            "1' OR '1'='1",
            "1 UNION SELECT",
            "1 && 1=1",
            "1); DROP TABLE",
            "1 --",
            "@@version",
            "1 /*! UNION */",
        ];

        for input in malicious_inputs {
            let eval = engine.evaluate("", &format!("q={input}"), "", "");
            assert!(
                eval.blocked,
                "False negative allowed: '{input}'. matched_rules: {:?}",
                eval.matched_rules
            );
        }
    }

    #[test]
    fn test_context_aware_non_sqli_false_positives() {
        let engine = RuleEngine::new();

        let safe_cases = [
            "1 < 2",
            "I <3 u",
            "Loading...",
            "ver 1..2",
            r"Line 1\nLine 2",
        ];

        for input in safe_cases {
            let eval = engine.evaluate("", &format!("q={input}"), "", "");
            assert!(
                !eval.blocked,
                "False positive blocked: '{input}'. Matched: {:?}",
                eval.matched_rules
            );
        }

        let blocked_cases = [
            "<b>bold</b>",
            "<script>alert(1)</script>",
            "../etc/passwd",
            r"..\windows\system32",
            r"C:\Windows\System32",
        ];

        for input in blocked_cases {
            let eval = engine.evaluate("", &format!("q={input}"), "", "");
            assert!(
                eval.blocked,
                "False negative allowed: '{input}'. Matched: {:?}",
                eval.matched_rules
            );
        }
    }

    #[test]
    fn test_evasion_rules() {
        let engine = RuleEngine::new();

        let safe_inputs = [
            "The labor union selected a new leader",
            "Please insert into the slot",
            "I will drop table tennis from my hobbies",
        ];

        for input in safe_inputs {
            let eval = engine.evaluate("", &format!("q={input}"), "", "");
            assert!(!eval.blocked, "blocked legitimate input: {input}");
        }

        let evasion_payloads = [
            "String.fromCharCode(88,83,83)",
            "javascript://%250Aalert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "....//....//etc/passwd",
            "..;/etc/passwd",
            "%2e%2e/etc/passwd",
            "1'/**/UNION/**/SELECT",
            "1'/*!UNION*/SELECT",
            "id=-1' UNION ALL SELECT password FROM users--",
            "admin' --",
            "admin' #",
        ];

        for input in evasion_payloads {
            let eval = engine.evaluate("", &format!("q={input}"), "", "");
            assert!(eval.blocked, "allowed malicious input: {input}");
        }
    }
}
