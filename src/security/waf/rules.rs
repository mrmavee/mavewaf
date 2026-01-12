//! Rule engine logic.
//!
//! Implements score-based request filtering using regex and literal comparisons.

use aho_corasick::AhoCorasick;
use percent_encoding::percent_decode_str;
use regex::RegexSet;
use std::collections::HashMap;
use std::sync::Arc;
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

impl RuleEngine {
    /// Creates a new engine with default detection rules.
    ///
    /// # Panics
    ///
    /// Panics if any default rule contains an invalid regex pattern (compile-time invariant).
    #[must_use]
    pub fn new() -> Self {
        let (lit_patterns, lit_rules, rx_patterns, rx_rules) = Self::default_rules();
        debug!(
            literal_count = lit_rules.len(),
            regex_count = rx_rules.len(),
            "Rule engine initialized"
        );

        let ac = AhoCorasick::new(lit_patterns).expect("Failed to build Aho-Corasick automaton");
        let regex_set = RegexSet::new(rx_patterns).expect("Failed to build RegexSet");

        let thresholds = HashMap::from([
            ("SQL".into(), 8),
            ("XSS".into(), 8),
            ("RFI".into(), 8),
            ("TRAVERSAL".into(), 4),
            ("EVADE".into(), 4),
        ]);

        Self {
            literal_rules: Arc::new(lit_rules),
            regex_rules: Arc::new(rx_rules),
            ac: Arc::new(ac),
            regex_set: Arc::new(regex_set),
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
            Self::lit(
                1003,
                "/*",
                &[Zone::Path, Zone::Query, Zone::Cookie],
                &[("SQL", 8)],
            ),
            Self::lit(
                1004,
                "*/",
                &[Zone::Path, Zone::Query, Zone::Cookie],
                &[("SQL", 8)],
            ),
            Self::lit(
                1005,
                "|",
                &[Zone::Path, Zone::Query, Zone::Cookie],
                &[("SQL", 8)],
            ),
            Self::lit(
                1006,
                "&&",
                &[Zone::Path, Zone::Query, Zone::Cookie],
                &[("SQL", 8)],
            ),
            Self::lit(
                1007,
                "--",
                &[Zone::Path, Zone::Query, Zone::Cookie],
                &[("SQL", 4)],
            ),
            Self::lit(
                1008,
                ";",
                &[Zone::Path, Zone::Query],
                &[("SQL", 4), ("XSS", 8)],
            ),
            Self::lit(
                1010,
                "(",
                &[Zone::Path, Zone::Cookie],
                &[("SQL", 4), ("XSS", 8)],
            ),
            Self::lit(
                1011,
                ")",
                &[Zone::Path, Zone::Cookie],
                &[("SQL", 4), ("XSS", 8)],
            ),
            Self::lit(
                1013,
                "'",
                &[Zone::Query, Zone::Path, Zone::Cookie],
                &[("SQL", 4), ("XSS", 8)],
            ),
            Self::lit(
                1017,
                "@@",
                &[Zone::Path, Zone::Query, Zone::Cookie],
                &[("SQL", 4)],
            ),
            Self::rx(
                2001,
                r"(?i)(union\s+(all\s+)?select)",
                &[Zone::Query, Zone::Body],
                &[("SQL", 8)],
            ),
            Self::rx(
                2002,
                r"(?i)(insert\s+into|delete\s+from|drop\s+table)",
                &[Zone::Query, Zone::Body],
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
            Self::lit(
                1200,
                "..",
                &[Zone::Query, Zone::Path, Zone::Cookie],
                &[("TRAVERSAL", 4)],
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
            Self::lit(
                1205,
                "\\",
                &[Zone::Query, Zone::Path, Zone::Cookie],
                &[("TRAVERSAL", 4)],
            ),
        ]
    }

    fn xss_rules() -> Vec<(String, Rule, bool)> {
        vec![
            Self::lit(
                1302,
                "<",
                &[Zone::Query, Zone::Path, Zone::Cookie],
                &[("XSS", 8)],
            ),
            Self::lit(
                1303,
                ">",
                &[Zone::Query, Zone::Path, Zone::Cookie],
                &[("XSS", 8)],
            ),
            Self::lit(
                1312,
                "~",
                &[Zone::Path, Zone::Query, Zone::Cookie],
                &[("XSS", 4)],
            ),
            Self::lit(
                1314,
                "`",
                &[Zone::Query, Zone::Path, Zone::Cookie],
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
        vec![
            Self::lit(
                1400,
                "&#",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("EVADE", 4)],
            ),
            Self::lit(
                1401,
                "%U",
                &[Zone::Query, Zone::Body, Zone::Path, Zone::Cookie],
                &[("EVADE", 4)],
            ),
        ]
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
}
