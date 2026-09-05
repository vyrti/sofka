//! The fuzzy matcher behind row filtering, the pickers and `find`.
//!
//! One matcher instance is shared by everything that scores a needle against a
//! haystack, so the scratch buffers below are allocated once for the process
//! rather than once per row. The matcher needs `&mut self`, and the call sites
//! hold `&App`, hence the interior mutability.

use std::cell::RefCell;

use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher, Utf32Str};

/// A shared fuzzy matcher.
///
/// Case handling is *smart*: an all-lowercase needle matches case-insensitively
/// and a needle with any uppercase character matches exactly, which is what the
/// previous matcher did by default and what the filter's documented behaviour
/// describes.
///
/// The whole needle is one fuzzy atom. The matcher's own pattern syntax —
/// space-separated atoms, `^`/`$`/`'`/`!` prefixes — is deliberately not
/// enabled: sofka parses `!`, `-l` and `key=value` terms itself before
/// anything reaches here, and letting a second syntax through would change
/// what a filter means.
pub struct Fuzzy {
    inner: RefCell<Inner>,
}

struct Inner {
    matcher: Matcher,
    /// The needle `atom` was built from. Building an atom case-folds and
    /// normalizes it, and a filter pass scores one needle against every row in
    /// the store, so it is built once per needle rather than once per row.
    needle: String,
    atom: Atom,
    /// Scratch for the UTF-32 haystack and the match positions.
    haystack: Vec<char>,
    indices: Vec<u32>,
}

impl Inner {
    fn sync(&mut self, needle: &str) {
        if self.needle != needle {
            self.needle.clear();
            self.needle.push_str(needle);
            self.atom = atom(needle);
        }
    }
}

fn atom(needle: &str) -> Atom {
    Atom::new(
        needle,
        CaseMatching::Smart,
        Normalization::Smart,
        AtomKind::Fuzzy,
        // `\ ` escaping belongs to the pattern syntax this deliberately avoids.
        false,
    )
}

impl Fuzzy {
    pub fn new() -> Self {
        Fuzzy {
            inner: RefCell::new(Inner {
                matcher: Matcher::new(Config::DEFAULT),
                needle: String::new(),
                atom: atom(""),
                haystack: Vec::new(),
                indices: Vec::new(),
            }),
        }
    }

    /// The match score, or `None` when `needle` does not match. Higher is a
    /// better match; the absolute values are only ever compared with each
    /// other.
    pub fn score(&self, haystack: &str, needle: &str) -> Option<i64> {
        let mut inner = self.inner.borrow_mut();
        inner.sync(needle);
        let Inner {
            matcher,
            atom,
            haystack: buf,
            ..
        } = &mut *inner;
        atom.score(Utf32Str::new(haystack, buf), matcher)
            .map(i64::from)
    }

    /// The char positions in `haystack` that `needle` matched, ascending, or
    /// `None` when it does not match.
    pub fn indices(&self, haystack: &str, needle: &str) -> Option<Vec<usize>> {
        let mut inner = self.inner.borrow_mut();
        inner.sync(needle);
        let Inner {
            matcher,
            atom,
            haystack: buf,
            indices,
            ..
        } = &mut *inner;
        indices.clear();
        atom.indices(Utf32Str::new(haystack, buf), matcher, indices)?;
        // Reported in match order, which is not necessarily ascending, and can
        // repeat a position; callers highlight by walking them in order.
        indices.sort_unstable();
        indices.dedup();
        Some(indices.iter().map(|&i| i as usize).collect())
    }
}

impl Default for Fuzzy {
    fn default() -> Self {
        Fuzzy::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_subsequences_and_reports_their_positions() {
        let f = Fuzzy::new();
        assert!(f.score("kube-httpcache-0", "khc").is_some());
        assert!(f.score("kube-httpcache-0", "zzz").is_none());

        let idx = f.indices("kube-httpcache-0", "khc").unwrap();
        assert_eq!(idx.len(), 3);
        assert!(idx.is_sorted());
        // Every reported position is inside the name and names its character.
        let chars: Vec<char> = "kube-httpcache-0".chars().collect();
        for (pos, want) in idx.iter().zip("khc".chars()) {
            assert_eq!(chars[*pos].to_ascii_lowercase(), want);
        }
    }

    /// Smart case: a lowercase needle ignores case, an uppercase one does not.
    #[test]
    fn case_is_smart() {
        let f = Fuzzy::new();
        assert!(f.score("Kube-System", "kube").is_some());
        assert!(f.score("Kube-System", "Kube").is_some());
        assert!(f.score("kube-system", "Kube").is_none());
    }

    #[test]
    fn an_empty_needle_matches_everything() {
        let f = Fuzzy::new();
        assert!(f.score("anything", "").is_some());
        assert_eq!(f.indices("anything", "").unwrap(), Vec::<usize>::new());
    }

    /// Positions are char indices, not byte offsets, so a multibyte name
    /// highlights the character the user sees.
    #[test]
    fn positions_are_char_indices() {
        let f = Fuzzy::new();
        let idx = f.indices("héllo-world", "hw").unwrap();
        let chars: Vec<char> = "héllo-world".chars().collect();
        assert_eq!(chars[idx[0]], 'h');
        assert_eq!(chars[idx[1]], 'w');
    }

    /// Switching needles must rebuild the cached atom, not reuse the old one.
    #[test]
    fn a_new_needle_replaces_the_cached_atom() {
        let f = Fuzzy::new();
        assert!(f.score("alpha", "alp").is_some());
        assert!(f.score("alpha", "zzz").is_none());
        assert!(f.score("alpha", "pha").is_some());
    }

    /// The matcher's own pattern syntax stays off: these are literal
    /// characters to match, not operators.
    #[test]
    fn pattern_syntax_is_not_interpreted() {
        let f = Fuzzy::new();
        // `^`, `$` and `!` would be anchors/negation in the pattern language.
        assert!(f.score("web-1", "^web").is_none());
        assert!(f.score("^web-1", "^web").is_some());
        assert!(f.score("web-1", "!web").is_none());
        // A space is a literal, not an atom separator.
        assert!(f.score("default web-1", "t w").is_some());
        assert!(f.score("web-1", "web 1").is_none());
    }
}
