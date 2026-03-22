#![no_main]
use libfuzzer_sys::fuzz_target;
use nein::rule::{Match, Rule, Verdict};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz rule rendering with arbitrary string inputs
        let rule = Rule::new(Verdict::Accept)
            .matching(Match::SourceAddr(s.to_string()))
            .matching(Match::Iif(s.to_string()))
            .comment(s);

        // Validation should catch bad input
        let _ = rule.validate();

        // Rendering should never panic
        let _ = rule.render();
    }
});
