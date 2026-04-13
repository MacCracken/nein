#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz TOML config parsing — should never panic
        if let Ok(fw) = nein::config::from_toml(s) {
            let _ = fw.validate();
            let _ = fw.render();
        }
    }
});
