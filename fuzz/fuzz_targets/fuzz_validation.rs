#![no_main]
use libfuzzer_sys::fuzz_target;
use nein::validate;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz all validators — should never panic
        let _ = validate::validate_identifier(s);
        let _ = validate::validate_addr(s);
        let _ = validate::validate_iface(s);
        let _ = validate::validate_comment(s);
        let _ = validate::validate_log_prefix(s);
        let _ = validate::validate_nft_element(s);
    }
});
