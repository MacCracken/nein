//! Basic host firewall example.
//!
//! Generates a standard host firewall that allows established connections,
//! loopback, and SSH, dropping everything else.

fn main() {
    let fw = nein::builder::basic_host_firewall();
    println!("{}", fw.render());
}
