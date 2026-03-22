//! GeoIP blocking example.
//!
//! Demonstrates blocking traffic from specific countries using nftables
//! sets populated with country CIDR ranges.

use nein::geoip::{CountryBlock, GeoIpBlocklist};

fn main() {
    let mut blocklist = GeoIpBlocklist::new();

    // Block example CIDRs (real deployments use a GeoIP database)
    blocklist.block_country(CountryBlock::v4(
        "XX",
        vec!["198.51.100.0/24".into(), "203.0.113.0/24".into()],
    ));

    blocklist.block_country(CountryBlock::dual(
        "YY",
        vec!["192.0.2.0/24".into()],
        vec!["2001:db8::/32".into()],
    ));

    blocklist.validate().expect("validate blocklist");
    println!("{}", blocklist.to_firewall().render());
}
