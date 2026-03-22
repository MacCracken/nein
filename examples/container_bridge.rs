//! Container bridge firewall with port mappings and isolation.
//!
//! Demonstrates `BridgeFirewall` for container networking with port
//! forwarding and network isolation groups.

use nein::bridge::{BridgeConfig, BridgeFirewall, IsolationGroup, PortMapping};

fn main() {
    let config = BridgeConfig::new("br0", "172.17.0.0/16", "eth0");
    let mut bf = BridgeFirewall::new(config);

    // Add port mappings for two containers
    bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
        .expect("add web port");
    bf.add_port_mapping(PortMapping::tcp(5432, "172.17.0.3", 5432))
        .expect("add db port");

    // Isolate frontend and backend groups
    bf.add_isolation_group(IsolationGroup::new(
        "frontend",
        vec!["172.17.1.0/24".into()],
    ));
    bf.add_isolation_group(IsolationGroup::new("backend", vec!["172.17.2.0/24".into()]));

    bf.validate().expect("validate bridge config");
    println!("{}", bf.to_firewall().render());
}
