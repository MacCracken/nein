//! Agent network policy engine example.
//!
//! Demonstrates `PolicyEngine` managing per-agent firewall policies
//! with inbound/outbound port control and host restrictions.

use nein::engine::{AgentPolicy, PolicyEngine, PortSpec};

fn main() {
    let mut engine = PolicyEngine::new();

    // Web agent: accept inbound HTTP/HTTPS, outbound to API
    engine.add_agent(
        AgentPolicy::new("web-agent", "10.100.1.2")
            .allow_inbound(PortSpec::tcp(80))
            .allow_inbound(PortSpec::tcp(443))
            .allow_outbound(PortSpec::tcp(8090))
            .allow_outbound_host("10.100.2.0/24"),
    );

    // Database agent: accept inbound PostgreSQL from web agent only
    engine.add_agent(AgentPolicy::new("db-agent", "10.100.2.3").allow_inbound(PortSpec::tcp(5432)));

    engine.validate().expect("validate policies");
    println!("{}", engine.to_firewall().render());
}
