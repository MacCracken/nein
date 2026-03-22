//! Fluent builder for common firewall configurations.

use crate::Firewall;
use crate::chain::{Chain, ChainType, Hook, Policy};
use crate::nat;
use crate::rule::{self, Match, Protocol, Rule, Verdict};
use crate::table::{Family, Table};

/// Build a basic host firewall (allow established, SSH, drop rest).
pub fn basic_host_firewall() -> Firewall {
    let mut fw = Firewall::new();

    let mut table = Table::new("filter", Family::Inet);
    let mut input = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Drop);

    input.add_rule(rule::allow_established());
    input.add_rule(Rule::new(Verdict::Accept).matching(Match::Iif("lo".to_string())));
    input.add_rule(rule::allow_tcp(22).comment("SSH"));

    let output = Chain::base("output", ChainType::Filter, Hook::Output, 0, Policy::Accept);

    table.add_chain(input);
    table.add_chain(output);
    fw.add_table(table);
    fw
}

/// Build container bridge networking rules.
pub fn container_bridge(bridge_name: &str, subnet: &str, outbound_iface: &str) -> Firewall {
    let mut fw = Firewall::new();

    let mut filter = Table::new("filter", Family::Inet);
    let mut forward = Chain::base("forward", ChainType::Filter, Hook::Forward, 0, Policy::Drop);

    forward.add_rule(rule::allow_established());
    forward.add_rule(
        Rule::new(Verdict::Accept)
            .matching(Match::Iif(bridge_name.to_string()))
            .matching(Match::Oif(outbound_iface.to_string()))
            .comment("container to internet"),
    );
    forward.add_rule(
        Rule::new(Verdict::Accept)
            .matching(Match::Iif(bridge_name.to_string()))
            .matching(Match::Oif(bridge_name.to_string()))
            .comment("container to container"),
    );

    filter.add_chain(forward);
    fw.add_table(filter);

    let mut nat_table = Table::new("nat", Family::Ip);
    let mut postrouting = Chain::base(
        "postrouting",
        ChainType::Nat,
        Hook::Postrouting,
        100,
        Policy::Accept,
    );

    let masq = nat::container_masquerade(subnet, outbound_iface);
    postrouting.add_rule(Rule::new(Verdict::Accept).matching(Match::Raw(masq.render())));

    nat_table.add_chain(postrouting);
    fw.add_table(nat_table);

    fw
}

/// Build agent-to-agent service policy rules.
pub fn service_policy(agent_source: &str, ports: &[(Protocol, u16)]) -> Firewall {
    let mut fw = Firewall::new();
    let mut table = Table::new("agnos_policy", Family::Inet);
    let mut chain = Chain::regular("agent_access");

    for (proto, port) in ports {
        chain.add_rule(rule::allow_service(agent_source, *proto, *port));
    }

    table.add_chain(chain);
    fw.add_table(table);
    fw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_host_firewall_renders() {
        let fw = basic_host_firewall();
        let rendered = fw.render();
        assert!(rendered.contains("table inet filter"));
        assert!(rendered.contains("policy drop"));
        assert!(rendered.contains("ct state { established, related } accept"));
        assert!(rendered.contains("dport 22 accept"));
    }

    #[test]
    fn container_bridge_renders() {
        let fw = container_bridge("br0", "172.17.0.0/16", "eth0");
        let rendered = fw.render();
        assert!(rendered.contains("table inet filter"));
        assert!(rendered.contains("table ip nat"));
        assert!(rendered.contains("container to internet"));
        assert!(rendered.contains("masquerade"));
    }

    #[test]
    fn service_policy_renders() {
        let fw = service_policy("10.0.0.1", &[(Protocol::Tcp, 8090)]);
        let rendered = fw.render();
        assert!(rendered.contains("ip saddr 10.0.0.1"));
        assert!(rendered.contains("dport 8090"));
    }
}
