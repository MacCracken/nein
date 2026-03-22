use criterion::{Criterion, black_box, criterion_group, criterion_main};
use nein::Firewall;
use nein::bridge::{BridgeConfig, BridgeFirewall, IsolationGroup, PortMapping};
use nein::chain::{Chain, ChainType, Hook, Policy};
use nein::nat;
use nein::policy;
use nein::rule::{self, Match, Protocol, Rule, Verdict};
use nein::table::{Family, Table};

fn bench_rule_render(c: &mut Criterion) {
    let rule =
        rule::allow_service("192.168.1.0/24", Protocol::Tcp, 8090).comment("bench service rule");

    c.bench_function("rule_render", |b| {
        b.iter(|| black_box(rule.render()));
    });
}

fn bench_rule_validate(c: &mut Criterion) {
    let rule = Rule::new(Verdict::Accept)
        .matching(Match::SourceAddr("10.0.0.0/8".into()))
        .matching(Match::Protocol(Protocol::Tcp))
        .matching(Match::DPort(443))
        .matching(Match::Iif("eth0".into()))
        .matching(Match::CtState(vec!["established".into(), "related".into()]))
        .comment("bench validation");

    c.bench_function("rule_validate", |b| {
        b.iter(|| black_box(rule.validate()).unwrap());
    });
}

fn bench_nat_render(c: &mut Criterion) {
    let rule = nat::port_forward(8080, "172.17.0.2", 80);
    c.bench_function("nat_render", |b| {
        b.iter(|| black_box(rule.render()));
    });
}

fn bench_host_firewall_render(c: &mut Criterion) {
    let fw = nein::builder::basic_host_firewall();
    c.bench_function("host_firewall_render", |b| {
        b.iter(|| black_box(fw.render()));
    });
}

fn bench_bridge_firewall_small(c: &mut Criterion) {
    let mut bf = BridgeFirewall::new(BridgeConfig::new("br0", "172.17.0.0/16", "eth0"));
    bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
        .unwrap();
    bf.add_port_mapping(PortMapping::tcp(8443, "172.17.0.2", 443))
        .unwrap();

    c.bench_function("bridge_firewall_small_to_firewall", |b| {
        b.iter(|| black_box(bf.to_firewall()));
    });

    let fw = bf.to_firewall();
    c.bench_function("bridge_firewall_small_render", |b| {
        b.iter(|| black_box(fw.render()));
    });

    c.bench_function("bridge_firewall_small_validate", |b| {
        b.iter(|| black_box(bf.validate()).unwrap());
    });
}

fn bench_bridge_firewall_large(c: &mut Criterion) {
    let mut bf = BridgeFirewall::new(BridgeConfig::new("br0", "172.17.0.0/16", "eth0"));

    // 50 port mappings
    for i in 0..50u16 {
        bf.add_port_mapping(PortMapping::tcp(
            8000 + i,
            &format!("172.17.0.{}", 2 + (i % 254)),
            80,
        ))
        .unwrap();
    }

    // 5 isolation groups
    for i in 0..5 {
        bf.add_isolation_group(IsolationGroup::new(
            &format!("group{i}"),
            vec![format!("172.17.{}.0/24", i + 1)],
        ));
    }

    c.bench_function("bridge_firewall_large_to_firewall", |b| {
        b.iter(|| black_box(bf.to_firewall()));
    });

    let fw = bf.to_firewall();
    c.bench_function("bridge_firewall_large_render", |b| {
        b.iter(|| black_box(fw.render()));
    });

    c.bench_function("bridge_firewall_large_validate", |b| {
        b.iter(|| black_box(bf.validate()).unwrap());
    });
}

fn bench_policy_to_rules(c: &mut Criterion) {
    let pol = policy::agent_to_agent("bench-policy", "10.0.0.1", "10.0.0.2", Protocol::Tcp, 8090);
    c.bench_function("policy_to_rules", |b| {
        b.iter(|| black_box(pol.to_rules()));
    });
}

fn bench_firewall_validate(c: &mut Criterion) {
    let mut fw = Firewall::new();
    let mut table = Table::new("bench", Family::Inet);
    let mut chain = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Drop);
    for i in 0..100u16 {
        chain.add_rule(rule::allow_tcp(1000 + i));
    }
    table.add_chain(chain);
    fw.add_table(table);

    c.bench_function("firewall_validate_100_rules", |b| {
        b.iter(|| black_box(fw.validate()).unwrap());
    });
}

criterion_group!(
    benches,
    bench_rule_render,
    bench_rule_validate,
    bench_nat_render,
    bench_host_firewall_render,
    bench_bridge_firewall_small,
    bench_bridge_firewall_large,
    bench_policy_to_rules,
    bench_firewall_validate,
);
criterion_main!(benches);
