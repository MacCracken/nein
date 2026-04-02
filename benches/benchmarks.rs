use criterion::{Criterion, black_box, criterion_group, criterion_main};
use nein::Firewall;
use nein::bridge::{BridgeConfig, BridgeFirewall, IsolationGroup, PortMapping};
use nein::chain::{Chain, ChainType, Hook, Policy};
use nein::engine::{AgentPolicy, PolicyEngine, PortSpec};
use nein::geoip::{CountryBlock, GeoIpBlocklist};
use nein::mesh::SidecarConfig;
use nein::nat;
use nein::policy;
use nein::rule::{
    self, Ipv6ExtHdr, LogLevel, Match, PktType, Protocol, QuotaMode, QuotaUnit, RateUnit, Rule,
    Verdict,
};
use nein::set::{NftSet, SetFlag, SetType};
use nein::table::{CtTimeout, Define, Family, Flowtable, Table};

// -- Core rule benchmarks --

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

fn bench_rule_complex(c: &mut Criterion) {
    let rule = Rule::new(Verdict::Accept)
        .matching(Match::SourceAddr6("2001:db8::/32".into()))
        .matching(Match::Protocol(Protocol::Tcp))
        .matching(Match::TcpFlags(vec!["syn".into()]))
        .matching(Match::DPort(443))
        .matching(Match::Limit {
            rate: 100,
            unit: RateUnit::Second,
            burst: 200,
        })
        .matching(Match::MetaMark(42))
        .comment("complex rule bench");

    c.bench_function("rule_complex_render", |b| {
        b.iter(|| black_box(rule.render()));
    });

    c.bench_function("rule_complex_validate", |b| {
        b.iter(|| black_box(rule.validate()).unwrap());
    });
}

fn bench_nat_render(c: &mut Criterion) {
    let rule = nat::port_forward(8080, "172.17.0.2", 80);
    c.bench_function("nat_render", |b| {
        b.iter(|| black_box(rule.render()));
    });
}

// -- Builder benchmarks --

fn bench_host_firewall_render(c: &mut Criterion) {
    let fw = nein::builder::basic_host_firewall();
    c.bench_function("host_firewall_render", |b| {
        b.iter(|| black_box(fw.render()));
    });
}

// -- Bridge benchmarks --

fn bench_bridge_firewall_small(c: &mut Criterion) {
    let mut bf = BridgeFirewall::new(BridgeConfig::new("br0", "172.17.0.0/16", "eth0"));
    bf.add_port_mapping(PortMapping::tcp(8080, "172.17.0.2", 80))
        .unwrap();
    bf.add_port_mapping(PortMapping::tcp(8443, "172.17.0.2", 443))
        .unwrap();

    c.bench_function("bridge_small_to_firewall", |b| {
        b.iter(|| black_box(bf.to_firewall()));
    });

    let fw = bf.to_firewall();
    c.bench_function("bridge_small_render", |b| {
        b.iter(|| black_box(fw.render()));
    });
}

fn bench_bridge_firewall_large(c: &mut Criterion) {
    let mut bf = BridgeFirewall::new(BridgeConfig::new("br0", "172.17.0.0/16", "eth0"));

    for i in 0..50u16 {
        bf.add_port_mapping(PortMapping::tcp(
            8000 + i,
            &format!("172.17.0.{}", 2 + (i % 254)),
            80,
        ))
        .unwrap();
    }
    for i in 0..5 {
        bf.add_isolation_group(IsolationGroup::new(
            &format!("group{i}"),
            vec![format!("172.17.{}.0/24", i + 1)],
        ));
    }

    c.bench_function("bridge_large_to_firewall", |b| {
        b.iter(|| black_box(bf.to_firewall()));
    });

    let fw = bf.to_firewall();
    c.bench_function("bridge_large_render", |b| {
        b.iter(|| black_box(fw.render()));
    });
}

// -- Policy engine benchmarks --

fn bench_engine(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();
    for i in 0..10 {
        engine.add_agent(
            AgentPolicy::new(&format!("agent-{i}"), &format!("10.100.{i}.2"))
                .allow_inbound(PortSpec::tcp(80))
                .allow_inbound(PortSpec::tcp(443))
                .allow_outbound(PortSpec::tcp(8090))
                .allow_outbound(PortSpec::udp(53)),
        );
    }

    c.bench_function("engine_10_agents_to_firewall", |b| {
        b.iter(|| black_box(engine.to_firewall()));
    });

    let fw = engine.to_firewall();
    c.bench_function("engine_10_agents_render", |b| {
        b.iter(|| black_box(fw.render()));
    });

    c.bench_function("engine_10_agents_validate", |b| {
        b.iter(|| black_box(engine.validate()).unwrap());
    });
}

fn bench_policy_to_rules(c: &mut Criterion) {
    let pol = policy::agent_to_agent("bench-policy", "10.0.0.1", "10.0.0.2", Protocol::Tcp, 8090);
    c.bench_function("policy_to_rules", |b| {
        b.iter(|| black_box(pol.to_rules()));
    });
}

// -- Mesh benchmarks --

fn bench_mesh(c: &mut Criterion) {
    let cfg = SidecarConfig::envoy()
        .exclude_outbound_cidr("10.0.0.0/8")
        .exclude_outbound_port(9090)
        .exclude_inbound_port(15090);

    c.bench_function("mesh_to_firewall", |b| {
        b.iter(|| black_box(cfg.to_firewall()));
    });

    let fw = cfg.to_firewall();
    c.bench_function("mesh_render", |b| {
        b.iter(|| black_box(fw.render()));
    });
}

// -- GeoIP benchmarks --

fn bench_geoip(c: &mut Criterion) {
    let mut bl = GeoIpBlocklist::new();
    for i in 0..10 {
        let mut cidrs = vec![];
        for j in 0..50 {
            cidrs.push(format!("{i}.{j}.0.0/16"));
        }
        bl.block_country(CountryBlock::v4(
            &format!("{}{}", (b'A' + i) as char, (b'A' + i) as char),
            cidrs,
        ));
    }

    c.bench_function("geoip_10_countries_to_firewall", |b| {
        b.iter(|| black_box(bl.to_firewall()));
    });

    let fw = bl.to_firewall();
    c.bench_function("geoip_10_countries_render", |b| {
        b.iter(|| black_box(fw.render()));
    });
}

// -- Set benchmarks --

fn bench_set(c: &mut Criterion) {
    let mut set = NftSet::new("blocklist", SetType::Ipv4Addr).flag(SetFlag::Interval);
    for i in 0..1000 {
        set = set.element(&format!("{}.{}.0.0/16", i / 256, i % 256));
    }

    c.bench_function("set_1000_elements_render", |b| {
        b.iter(|| black_box(set.render()));
    });
}

// -- TOML config benchmarks --

fn bench_toml_parse(c: &mut Criterion) {
    let toml = r#"
[[tables]]
name = "filter"
family = "inet"

[[tables.chains]]
name = "input"
chain_type = "filter"
hook = "input"
priority = 0
policy = "drop"

[[tables.chains.rules]]
matches = [{ type = "ct_state", states = ["established", "related"] }]
verdict = "accept"

[[tables.chains.rules]]
matches = [{ type = "protocol", value = "tcp" }, { type = "dport", port = 22 }]
verdict = "accept"
comment = "SSH"

[[tables.chains.rules]]
matches = [{ type = "protocol", value = "tcp" }, { type = "dport", port = 80 }]
verdict = "accept"

[[tables.chains.rules]]
matches = [{ type = "protocol", value = "tcp" }, { type = "dport", port = 443 }]
verdict = "accept"
"#;

    c.bench_function("toml_parse_small", |b| {
        b.iter(|| black_box(nein::config::from_toml(toml)).unwrap());
    });
}

// -- Validation benchmark --

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

// -- Phase 4 benchmarks --

fn bench_define_render(c: &mut Criterion) {
    let mut table = Table::new("filter", Family::Inet);
    for i in 0..20 {
        table.add_define(Define::new(&format!("VAR_{i}"), &format!("10.0.{i}.0/24")));
    }
    c.bench_function("table_20_defines_render", |b| {
        b.iter(|| black_box(table.render()));
    });
}

fn bench_flowtable_render(c: &mut Criterion) {
    let ft = Flowtable::new(
        "ft",
        0,
        vec!["eth0".into(), "eth1".into(), "eth2".into(), "eth3".into()],
    );
    c.bench_function("flowtable_render", |b| {
        b.iter(|| black_box(ft.render()));
    });
}

fn bench_ct_timeout_render(c: &mut Criterion) {
    let ct = CtTimeout::new("tcp-long", Protocol::Tcp)
        .l3proto(Family::Ip)
        .timeout("established", 7200)
        .timeout("close_wait", 60)
        .timeout("time_wait", 120);
    c.bench_function("ct_timeout_render", |b| {
        b.iter(|| black_box(ct.render()));
    });
}

fn bench_quota_render(c: &mut Criterion) {
    let rule = Rule::new(Verdict::Drop)
        .matching(Match::Protocol(Protocol::Tcp))
        .matching(Match::DPort(80))
        .matching(Match::Quota {
            mode: QuotaMode::Over,
            amount: 25,
            unit: QuotaUnit::MBytes,
        })
        .comment("rate limit");
    c.bench_function("quota_rule_render", |b| {
        b.iter(|| black_box(rule.render()));
    });
}

fn bench_nat_range_render(c: &mut Criterion) {
    let rule = nat::port_range_forward(80, 99, "172.17.0.2", 8080);
    c.bench_function("nat_range_render", |b| {
        b.iter(|| black_box(rule.render()));
    });
}

fn bench_deep_protocol_rule(c: &mut Criterion) {
    let rule = Rule::new(Verdict::LogAdvanced {
        prefix: Some("DEEP: ".into()),
        level: Some(LogLevel::Warn),
        group: None,
        snaplen: Some(128),
    })
    .matching(Match::PktType(PktType::Broadcast))
    .matching(Match::VlanId(100))
    .matching(Match::Dscp(46))
    .matching(Match::Ipv6ExtHdrExists(Ipv6ExtHdr::Fragment))
    .matching(Match::IcmpTypeCode("echo-request".into(), 0))
    .comment("deep protocol bench");

    c.bench_function("deep_protocol_render", |b| {
        b.iter(|| black_box(rule.render()));
    });

    c.bench_function("deep_protocol_validate", |b| {
        b.iter(|| black_box(rule.validate()).unwrap());
    });
}

// -- Scale benchmarks --

fn bench_1000_rule_firewall(c: &mut Criterion) {
    let mut fw = Firewall::new();
    let mut table = Table::new("scale", Family::Inet);
    let mut chain = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Drop);
    for i in 0..1000u16 {
        chain.add_rule(rule::allow_tcp(1000 + i).comment(&format!("rule {i}")));
    }
    table.add_chain(chain);
    fw.add_table(table);

    c.bench_function("firewall_1000_rules_render", |b| {
        b.iter(|| black_box(fw.render()));
    });

    c.bench_function("firewall_1000_rules_validate", |b| {
        b.iter(|| black_box(fw.validate()).unwrap());
    });
}

fn bench_100_agent_engine(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();
    for i in 0..100 {
        engine.add_agent(
            AgentPolicy::new(
                &format!("agent-{i}"),
                &format!("10.{}.{}.2", i / 256, i % 256),
            )
            .allow_inbound(PortSpec::tcp(80))
            .allow_inbound(PortSpec::tcp(443))
            .allow_outbound(PortSpec::tcp(8090))
            .allow_outbound(PortSpec::udp(53))
            .allow_outbound(PortSpec::quic(443)),
        );
    }

    c.bench_function("engine_100_agents_to_firewall", |b| {
        b.iter(|| black_box(engine.to_firewall()));
    });

    let fw = engine.to_firewall();
    c.bench_function("engine_100_agents_render", |b| {
        b.iter(|| black_box(fw.render()));
    });

    c.bench_function("engine_100_agents_validate", |b| {
        b.iter(|| black_box(engine.validate()).unwrap());
    });
}

criterion_group!(
    benches,
    bench_rule_render,
    bench_rule_validate,
    bench_rule_complex,
    bench_nat_render,
    bench_host_firewall_render,
    bench_bridge_firewall_small,
    bench_bridge_firewall_large,
    bench_engine,
    bench_policy_to_rules,
    bench_mesh,
    bench_geoip,
    bench_set,
    bench_toml_parse,
    bench_firewall_validate,
    bench_define_render,
    bench_flowtable_render,
    bench_ct_timeout_render,
    bench_quota_render,
    bench_nat_range_render,
    bench_deep_protocol_rule,
    bench_1000_rule_firewall,
    bench_100_agent_engine,
);
criterion_main!(benches);
