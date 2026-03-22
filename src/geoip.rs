//! GeoIP-based traffic blocking.
//!
//! Generates nftables sets populated with CIDR ranges for country-based
//! blocking. Requires an external GeoIP CIDR database — this module
//! only handles the nftables rule generation from CIDR lists.

use crate::Firewall;
use crate::chain::{Chain, ChainType, Hook, Policy};
use crate::error::NeinError;
use crate::rule::{Match, Rule, Verdict};
use crate::set::{NftSet, SetFlag, SetType};
use crate::table::{Family, Table};
use crate::validate;
use serde::{Deserialize, Serialize};

/// A country block entry: country code + its CIDR ranges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryBlock {
    /// ISO 3166-1 alpha-2 country code (e.g., "CN", "RU").
    pub code: String,
    /// IPv4 CIDR ranges belonging to this country.
    pub cidrs_v4: Vec<String>,
    /// IPv6 CIDR ranges belonging to this country.
    pub cidrs_v6: Vec<String>,
}

impl CountryBlock {
    /// Create a new country block with IPv4 CIDRs.
    pub fn v4(code: &str, cidrs: Vec<String>) -> Self {
        Self {
            code: code.to_uppercase(),
            cidrs_v4: cidrs,
            cidrs_v6: vec![],
        }
    }

    /// Create a new country block with both IPv4 and IPv6 CIDRs.
    pub fn dual(code: &str, cidrs_v4: Vec<String>, cidrs_v6: Vec<String>) -> Self {
        Self {
            code: code.to_uppercase(),
            cidrs_v4,
            cidrs_v6,
        }
    }
}

/// GeoIP blocklist configuration.
#[derive(Debug, Clone)]
pub struct GeoIpBlocklist {
    /// Countries to block.
    countries: Vec<CountryBlock>,
    /// nftables table name (default: "nein_geoip").
    table_name: String,
    /// Chain hook (default: Input).
    hook: Hook,
}

impl GeoIpBlocklist {
    /// Create a new GeoIP blocklist.
    pub fn new() -> Self {
        Self {
            countries: vec![],
            table_name: "nein_geoip".to_string(),
            hook: Hook::Input,
        }
    }

    /// Set custom table name.
    pub fn table_name(mut self, name: &str) -> Self {
        self.table_name = name.to_string();
        self
    }

    /// Set the hook point (default: Input).
    pub fn hook(mut self, hook: Hook) -> Self {
        self.hook = hook;
        self
    }

    /// Add a country to block.
    pub fn block_country(&mut self, country: CountryBlock) {
        self.countries.push(country);
    }

    /// Access blocked countries.
    pub fn countries(&self) -> &[CountryBlock] {
        &self.countries
    }

    /// Validate all fields.
    pub fn validate(&self) -> Result<(), NeinError> {
        validate::validate_identifier(&self.table_name)?;
        for country in &self.countries {
            if country.code.len() != 2 || !country.code.chars().all(|c| c.is_ascii_uppercase()) {
                return Err(NeinError::InvalidRule(format!(
                    "invalid country code: {} (expected 2-letter uppercase)",
                    country.code
                )));
            }
            for cidr in &country.cidrs_v4 {
                validate::validate_addr(cidr)?;
            }
            for cidr in &country.cidrs_v6 {
                validate::validate_addr(cidr)?;
            }
        }
        Ok(())
    }

    /// Generate the nftables `Firewall` for GeoIP blocking.
    ///
    /// Creates sets for each blocked country's CIDRs, then rules that
    /// drop traffic matching those sets.
    pub fn to_firewall(&self) -> Firewall {
        let mut fw = Firewall::new();

        if self.countries.is_empty() {
            return fw;
        }

        // IPv4 table
        let has_v4 = self.countries.iter().any(|c| !c.cidrs_v4.is_empty());
        if has_v4 {
            fw.add_table(self.build_table(Family::Ip, false));
        }

        // IPv6 table
        let has_v6 = self.countries.iter().any(|c| !c.cidrs_v6.is_empty());
        if has_v6 {
            fw.add_table(self.build_table(Family::Ip6, true));
        }

        fw
    }

    fn build_table(&self, family: Family, v6: bool) -> Table {
        let suffix = if v6 { "_v6" } else { "" };
        let mut table = Table::new(&format!("{}{suffix}", self.table_name), family);

        let mut chain = Chain::base(
            "geoblock",
            ChainType::Filter,
            self.hook,
            -10,
            Policy::Accept,
        );

        for country in &self.countries {
            let cidrs = if v6 {
                &country.cidrs_v6
            } else {
                &country.cidrs_v4
            };
            if cidrs.is_empty() {
                continue;
            }

            let set_name = format!("geo_{}", country.code.to_lowercase());
            let set_type = if v6 {
                SetType::Ipv6Addr
            } else {
                SetType::Ipv4Addr
            };

            let mut set = NftSet::new(&set_name, set_type).flag(SetFlag::Interval);
            for cidr in cidrs {
                set = set.element(cidr);
            }
            table.add_set(set);

            let field = if v6 { "ip6 saddr" } else { "ip saddr" };
            chain.add_rule(
                Rule::new(Verdict::Drop)
                    .matching(Match::SetLookup {
                        field: field.to_string(),
                        set_name: set_name.clone(),
                    })
                    .comment(&format!("geoblock {}", country.code)),
            );
        }

        table.add_chain(chain);
        table
    }
}

impl Default for GeoIpBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blocklist() {
        let bl = GeoIpBlocklist::new();
        let fw = bl.to_firewall();
        assert_eq!(fw.render(), "");
    }

    #[test]
    fn single_country_v4() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::v4(
            "CN",
            vec!["1.0.0.0/8".into(), "2.0.0.0/8".into()],
        ));

        let fw = bl.to_firewall();
        let rendered = fw.render();

        assert!(rendered.contains("table ip nein_geoip"));
        assert!(rendered.contains("set geo_cn"));
        assert!(rendered.contains("type ipv4_addr"));
        assert!(rendered.contains("flags interval"));
        assert!(rendered.contains("1.0.0.0/8, 2.0.0.0/8"));
        assert!(rendered.contains("ip saddr @geo_cn drop"));
        assert!(rendered.contains("geoblock CN"));
    }

    #[test]
    fn dual_stack() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::dual(
            "RU",
            vec!["5.0.0.0/8".into()],
            vec!["2a00::/12".into()],
        ));

        let fw = bl.to_firewall();
        let rendered = fw.render();

        assert!(rendered.contains("table ip nein_geoip"));
        assert!(rendered.contains("table ip6 nein_geoip_v6"));
        assert!(rendered.contains("type ipv4_addr"));
        assert!(rendered.contains("type ipv6_addr"));
        assert!(rendered.contains("ip saddr @geo_ru"));
        assert!(rendered.contains("ip6 saddr @geo_ru"));
    }

    #[test]
    fn multiple_countries() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::v4("CN", vec!["1.0.0.0/8".into()]));
        bl.block_country(CountryBlock::v4("RU", vec!["5.0.0.0/8".into()]));

        let rendered = bl.to_firewall().render();
        assert!(rendered.contains("set geo_cn"));
        assert!(rendered.contains("set geo_ru"));
        assert!(rendered.contains("geoblock CN"));
        assert!(rendered.contains("geoblock RU"));
    }

    #[test]
    fn custom_table_name() {
        let mut bl = GeoIpBlocklist::new().table_name("aegis_geo");
        bl.block_country(CountryBlock::v4("CN", vec!["1.0.0.0/8".into()]));
        let rendered = bl.to_firewall().render();
        assert!(rendered.contains("table ip aegis_geo"));
    }

    #[test]
    fn custom_hook() {
        let mut bl = GeoIpBlocklist::new().hook(Hook::Forward);
        bl.block_country(CountryBlock::v4("CN", vec!["1.0.0.0/8".into()]));
        let rendered = bl.to_firewall().render();
        assert!(rendered.contains("hook forward"));
    }

    #[test]
    fn validate_good() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::v4("US", vec!["3.0.0.0/8".into()]));
        assert!(bl.validate().is_ok());
    }

    #[test]
    fn validate_bad_country_code() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::v4("invalid", vec!["1.0.0.0/8".into()]));
        assert!(bl.validate().is_err());
    }

    #[test]
    fn validate_bad_cidr() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::v4("CN", vec!["evil;cidr".into()]));
        assert!(bl.validate().is_err());
    }

    #[test]
    fn validate_bad_v6_cidr() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::dual("RU", vec![], vec!["evil;v6".into()]));
        assert!(bl.validate().is_err());
    }

    #[test]
    fn validate_bad_table() {
        let bl = GeoIpBlocklist::new().table_name("bad;table");
        assert!(bl.validate().is_err());
    }

    #[test]
    fn v6_only_country() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::dual("JP", vec![], vec!["2001::/16".into()]));

        let fw = bl.to_firewall();
        let rendered = fw.render();

        // Only v6 table, no v4
        assert!(!rendered.contains("table ip nein_geoip {"));
        assert!(rendered.contains("table ip6 nein_geoip_v6"));
    }

    #[test]
    fn firewall_validates() {
        let mut bl = GeoIpBlocklist::new();
        bl.block_country(CountryBlock::v4("US", vec!["3.0.0.0/8".into()]));
        let fw = bl.to_firewall();
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn default_impl() {
        let bl = GeoIpBlocklist::default();
        assert!(bl.countries().is_empty());
    }
}
