//! This module exports a DNS resolver, which is also the default resolver used in the
//! [`crate::Endpoint`] if no custom resolver is configured.
//!
//! The resolver provides methods to resolve domain names to ipv4 and ipv6 addresses,
//! and to resolve endpoint ids to endpoint addresses.
//!
//! See the [`endpoint_info`](crate::endpoint_info) module documentation for details on how
//! iroh endpoint records are structured.

pub use iroh_relay::dns::{
    DnsResolver, N0_DNS_ENDPOINT_ORIGIN_PROD, N0_DNS_ENDPOINT_ORIGIN_STAGING,
};

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use n0_tracing_test::traced_test;

    use super::DnsResolver;
    use crate::defaults::staging::NA_EAST_RELAY_HOSTNAME;

    const TIMEOUT: Duration = Duration::from_secs(5);
    const STAGGERING_DELAYS: &[u64] = &[200, 300];

    #[tokio::test]
    #[traced_test]
    async fn test_dns_lookup_ipv4_ipv6() {
        let resolver = DnsResolver::new();
        let res: Vec<_> = resolver
            .lookup_ipv4_ipv6_staggered(NA_EAST_RELAY_HOSTNAME, TIMEOUT, STAGGERING_DELAYS)
            .await
            .unwrap()
            .collect();
        assert!(!res.is_empty());
        dbg!(res);
    }

    /// The lookups keep only the record type that was asked for, so an answer section cannot
    /// smuggle records of another type into the result (GHSA-6f2x-v7q7-m7m5, the filters ported
    /// from upstream iroh #4117).
    ///
    /// The test nameserver answers a TXT query with an extra `A` record and an `A` query with an
    /// extra TXT record, both under the queried name. hickory hands that answer section on
    /// unchanged, so dropping the record of the wrong type is the resolver's own work and this
    /// test fails without the filters. In hickory-resolver 0.26.3 that path is:
    ///
    /// - `src/caching_client.rs:417` computes `needs_filtering` from the CNAME chain only — with
    ///   no CNAME in the answer and nothing carried over from an earlier hop it is `false`, and
    ///   the message is returned "as-is" to "preserve all sections exactly as DNS server sent
    ///   them" (`src/caching_client.rs:415`, returned at `:462`). The one place hickory rewrites
    ///   the answer section by record type, `:456`, is reached only when `needs_filtering` holds.
    /// - `src/caching_client.rs:531` builds the `Lookup` from that message; the only thing done
    ///   to the records on the way is a TTL clamp (`src/cache.rs:128`).
    /// - `src/lookup.rs:88` hands `message.answers` back verbatim, which is what
    ///   `iroh_relay::dns` filters.
    #[tokio::test]
    #[traced_test]
    async fn test_lookup_keeps_only_the_queried_record_type() {
        use std::net::{IpAddr, Ipv4Addr};

        use hickory_resolver::proto::{
            op::Message,
            rr::{
                RData, Record, RecordType,
                rdata::{A, TXT},
            },
        };

        use crate::test_utils::dns_server::{QueryHandler, run_dns_server};

        const HOST: &str = "mixed.example.";
        const TTL: u32 = 30;
        const ADDR: A = A::new(10, 0, 0, 1);
        const TXT_VALUE: &str = "hello";

        /// Answers every TXT and `A` query with the record asked for plus one of the other type.
        struct MixedTypes;

        impl QueryHandler for MixedTypes {
            fn resolve(
                &self,
                query: &Message,
                reply: &mut Message,
            ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
                for query in &query.queries {
                    let name = query.name().clone();
                    let txt = Record::from_rdata(
                        name.clone(),
                        TTL,
                        RData::TXT(TXT::new(vec![TXT_VALUE.to_string()])),
                    );
                    let a = Record::from_rdata(name, TTL, RData::A(ADDR));
                    match query.query_type() {
                        RecordType::TXT => {
                            reply.add_answer(a);
                            reply.add_answer(txt);
                        }
                        RecordType::A => {
                            reply.add_answer(txt);
                            reply.add_answer(a);
                        }
                        _ => {}
                    }
                }
                std::future::ready(Ok(()))
            }
        }

        let (nameserver, _dns_drop_guard) =
            run_dns_server(MixedTypes).await.expect("run dns server");
        let resolver = DnsResolver::with_nameserver(nameserver);

        let txt: Vec<String> = resolver
            .lookup_txt(HOST, TIMEOUT)
            .await
            .expect("txt lookup")
            .map(|record| record.to_string())
            .collect();
        assert_eq!(
            txt,
            vec![TXT_VALUE.to_string()],
            "the A record must be dropped from a TXT lookup"
        );

        let addrs: Vec<IpAddr> = resolver
            .lookup_ipv4(HOST, TIMEOUT)
            .await
            .expect("ipv4 lookup")
            .collect();
        assert_eq!(
            addrs,
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            "the TXT record must be dropped from an IPv4 lookup"
        );
    }
}
