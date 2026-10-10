//! Allocateur IP premier-trou-libre.
//!
//! - Adresse serveur toujours `réseau start + 1` ([`server_address`]).
//! - Clients alloués de `start + 2` jusqu'à `end - 1`
//!   ([`first_free`], [`allocate_pair`]).
//! - Pool plein → [`IpAllocError::PoolExhausted`] explicite.
//! - Une famille desactivee (`IP_MODE`) est simplement omise par l'appelant
//!   (l'adresse de cette famille devient `None`).

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Erreur d'allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAllocError {
    /// CIDR illisible.
    InvalidCidr(String),
    /// Plus aucune adresse libre dans le pool client.
    PoolExhausted { cidr: String },
    /// Famille inattendue (v6 reçue pour un pool v4, etc.).
    FamilyMismatch { cidr: String },
    /// Adresse hors du pool client : adresse réseau, adresse serveur
    /// (`réseau + 1`), broadcast / dernière adresse v6, hors CIDR ou famille
    /// différente du CIDR.
    AddressNotInPool { address: IpAddr, cidr: String },
    /// Aucune des deux familles n'est active.
    NoPool,
}

impl fmt::Display for IpAllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCidr(cidr) => write!(f, "invalid CIDR `{cidr}`"),
            Self::PoolExhausted { cidr } => {
                write!(f, "IP pool exhausted in `{cidr}`: no free client address")
            }
            Self::FamilyMismatch { cidr } => {
                write!(f, "address family mismatch for pool `{cidr}`")
            }
            Self::AddressNotInPool { address, cidr } => write!(
                f,
                "address {address} is not a usable client address of pool `{cidr}` \
                 (network, server or broadcast)"
            ),
            Self::NoPool => write!(f, "no address family enabled"),
        }
    }
}

impl std::error::Error for IpAllocError {}

fn parse_cidr(cidr: &str) -> Result<IpNet, IpAllocError> {
    cidr.trim()
        .parse::<IpNet>()
        .map_err(|_| IpAllocError::InvalidCidr(cidr.to_string()))
}

/// Longueur du préfixe d'un CIDR (pour le rendu `Address = ip/préfixe`).
pub fn prefix_len(cidr: &str) -> Result<u8, IpAllocError> {
    Ok(parse_cidr(cidr)?.prefix_len())
}

/// Adresse du serveur : `réseau start + 1`.
pub fn server_address(cidr: &str) -> Result<IpAddr, IpAllocError> {
    let net = parse_cidr(cidr)?;
    match net {
        IpNet::V4(n) => {
            let base = u32::from(n.network());
            let server = base
                .checked_add(1)
                .ok_or_else(|| IpAllocError::PoolExhausted {
                    cidr: cidr.to_string(),
                })?;
            if server >= u32::from(n.broadcast()) {
                return Err(IpAllocError::PoolExhausted {
                    cidr: cidr.to_string(),
                });
            }
            Ok(IpAddr::V4(Ipv4Addr::from(server)))
        }
        IpNet::V6(n) => {
            let base = u128::from(n.network());
            let server = base
                .checked_add(1)
                .ok_or_else(|| IpAllocError::PoolExhausted {
                    cidr: cidr.to_string(),
                })?;
            if server >= last_v6(&n) {
                return Err(IpAllocError::PoolExhausted {
                    cidr: cidr.to_string(),
                });
            }
            Ok(IpAddr::V6(Ipv6Addr::from(server)))
        }
    }
}

/// Première adresse libre du pool client (`start + 2 .. end - 1`).
///
/// `used` contient les adresses déjà attribuées ; les adresses hors pool
/// ou d'une autre famille sont ignorées.
pub fn first_free(cidr: &str, used: &[IpAddr]) -> Result<IpAddr, IpAllocError> {
    let net = parse_cidr(cidr)?;
    match net {
        IpNet::V4(n) => {
            let lo = u32::from(n.network()).checked_add(2).ok_or_else(|| {
                IpAllocError::PoolExhausted {
                    cidr: cidr.to_string(),
                }
            })?;
            let hi = u32::from(n.broadcast()).saturating_sub(1);
            let taken: HashSet<u32> = used
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(u32::from(*v4)),
                    IpAddr::V6(_) => None,
                })
                .collect();
            first_free_int(lo, hi, &taken, cidr).map(|v| IpAddr::V4(Ipv4Addr::from(v)))
        }
        IpNet::V6(n) => {
            let lo = u128::from(n.network()).checked_add(2).ok_or_else(|| {
                IpAllocError::PoolExhausted {
                    cidr: cidr.to_string(),
                }
            })?;
            let hi = last_v6(&n).saturating_sub(1);
            let taken: HashSet<u128> = used
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(u128::from(*v6)),
                    IpAddr::V4(_) => None,
                })
                .collect();
            first_free_int(lo, hi, &taken, cidr).map(|v| IpAddr::V6(Ipv6Addr::from(v)))
        }
    }
}

fn first_free_int<T>(lo: T, hi: T, taken: &HashSet<T>, cidr: &str) -> Result<T, IpAllocError>
where
    T: Copy + PartialOrd + Eq + std::hash::Hash + AddrInt,
{
    if lo > hi {
        return Err(IpAllocError::PoolExhausted {
            cidr: cidr.to_string(),
        });
    }
    // Le premier trou se trouve au plus à `taken.len() + 1` pas de `lo` :
    // jamais d'énumération complète du pool (crucial en IPv6).
    let mut candidate = lo;
    let mut steps: usize = 0;
    loop {
        if !taken.contains(&candidate) {
            return Ok(candidate);
        }
        if candidate >= hi || steps >= taken.len() {
            return Err(IpAllocError::PoolExhausted {
                cidr: cidr.to_string(),
            });
        }
        candidate = candidate
            .succ()
            .ok_or_else(|| IpAllocError::PoolExhausted {
                cidr: cidr.to_string(),
            })?;
        steps += 1;
    }
}

/// Successeur arithmétique (+1) d'un entier d'adresse.
trait AddrInt {
    fn succ(self) -> Option<Self>
    where
        Self: Sized;
}

impl AddrInt for u32 {
    fn succ(self) -> Option<Self> {
        self.checked_add(1)
    }
}

impl AddrInt for u128 {
    fn succ(self) -> Option<Self> {
        self.checked_add(1)
    }
}

/// Dernière adresse (broadcast) d'un réseau IPv6, en entier 128 bits.
///
/// Formule unique réutilisée par l'allocateur ([`first_free`]) et par les
/// bornes de pool de la réaffectation (`src/web/backend/admin.rs`). Gère les
/// cas limites : `/0` renvoie [`u128::MAX`] (toutes les adresses), `/128`
/// renvoie l'adresse réseau elle-même (aucun bit d'hôte).
pub(crate) fn last_v6(net: &ipnet::Ipv6Net) -> u128 {
    let bits = 128 - net.prefix_len() as u32;
    if bits >= 128 {
        u128::MAX
    } else {
        u128::from(net.network()) | (u128::MAX >> (128 - bits))
    }
}

/// Vérifie qu'une adresse est une adresse client **utilisable** dans le pool
/// `cidr` : contenue dans le réseau, ni adresse réseau (`+0`), ni adresse
/// serveur (`réseau + 1`), ni broadcast (v4) / dernière adresse (v6). Une
/// famille différente du CIDR est aussi refusée.
///
/// Utilisé pour borner les `ipv4Address`/`ipv6Address` posées par patch :
/// sans ce contrôle un client pourrait s'attribuer l'adresse serveur ou
/// router le trafic hors de son pool.
pub fn validate_pool_address(addr: IpAddr, cidr: &str) -> Result<(), IpAllocError> {
    let net = parse_cidr(cidr)?;
    let not_in_pool = || IpAllocError::AddressNotInPool {
        address: addr,
        cidr: cidr.to_string(),
    };
    match (net, addr) {
        (IpNet::V4(n), IpAddr::V4(a)) => {
            let base = u32::from(n.network());
            let bcast = u32::from(n.broadcast());
            let a = u32::from(a);
            // `base + 2 ..= bcast - 1` : `<= base` couvre le réseau, `>= bcast`
            // le broadcast, et `base + 1` l'adresse serveur.
            if a <= base || a >= bcast || base.checked_add(1) == Some(a) {
                return Err(not_in_pool());
            }
        }
        (IpNet::V6(n), IpAddr::V6(a)) => {
            let base = u128::from(n.network());
            let last = last_v6(&n);
            let a = u128::from(a);
            if a <= base || a >= last || base.checked_add(1) == Some(a) {
                return Err(not_in_pool());
            }
        }
        _ => return Err(not_in_pool()),
    }
    Ok(())
}

/// Paire allouée à un nouveau client. Une famille desactivee (`None`) reste
/// `None` (`IP_MODE=ipv6` / `IP_MODE=ipv4`). Au moins une famille doit etre
/// active, sinon [`IpAllocError::NoPool`].
pub fn allocate_pair(
    v4_cidr: Option<&str>,
    v6_cidr: Option<&str>,
    used_v4: &[Ipv4Addr],
    used_v6: &[Ipv6Addr],
) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), IpAllocError> {
    if v4_cidr.is_none() && v6_cidr.is_none() {
        return Err(IpAllocError::NoPool);
    }
    let v4 = match v4_cidr {
        None => None,
        Some(cidr) => {
            let used4: Vec<IpAddr> = used_v4.iter().map(|ip| IpAddr::V4(*ip)).collect();
            match first_free(cidr, &used4)? {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => {
                    return Err(IpAllocError::FamilyMismatch {
                        cidr: cidr.to_string(),
                    });
                }
            }
        }
    };
    let v6 = match v6_cidr {
        None => None,
        Some(cidr) => {
            let used6: Vec<IpAddr> = used_v6.iter().map(|ip| IpAddr::V6(*ip)).collect();
            match first_free(cidr, &used6)? {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => {
                    return Err(IpAllocError::FamilyMismatch {
                        cidr: cidr.to_string(),
                    });
                }
            }
        }
    };
    Ok((v4, v6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_is_start_plus_one() {
        assert_eq!(
            server_address("10.8.0.0/24").expect("server"),
            IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))
        );
        assert_eq!(
            server_address("fdcc:ad94:bacf:61a4::cafe:0/112").expect("server6"),
            "fdcc:ad94:bacf:61a4::cafe:1".parse::<IpAddr>().expect("v6")
        );
    }

    #[test]
    fn clients_start_at_plus_two_and_fill_holes() {
        let v4 = |s: &str| s.parse::<IpAddr>().expect("ip");
        // Premier client : start+2.
        assert_eq!(
            first_free("10.8.0.0/24", &[]).expect("first"),
            v4("10.8.0.2")
        );
        // Trou réutilisé en premier.
        let used = vec![v4("10.8.0.2"), v4("10.8.0.4"), v4("10.8.0.1")];
        assert_eq!(
            first_free("10.8.0.0/24", &used).expect("hole"),
            v4("10.8.0.3")
        );
        // Adresses d'une autre famille / hors pool ignorées.
        let used = vec![v4("::1"), v4("192.168.99.9")];
        assert_eq!(
            first_free("10.8.0.0/24", &used).expect("ignored"),
            v4("10.8.0.2")
        );
    }

    #[test]
    fn full_pool_is_explicit() {
        // /30 : .0 réseau, .1 serveur, .2 seul client, .3 broadcast.
        let v4 = |s: &str| s.parse::<IpAddr>().expect("ip");
        assert_eq!(
            first_free("10.8.0.0/30", &[]).expect("slot"),
            v4("10.8.0.2")
        );
        let err = first_free("10.8.0.0/30", &[v4("10.8.0.2")]).unwrap_err();
        assert!(matches!(err, IpAllocError::PoolExhausted { .. }));
        assert!(err.to_string().contains("exhausted"));
        // /31 : aucun slot client.
        assert!(first_free("10.8.0.0/31", &[]).is_err());
    }

    #[test]
    fn v6_holes_without_enumeration() {
        let cidr = "fdcc:ad94:bacf:61a4::cafe:0/112";
        let used = vec!["fdcc:ad94:bacf:61a4::cafe:2".parse().expect("v6")];
        assert_eq!(
            first_free(cidr, &used).expect("hole"),
            "fdcc:ad94:bacf:61a4::cafe:3".parse::<IpAddr>().expect("v6")
        );
    }

    #[test]
    fn pair_respects_disable_ipv6() {
        let (v4, v6) = allocate_pair(Some("10.8.0.0/24"), None, &[], &[]).expect("pair");
        assert_eq!((v4, v6), (Some(Ipv4Addr::new(10, 8, 0, 2)), None));
        let (v4, v6) = allocate_pair(
            Some("10.8.0.0/24"),
            Some("fdcc:ad94:bacf:61a4::cafe:0/112"),
            &[Ipv4Addr::new(10, 8, 0, 2)],
            &[],
        )
        .expect("pair6");
        assert_eq!(v4, Some(Ipv4Addr::new(10, 8, 0, 3)));
        assert_eq!(
            v6.expect("v6"),
            "fdcc:ad94:bacf:61a4::cafe:2"
                .parse::<Ipv6Addr>()
                .expect("v6")
        );
    }

    #[test]
    fn pair_supports_ipv6_only_and_rejects_no_family() {
        let (v4, v6) = allocate_pair(
            None,
            Some("fdcc:ad94:bacf:61a4::cafe:0/112"),
            &[],
            &[Ipv6Addr::new(
                0xfdcc, 0xad94, 0xbacf, 0x61a4, 0, 0, 0xcafe, 2,
            )],
        )
        .expect("v6-only");
        assert_eq!(v4, None);
        assert_eq!(
            v6.expect("v6"),
            "fdcc:ad94:bacf:61a4::cafe:3"
                .parse::<Ipv6Addr>()
                .expect("v6")
        );
        assert_eq!(
            allocate_pair(None, None, &[], &[]).expect_err("no pool"),
            IpAllocError::NoPool
        );
    }

    #[test]
    fn bad_cidr_rejected() {
        assert!(matches!(
            first_free("not-a-cidr", &[]).unwrap_err(),
            IpAllocError::InvalidCidr(_)
        ));
    }

    #[test]
    fn pool_address_accepts_only_client_range() {
        let v4 = |s: &str| s.parse::<IpAddr>().expect("v4");
        // 10.8.0.0/24 : réseau .0, serveur .1, clients .2-.254, broadcast .255.
        assert!(validate_pool_address(v4("10.8.0.2"), "10.8.0.0/24").is_ok());
        assert!(validate_pool_address(v4("10.8.0.254"), "10.8.0.0/24").is_ok());
        for bad in ["10.8.0.0", "10.8.0.1", "10.8.0.255", "10.9.0.2"] {
            assert!(
                matches!(
                    validate_pool_address(v4(bad), "10.8.0.0/24"),
                    Err(IpAllocError::AddressNotInPool { .. })
                ),
                "doit refuser {bad}"
            );
        }
        // Famille différente -> refus.
        assert!(validate_pool_address(v4("10.8.0.2"), "fd00::/64").is_err());
        // CIDR illisible.
        assert!(matches!(
            validate_pool_address(v4("10.8.0.2"), "nope"),
            Err(IpAllocError::InvalidCidr(_))
        ));
    }

    #[test]
    fn pool_address_v6_rejects_network_server_and_last() {
        let v6 = |s: &str| s.parse::<IpAddr>().expect("v6");
        let cidr = "fdcc:ad94:bacf:61a4::cafe:0/112";
        assert!(validate_pool_address(v6("fdcc:ad94:bacf:61a4::cafe:2"), cidr).is_ok());
        for bad in [
            "fdcc:ad94:bacf:61a4::cafe:0",
            "fdcc:ad94:bacf:61a4::cafe:1",
            "fdcc:ad94:bacf:61a4::cafe:ffff",
        ] {
            assert!(
                matches!(
                    validate_pool_address(v6(bad), cidr),
                    Err(IpAllocError::AddressNotInPool { .. })
                ),
                "doit refuser {bad}"
            );
        }
    }
}
