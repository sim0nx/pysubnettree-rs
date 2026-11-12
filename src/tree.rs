//! The subnet tree: an IPv4 and an IPv6 prefix table sharing one value store, and the strings
//! of the values.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::strings::{StringSet, Strings};
use crate::table::{Addr, PrefixTable};
use crate::value::{
    DecodeError, Refs, TypeDesc, Value, ValueRef, ValueStore, decode, encode, remap_strings, visit_strings,
};

/// An IP network (network address with host bits cleared, prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Network {
    V4(u32, u8),
    V6(u128, u8),
}

/// A single IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address {
    V4(u32),
    V6(u128),
}

/// `::ffff:0:0/96` shifted right by 32 bits.
const MAPPED_PREFIX: u128 = 0xffff;

impl Address {
    /// Converts an address, IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) become IPv4.
    #[must_use]
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(a) => Self::V4(u32::from(a)),
            IpAddr::V6(a) => {
                let v = u128::from(a);
                if v >> 32 == MAPPED_PREFIX { Self::V4(v as u32) } else { Self::V6(v) }
            }
        }
    }

    /// Parses an address from its packed (big endian) 4 or 16 byte representation.
    #[must_use]
    pub fn from_packed(b: &[u8]) -> Option<Self> {
        ip_from_packed(b).map(Self::from_ip)
    }
}

impl Network {
    /// Builds a network, clearing host bits. IPv4-mapped IPv6 networks (`::ffff:0:0/96` and
    /// longer) become IPv4 networks.
    ///
    /// # Errors
    /// If the prefix length is too large for the address family.
    pub fn new(ip: IpAddr, len: u8) -> Result<Self, ParseError> {
        match ip {
            IpAddr::V4(a) if len <= 32 => Ok(Self::V4(u32::from(a).network(len), len)),
            IpAddr::V6(a) if len <= 128 => {
                let v = u128::from(a);
                if len >= 96 && v >> 32 == MAPPED_PREFIX {
                    Ok(Self::V4((v as u32).network(len - 96), len - 96))
                } else {
                    Ok(Self::V6(v.network(len), len))
                }
            }
            _ => Err(ParseError::PrefixLength),
        }
    }

    /// The host route (`/32` or `/128`) of an address.
    #[must_use]
    pub fn host(addr: Address) -> Self {
        match addr {
            Address::V4(a) => Self::V4(a, 32),
            Address::V6(a) => Self::V6(a, 128),
        }
    }

    #[must_use]
    pub fn prefix_len(self) -> u8 {
        match self {
            Self::V4(_, l) | Self::V6(_, l) => l,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(a, l) => write!(f, "{}/{l}", Ipv4Addr::from(a)),
            Self::V6(a, l) => write!(f, "{}/{l}", Ipv6Addr::from(a)),
        }
    }
}

/// An IP address from its packed (big endian) 4 or 16 byte representation.
#[must_use]
pub fn ip_from_packed(b: &[u8]) -> Option<IpAddr> {
    if let Ok(b) = <[u8; 4]>::try_from(b) {
        return Some(IpAddr::V4(Ipv4Addr::from(b)));
    }
    <[u8; 16]>::try_from(b).ok().map(|b| IpAddr::V6(Ipv6Addr::from(b)))
}

/// Errors parsing addresses and networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Address,
    PrefixLength,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address => f.write_str("invalid IP address"),
            Self::PrefixLength => f.write_str("invalid prefix length"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses an IP address (`"192.0.2.1"`, `"2001:db8::1"`).
///
/// # Errors
/// If the string is not a valid address.
pub fn parse_address(s: &str) -> Result<Address, ParseError> {
    s.parse::<IpAddr>().map(Address::from_ip).map_err(|_| ParseError::Address)
}

/// Parses a network in CIDR notation (`"192.0.2.0/24"`). A plain address is a host route.
/// Host bits are cleared (`"192.0.2.1/24"` is `192.0.2.0/24`).
///
/// # Errors
/// If the address or the prefix length is invalid.
pub fn parse_network(s: &str) -> Result<Network, ParseError> {
    match s.split_once('/') {
        None => parse_address(s).map(Network::host),
        Some((addr, len)) => {
            let ip = addr.parse::<IpAddr>().map_err(|_| ParseError::Address)?;
            // u8::from_str accepts a leading '+', CIDR notation does not
            if len.is_empty() || len.len() > 3 || !len.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::PrefixLength);
            }
            let len = len.parse::<u8>().map_err(|_| ParseError::PrefixLength)?;
            Network::new(ip, len)
        }
    }
}

/// A matched entry: the network and its value (encoding + payload, dereferences to the payload).
pub type Match<'a, P> = (Network, ValueRef<'a, P>);

/// IPv4 and IPv6 longest-prefix-match tables sharing a deduplicated value store.
///
/// `P` is the payload kept for each distinct value next to its encoding; the Python bindings
/// store the read-only Python object there. Payloads are never dropped inside the tree's
/// methods: operations that discard payloads return them, so the caller decides when they are
/// dropped (for Python objects: not while holding a lock).
#[derive(Debug)]
pub struct Tree<P> {
    pub(crate) v4: PrefixTable<u32>,
    pub(crate) v6: PrefixTable<u128>,
    pub(crate) values: ValueStore<P>,
    /// Registered types referenced by [`Value::Object`] (append only).
    pub(crate) types: Vec<TypeDesc>,
    /// The strings referenced by the encoded values.
    pub(crate) strings: StringSet,
}

impl<P> Default for Tree<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Tree<P> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            v4: PrefixTable::new(),
            v6: PrefixTable::new(),
            values: ValueStore::new(),
            types: Vec::new(),
            strings: StringSet::default(),
        }
    }

    /// Number of networks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of IPv4 and IPv6 networks.
    #[must_use]
    pub fn len_by_family(&self) -> (usize, usize) {
        (self.v4.len(), self.v6.len())
    }

    /// Number of distinct values stored (may include unreferenced values until compiled).
    #[must_use]
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Registered types, indexed by the type ids used in [`Value::Object`].
    #[must_use]
    pub fn types(&self) -> &[TypeDesc] {
        &self.types
    }

    /// Id of a registered type, registering it if needed.
    ///
    /// # Panics
    /// If more than `u32::MAX` types are registered.
    pub fn register_type(&mut self, desc: &TypeDesc) -> u32 {
        let pos = self.types.iter().position(|t| t == desc).unwrap_or_else(|| {
            self.types.push(desc.clone());
            self.types.len() - 1
        });
        u32::try_from(pos).expect("too many types")
    }

    /// The strings referenced by the encoded values.
    #[must_use]
    pub fn strings(&self) -> &Strings {
        self.strings.strings()
    }

    /// What the encoded values refer to, to decode them.
    #[must_use]
    pub fn refs(&self) -> Refs<'_> {
        Refs { types: &self.types, strings: self.strings.strings() }
    }

    /// Encodes a value for this tree, adding its strings. `types`, if given, maps the object
    /// type ids of the value to the tree's (see [`Tree::register_type`]).
    pub fn encode(&mut self, value: &Value, types: Option<&[u32]>) -> Vec<u8> {
        encode(value, types, |s| self.strings.intern(s))
    }

    /// Decodes an encoded value of this tree.
    ///
    /// # Errors
    /// If the data is not a valid value of this tree.
    pub fn decode(&self, encoded: &[u8]) -> Result<Value, DecodeError> {
        decode(encoded, self.refs())
    }

    /// Payloads of all stored values.
    pub fn payloads(&self) -> impl Iterator<Item = &P> {
        self.values.payloads()
    }

    /// All stored values (encoding + payload), in id order.
    pub fn values(&self) -> impl Iterator<Item = ValueRef<'_, P>> {
        self.values.iter()
    }

    /// Id of a stored value given its encoding.
    pub fn find_value(&mut self, encoded: &[u8]) -> Option<u32> {
        self.values.find(encoded)
    }

    /// Inserts or replaces a network with a value given by its canonical encoding, from
    /// [`Tree::encode`]. Returns whether the network was new and, if the value
    /// already existed, the unused `payload`.
    pub fn insert(&mut self, net: Network, encoded: &[u8], payload: P) -> (bool, Option<P>) {
        let (id, unused) = self.add_value(encoded, payload);
        (self.insert_id(net, id), unused)
    }

    /// Stores a value given by its canonical encoding (from [`Tree::encode`]) unless it
    /// exists. Returns its id and, if the value already existed, the unused `payload`. The id
    /// stays valid until the next [`Tree::compile`].
    pub fn add_value(&mut self, encoded: &[u8], payload: P) -> (u32, Option<P>) {
        self.values.intern(encoded, payload)
    }

    /// Inserts or replaces a network with an already stored value id (see
    /// [`Tree::find_value`]). Returns true if the network was new.
    pub fn insert_id(&mut self, net: Network, id: u32) -> bool {
        debug_assert!((id as usize) < self.values.len());
        match net {
            Network::V4(a, l) => self.v4.insert((a, l), id).is_none(),
            Network::V6(a, l) => self.v6.insert((a, l), id).is_none(),
        }
    }

    /// Removes a network, returns its value (which stays stored until the next compaction).
    pub fn remove(&mut self, net: Network) -> Option<ValueRef<'_, P>> {
        let id = match net {
            Network::V4(a, l) => self.v4.remove((a, l)),
            Network::V6(a, l) => self.v6.remove((a, l)),
        }?;
        Some(self.values.get(id))
    }

    /// Value of exactly this network (no longest prefix match). Works without compiling.
    #[must_use]
    pub fn get_exact(&self, net: Network) -> Option<ValueRef<'_, P>> {
        let id = match net {
            Network::V4(a, l) => self.v4.get_exact((a, l)),
            Network::V6(a, l) => self.v6.get_exact((a, l)),
        }?;
        Some(self.values.get(id))
    }

    /// True if the tree needs [`Tree::compile`] before lookups.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.v4.is_dirty() || self.v6.is_dirty()
    }

    /// Merges pending mutations, rebuilds the lookup structures and drops values which are no
    /// longer referenced (if there are enough of them to be worth it). Returns the payloads of
    /// the dropped values.
    #[must_use = "the removed payloads should be dropped deliberately"]
    pub fn compile(&mut self) -> Vec<P> {
        if !self.is_dirty() {
            return Vec::new();
        }
        self.v4.compile();
        self.v6.compile();
        let removed = self.compact_values(false);
        // usually the last compile after a bulk load: release the room reserved for more
        self.values.shrink();
        self.strings.shrink();
        removed
    }

    /// Removes unreferenced values, without `force` only if at least a quarter is unused.
    /// Returns their payloads. The tree must be compiled.
    pub(crate) fn compact_values(&mut self, force: bool) -> Vec<P> {
        debug_assert!(!self.is_dirty());
        let mut keep = vec![false; self.values.len()];
        for id in self.v4.value_ids().chain(self.v6.value_ids()) {
            keep[id as usize] = true;
        }
        let unused = keep.iter().filter(|&&k| !k).count();
        if unused == 0 || (!force && unused * 4 < keep.len()) {
            return Vec::new();
        }
        let (remap, removed) = self.values.retain(&keep);
        self.v4.remap_values(&remap);
        self.v6.remap_values(&remap);
        self.compact_strings(force);
        removed
    }

    /// Removes strings no longer used by any value, without `force` only if at least a
    /// quarter is unused. The values are encoded again with the new string ids.
    fn compact_strings(&mut self, force: bool) {
        let strings = self.strings.strings();
        let types = &self.types;
        let mut used = vec![false; strings.len()];
        for v in self.values.iter() {
            visit_strings(v.encoded(), types, |id| used[id as usize] = true);
        }
        let unused = used.iter().filter(|&&u| !u).count();
        if unused == 0 || (!force && unused * 4 < used.len()) {
            return;
        }
        let mut kept = Strings::new();
        let remap: Vec<u32> =
            strings.iter().zip(&used).map(|(s, &u)| if u { kept.push(s) } else { u32::MAX }).collect();
        self.values.rewrite_encodings(|e, out| remap_strings(e, out, types, |id| remap[id as usize]));
        self.strings = StringSet::new(kept);
    }

    /// Replaces the payloads (e.g. after decoding from disk). `make` gets the value id, its
    /// canonical encoding and what it refers to (to decode it).
    ///
    /// # Errors
    /// The first error returned by `make`.
    pub fn with_payloads<Q, E>(self, mut make: impl FnMut(u32, &[u8], Refs<'_>) -> Result<Q, E>) -> Result<Tree<Q>, E> {
        let payloads = self.values.iter().map(|v| make(v.id(), v.encoded(), self.refs())).collect::<Result<_, E>>()?;
        Ok(Tree {
            values: self.values.map_payloads(payloads),
            v4: self.v4,
            v6: self.v6,
            types: self.types,
            strings: self.strings,
        })
    }

    /// An independent copy; payloads are produced by `clone` (e.g. `Py::clone_ref`, Python
    /// objects are not `Clone`). Used for copy-on-write.
    #[must_use]
    pub fn clone_with<Q>(&self, clone: impl FnMut(&P) -> Q) -> Tree<Q> {
        Tree {
            v4: self.v4.clone(),
            v6: self.v6.clone(),
            values: self.values.clone_with(clone),
            types: self.types.clone(),
            strings: self.strings.share(),
        }
    }

    /// Canonical encoding of a stored value.
    #[must_use]
    pub fn encoded(&self, id: u32) -> &[u8] {
        self.values.encoded(id)
    }

    fn match_v4(&self, id: Option<u32>) -> Option<Match<'_, P>> {
        let (a, l, v) = self.v4.entry(id?);
        Some((Network::V4(a, l), self.values.get(v)))
    }

    fn match_v6(&self, id: Option<u32>) -> Option<Match<'_, P>> {
        let (a, l, v) = self.v6.entry(id?);
        Some((Network::V6(a, l), self.values.get(v)))
    }

    /// Longest prefix match of an address. The tree must be compiled.
    #[must_use]
    pub fn lookup(&self, addr: Address) -> Option<Match<'_, P>> {
        match addr {
            Address::V4(a) => self.match_v4(self.v4.lookup(a)),
            Address::V6(a) => self.match_v6(self.v6.lookup(a)),
        }
    }

    /// Value of the longest prefix match of an address, without the matched network (touches
    /// less memory than [`Tree::lookup`]). The tree must be compiled.
    #[inline]
    #[must_use]
    pub fn lookup_value(&self, addr: Address) -> Option<ValueRef<'_, P>> {
        let id = match addr {
            Address::V4(a) => self.v4.lookup_value(a)?,
            Address::V6(a) => self.v6.lookup_value(a)?,
        };
        Some(self.values.get(id))
    }

    /// Longest prefix containing the whole network. The tree must be compiled.
    #[must_use]
    pub fn lookup_network(&self, net: Network) -> Option<Match<'_, P>> {
        match net {
            Network::V4(a, l) => self.match_v4(self.v4.lookup_network(a, l)),
            Network::V6(a, l) => self.match_v6(self.v6.lookup_network(a, l)),
        }
    }

    /// All networks containing the network, most specific first. The tree must be compiled.
    #[must_use]
    pub fn matches(&self, net: Network) -> Vec<Match<'_, P>> {
        let mut out = Vec::new();
        let mut cur = self.lookup_network(net);
        // walk up via lookups of the next shorter prefix; the chain is bounded by the length
        while let Some((n, v)) = cur {
            out.push((n, v));
            cur = match n {
                Network::V4(_, 0) | Network::V6(_, 0) => None,
                Network::V4(a, l) => self.match_v4(self.v4.lookup_network(a, l - 1)),
                Network::V6(a, l) => self.match_v6(self.v6.lookup_network(a, l - 1)),
            };
        }
        out
    }

    /// All networks and their payloads: IPv4 first, each family sorted by address and prefix
    /// length. The tree must be compiled.
    pub fn entries(&self) -> impl Iterator<Item = Match<'_, P>> + '_ {
        let v4 = self.v4.entries().map(|(a, l, v)| (Network::V4(a, l), self.values.get(v)));
        let v6 = self.v6.entries().map(|(a, l, v)| (Network::V6(a, l), self.values.get(v)));
        v4.chain(v6)
    }

    /// Approximate memory used in bytes, excluding what payloads point to.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        size_of::<Self>()
            + self.v4.memory_usage()
            + self.v6.memory_usage()
            + self.values.memory_usage()
            + self.strings.memory_usage()
    }
}

impl Tree<Value> {
    /// Convenience for Rust users (and tests): stores decoded values as their own payload.
    pub fn insert_value(&mut self, net: Network, value: Value) -> bool {
        let encoded = self.encode(&value, None);
        self.insert(net, &encoded, value).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Network {
        parse_network(s).unwrap()
    }

    fn addr(s: &str) -> Address {
        parse_address(s).unwrap()
    }

    #[test]
    fn parsing_and_display() {
        assert_eq!(net("10.1.2.3/8"), Network::V4(0x0a00_0000, 8));
        assert_eq!(net("10.1.2.3"), Network::V4(0x0a01_0203, 32));
        assert_eq!(net("2001:db8::1/32"), Network::V6(0x2001_0db8 << 96, 32));
        assert_eq!(net("::ffff:10.0.0.0/104"), Network::V4(0x0a00_0000, 8));
        assert_eq!(net("::ffff:0:0/95"), Network::V6(0xfffe << 32, 95));
        assert_eq!(addr("::ffff:1.2.3.4"), Address::V4(0x0102_0304));
        for (s, e) in [
            ("10.0.0.0/33", ParseError::PrefixLength),
            ("10.0.0.0/+8", ParseError::PrefixLength),
            ("10.0.0.0/", ParseError::PrefixLength),
            ("::/129", ParseError::PrefixLength),
            ("10.0.0/8", ParseError::Address),
        ] {
            assert_eq!(parse_network(s), Err(e), "{s}");
        }
        assert_eq!(parse_address("foo"), Err(ParseError::Address));
        assert_eq!(Address::from_packed(&[1, 2, 3, 4]), Some(Address::V4(0x0102_0304)));
        assert_eq!(Address::from_packed(&[1, 2, 3]), None);
        assert_eq!(net("10.1.2.3/8").to_string(), "10.0.0.0/8");
        assert_eq!(net("2001:db8::/32").to_string(), "2001:db8::/32");
    }

    #[test]
    fn lookups_mutations_and_compaction() {
        let mut t = Tree::new();
        assert!(t.insert_value(net("10.0.0.0/8"), Value::Str("ten".into())));
        assert!(t.insert_value(net("10.1.0.0/16"), Value::Null));
        assert!(t.insert_value(net("2001:db8::/32"), Value::Int(1)));
        assert!(!t.insert_value(net("2001:db8::/32"), Value::Int(2)));
        assert_eq!(t.len(), 3);
        assert_eq!(t.compile(), vec![Value::Int(1)], "the replaced value is 1 of 4 (25 %): compacted");
        assert_eq!(t.lookup(addr("10.1.2.3")).map(|(n, v)| (n, v.payload())), Some((net("10.1.0.0/16"), &Value::Null)));
        assert_eq!(
            t.lookup(addr("10.2.2.3")).map(|(n, v)| (n, v.payload())),
            Some((net("10.0.0.0/8"), &Value::Str("ten".into())))
        );
        assert_eq!(t.lookup_value(addr("2001:db8::1")).map(|v| v.payload()), Some(&Value::Int(2)));
        assert_eq!(t.lookup_value(addr("::ffff:10.0.0.1")).map(|v| v.payload()), Some(&Value::Str("ten".into())));
        assert!(t.lookup(addr("2001:db9::1")).is_none());
        let m: Vec<_> = t.matches(net("10.1.2.3")).into_iter().map(|(n, _)| n.to_string()).collect();
        assert_eq!(m, vec!["10.1.0.0/16", "10.0.0.0/8"]);
        assert_eq!(t.remove(net("10.1.0.0/16")).map(|v| v.payload()), Some(&Value::Null));
        assert!(t.remove(net("10.1.0.0/16")).is_none());
        let _ = t.compile();
        assert_eq!(t.lookup(addr("10.1.2.3")).unwrap().0, net("10.0.0.0/8"));
        assert_eq!(t.entries().count(), 2);

        // replaced values become garbage and are compacted (returned, not dropped)
        let mut t = Tree::new();
        for i in 0..100 {
            t.insert_value(net("10.0.0.0/8"), Value::Int(i));
        }
        assert_eq!(t.value_count(), 100);
        assert_eq!(t.compile().len(), 99);
        assert_eq!(t.value_count(), 1);
        assert_eq!(t.lookup_value(addr("10.0.0.1")).map(|v| v.payload()), Some(&Value::Int(99)));
        // the dedup index is consistent after compaction
        let encoded = t.encode(&Value::Int(99), None);
        assert_eq!(t.find_value(&encoded), Some(0));
        t.insert_value(net("11.0.0.0/8"), Value::Int(99));
        assert_eq!(t.value_count(), 1);

        // a copy is independent of the original, including pending mutations
        let mut copy = t.clone_with(Value::clone);
        copy.insert_value(net("12.0.0.0/8"), Value::Int(5));
        copy.remove(net("10.0.0.0/8"));
        let _ = copy.compile();
        let _ = t.compile();
        assert_eq!(t.len(), 2);
        assert_eq!(copy.len(), 2);
        assert_eq!(t.lookup_value(addr("10.0.0.1")).map(|v| v.payload()), Some(&Value::Int(99)));
        assert_eq!(copy.lookup_value(addr("10.0.0.1")).map(|v| v.payload()), None);
        assert_eq!(copy.lookup_value(addr("12.0.0.1")).map(|v| v.payload()), Some(&Value::Int(5)));
    }

    #[test]
    fn shared_strings_are_compacted() {
        let s = |s: &str| Value::Str(s.into());
        let pair = |a: &str, b: &str| Value::Seq(vec![s(a), s(b)].into());
        let mut t = Tree::new();
        t.insert_value(net("10.0.0.0/8"), pair("a", "b"));
        t.insert_value(net("11.0.0.0/8"), pair("b", "c"));
        t.insert_value(net("12.0.0.0/8"), pair("c", "a"));
        assert_eq!(t.strings().iter().collect::<Vec<_>>(), ["a", "b", "c"], "each string is stored once");
        assert!(t.compile().is_empty());

        // a copy shares the strings; replacing a value does not change the copy
        let copy = t.clone_with(Value::clone);
        t.insert_value(net("10.0.0.0/8"), pair("d", "c"));
        t.insert_value(net("11.0.0.0/8"), pair("d", "d"));
        assert_eq!(t.strings().len(), 4);
        assert_eq!(t.compile().len(), 2, "two of five values unused: compacted");
        // "b" is unused now (1 of 4 strings): removed, the values are encoded again
        assert_eq!(t.strings().iter().collect::<Vec<_>>(), ["a", "c", "d"]);
        let found = |t: &Tree<Value>, a: &str| t.lookup_value(addr(a)).map(|v| t.decode(v.encoded()).unwrap());
        assert_eq!(found(&t, "10.0.0.1"), Some(pair("d", "c")));
        assert_eq!(found(&t, "11.0.0.1"), Some(pair("d", "d")));
        assert_eq!(found(&t, "12.0.0.1"), Some(pair("c", "a")));
        assert_eq!(found(&copy, "10.0.0.1"), Some(pair("a", "b")));
        assert_eq!(copy.strings().len(), 3);
        // the deduplication index is rebuilt for the new encodings
        let encoded = t.encode(&pair("c", "a"), None);
        assert_eq!(t.find_value(&encoded), Some(0));
        assert_eq!(t.strings().len(), 3);
    }
}
