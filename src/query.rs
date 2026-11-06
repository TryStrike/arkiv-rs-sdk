//! A typed builder for the Arkiv query language.
//!
//! Pure string building: no network, no dependency on `client`.

use crate::attributes::{validate_name, AttrType, Value, SCHEMA_ATTRIBUTE};
use crate::error::{Error, Result};
use crate::types::{Address, Key};

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Ascending.
    Asc,
    /// Descending.
    Desc,
}

/// A comparison operator the node supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    /// `=`
    Eq,
    /// `>`
    Gt,
    /// `>=`
    Gte,
    /// `<`
    Lt,
    /// `<=`
    Lte,
}

/// A boolean expression over attributes. Build with the free functions below.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// `name <op> literal`.
    Compare {
        /// Attribute or system attribute (`$owner`, `$creator`, `$key`, `$expiresAt`).
        name: String,
        /// Operator.
        op: Cmp,
        /// Literal.
        value: Value,
    },
    /// `name BETWEEN low AND high`.
    Between {
        /// Attribute name.
        name: String,
        /// Lower bound.
        low: Value,
        /// Upper bound.
        high: Value,
    },
    /// `name STARTSWITH str('prefix')`.
    StartsWith {
        /// Attribute name.
        name: String,
        /// Prefix.
        prefix: String,
    },
    /// `EXISTS(name)`.
    Exists(String),
    /// Conjunction. Rendered with `AND`; nested `Or` children are parenthesised.
    And(Vec<Expr>),
    /// Disjunction. Rendered with `OR`.
    Or(Vec<Expr>),
}

fn compare(name: &str, op: Cmp, value: Value) -> Expr {
    Expr::Compare {
        name: name.to_string(),
        op,
        value,
    }
}

/// `name = value`.
pub fn eq(name: &str, value: Value) -> Expr {
    compare(name, Cmp::Eq, value)
}
/// `name > value`.
pub fn gt(name: &str, value: Value) -> Expr {
    compare(name, Cmp::Gt, value)
}
/// `name >= value`.
pub fn gte(name: &str, value: Value) -> Expr {
    compare(name, Cmp::Gte, value)
}
/// `name < value`.
pub fn lt(name: &str, value: Value) -> Expr {
    compare(name, Cmp::Lt, value)
}
/// `name <= value`.
pub fn lte(name: &str, value: Value) -> Expr {
    compare(name, Cmp::Lte, value)
}
/// `name BETWEEN low AND high`.
pub fn between(name: &str, low: Value, high: Value) -> Expr {
    Expr::Between {
        name: name.to_string(),
        low,
        high,
    }
}
/// `name STARTSWITH str('prefix')`.
pub fn starts_with(name: &str, prefix: &str) -> Expr {
    Expr::StartsWith {
        name: name.to_string(),
        prefix: prefix.to_string(),
    }
}
/// `EXISTS(name)`.
pub fn exists(name: &str) -> Expr {
    Expr::Exists(name.to_string())
}
/// Conjunction of expressions.
pub fn and(exprs: Vec<Expr>) -> Expr {
    Expr::And(exprs)
}
/// Disjunction of expressions.
pub fn or(exprs: Vec<Expr>) -> Expr {
    Expr::Or(exprs)
}

/// A query: a conjunction of filters and an optional order. Errors surface in [`Query::build`],
/// so the chain methods stay infallible.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Query {
    filters: Vec<Expr>,
    order: Option<(String, AttrType, Dir)>,
}

impl Query {
    /// An empty query. [`build`](Query::build) on it errors: the node needs at least one filter.
    ///
    /// ```
    /// use arkiv::query::{gt, Dir, Query};
    /// use arkiv::{AttrType, Value};
    ///
    /// let q = Query::new()
    ///     .schema("strike.rounds")
    ///     .filter(gt("settledAt", Value::U64(123)))
    ///     .order_by("settledAt", AttrType::U64, Dir::Desc);
    /// assert_eq!(
    ///     q.build().unwrap(),
    ///     "arkiv.schema = str('strike.rounds') AND settledAt > u64(123) ORDER BY settledAt:u64 DESC"
    /// );
    /// ```
    pub fn new() -> Query {
        Query::default()
    }
    /// Filters on the `arkiv.schema` tag: `arkiv.schema = str('tag')`.
    pub fn schema(self, tag: &str) -> Query {
        self.filter(eq(SCHEMA_ATTRIBUTE, Value::Str(tag.to_string())))
    }
    /// Filters on `$creator = addr(..)`.
    pub fn creator(self, creator: Address) -> Query {
        self.filter(eq("$creator", Value::Addr(creator)))
    }
    /// Filters on `$owner = addr(..)`.
    pub fn owner(self, owner: Address) -> Query {
        self.filter(eq("$owner", Value::Addr(owner)))
    }
    /// Filters on `$key = key(..)`.
    pub fn key(self, key: Key) -> Query {
        self.filter(eq("$key", Value::Key(key)))
    }
    /// Adds a filter, ANDed with the others.
    pub fn filter(mut self, expr: Expr) -> Query {
        self.filters.push(expr);
        self
    }
    /// Orders results: `ORDER BY name:type DIR`. `ty` is required (the node sorts as one type) and
    /// must be indexable.
    pub fn order_by(mut self, name: &str, ty: AttrType, dir: Dir) -> Query {
        self.order = Some((name.to_string(), ty, dir));
        self
    }
    /// Renders the query string. Names are checked with `validate_name` (or the four queryable
    /// system names), `bytes` literals are rejected, system names get their fixed type.
    /// Strings are written `str('..')` with `'` doubled. `u64` is `u64(123)`, `u256` is `u256(decimal)`,
    /// `dec` is `dec(1.5)`, `addr` is `addr(0x..)` lowercase, `key` is `key(0x..)`, `bool` is bare `true`/`false`,
    /// `i32` is `i32(5)`. Clauses join with ` AND ` in insertion order, then the order clause.
    pub fn build(&self) -> Result<String> {
        if self.filters.is_empty() {
            return Err(invalid("a query needs at least one filter"));
        }
        let in_and = self.filters.len() > 1;
        let parts = self
            .filters
            .iter()
            .map(|e| render(e, in_and))
            .collect::<Result<Vec<_>>>()?;
        let mut out = parts.join(" AND ");
        if let Some((name, ty, dir)) = &self.order {
            check_name(name, false)?;
            if !ty.is_indexable() {
                return Err(invalid(format!(
                    "cannot order by {name}: {} is not indexable",
                    ty.tag()
                )));
            }
            let dir = match dir {
                Dir::Asc => "ASC",
                Dir::Desc => "DESC",
            };
            out.push_str(&format!(" ORDER BY {name}:{} {dir}", ty.tag()));
        }
        Ok(out)
    }
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidQuery(msg.into())
}

/// The type a system name is fixed to, or `None` for an ordinary name.
fn system_type(name: &str) -> Option<AttrType> {
    match name {
        "$key" => Some(AttrType::Key),
        "$owner" | "$creator" => Some(AttrType::Addr),
        "$expiresAt" => Some(AttrType::U64),
        _ => None,
    }
}

/// Checks a name; system names pass only where `allow_system` is set.
fn check_name(name: &str, allow_system: bool) -> Result<()> {
    if system_type(name).is_some() {
        if allow_system {
            return Ok(());
        }
        return Err(invalid(format!("{name} cannot be used here")));
    }
    validate_name(name).map_err(|e| invalid(e.to_string()))
}

fn check_value(name: &str, value: &Value) -> Result<()> {
    if let Some(want) = system_type(name) {
        if value.attr_type() != want {
            return Err(invalid(format!(
                "{name} is {}, got a {} literal",
                want.tag(),
                value.attr_type().tag()
            )));
        }
    }
    Ok(())
}

fn cmp_str(op: Cmp) -> &'static str {
    match op {
        Cmp::Eq => "=",
        Cmp::Gt => ">",
        Cmp::Gte => ">=",
        Cmp::Lt => "<",
        Cmp::Lte => "<=",
    }
}

fn render_list(children: &[Expr], sep: &str, in_and: bool, what: &str) -> Result<String> {
    if children.is_empty() {
        return Err(invalid(format!("empty {what}")));
    }
    let parts = children
        .iter()
        .map(|c| render(c, in_and))
        .collect::<Result<Vec<_>>>()?;
    Ok(parts.join(sep))
}

/// `in_and` is true when the expression sits in a conjunction of several clauses.
fn render(expr: &Expr, in_and: bool) -> Result<String> {
    match expr {
        Expr::Compare { name, op, value } => {
            check_name(name, true)?;
            check_value(name, value)?;
            Ok(format!("{name} {} {}", cmp_str(*op), literal(value)?))
        }
        Expr::Between { name, low, high } => {
            check_name(name, true)?;
            check_value(name, low)?;
            check_value(name, high)?;
            if low.attr_type() != high.attr_type() {
                return Err(invalid(format!("BETWEEN bounds for {name} differ in type")));
            }
            Ok(format!(
                "{name} BETWEEN {} AND {}",
                literal(low)?,
                literal(high)?
            ))
        }
        Expr::StartsWith { name, prefix } => {
            check_name(name, false)?;
            Ok(format!(
                "{name} STARTSWITH {}",
                literal(&Value::Str(prefix.clone()))?
            ))
        }
        Expr::Exists(name) => {
            check_name(name, false)?;
            Ok(format!("EXISTS({name})"))
        }
        Expr::And(children) => render_list(children, " AND ", true, "AND"),
        Expr::Or(children) => {
            let s = render_list(children, " OR ", false, "OR")?;
            Ok(if in_and && children.len() > 1 {
                format!("({s})")
            } else {
                s
            })
        }
    }
}

/// Renders one value as a query literal (see [`Query::build`] for the forms).
pub fn literal(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Bool(b) => b.to_string(),
        Value::I32(n) => format!("i32({n})"),
        Value::U64(n) => format!("u64({n})"),
        Value::U256(be) => format!("u256({})", u256_decimal(be)),
        Value::Dec(d) => format!("dec({d})"),
        Value::Bytes(_) => return Err(invalid("bytes values cannot be queried")),
        Value::Str(s) => format!("str('{}')", s.replace('\'', "''")),
        Value::Addr(a) => format!("addr({a})"),
        Value::Key(k) => format!("key({k})"),
    })
}

/// Big-endian 256-bit integer to decimal digits, by repeated division by 10.
fn u256_decimal(be: &[u8; 32]) -> String {
    let mut n = be.to_vec();
    let mut digits = Vec::new();
    while n.iter().any(|b| *b != 0) {
        let mut rem = 0u32;
        for b in n.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        return "0".into();
    }
    digits.reverse();
    String::from_utf8_lossy(&digits).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attributes::Decimal;
    use crate::types::B256;

    const CREATOR: &str = "0x0f05df479fcb23b2281e28813fb47e57e47d1bb7";
    fn addr() -> Address {
        CREATOR.parse().unwrap()
    }
    fn s(v: &str) -> Value {
        Value::Str(v.into())
    }
    fn build(q: Query) -> String {
        q.build().unwrap()
    }
    fn err(q: Query) -> String {
        q.build().unwrap_err().to_string()
    }

    #[test]
    fn strike_example_exact() {
        let q = Query::new()
            .schema("strike.rounds")
            .creator(addr())
            .filter(eq("asset", s("BTC")))
            .filter(gt("settledAt", Value::U64(123)));
        assert_eq!(
            build(q),
            "arkiv.schema = str('strike.rounds') AND $creator = addr(0x0f05df479fcb23b2281e28813fb47e57e47d1bb7) AND asset = str('BTC') AND settledAt > u64(123)"
        );
    }

    #[test]
    fn spec_example_with_order() {
        let q = Query::new()
            .schema("strike.rounds")
            .creator(addr())
            .filter(eq("asset", s("BTC")))
            .filter(gt("settledAt", Value::U64(123)))
            .order_by("settledAt", AttrType::U64, Dir::Desc);
        assert!(build(q).ends_with("settledAt > u64(123) ORDER BY settledAt:u64 DESC"));
    }

    #[test]
    fn empty_query_errors() {
        assert!(Query::new().build().is_err());
        assert!(Query::new()
            .order_by("a", AttrType::U64, Dir::Asc)
            .build()
            .is_err());
    }

    #[test]
    fn order_asc_and_types() {
        let q = Query::new()
            .schema("x")
            .order_by("name", AttrType::Str, Dir::Asc);
        assert_eq!(build(q), "arkiv.schema = str('x') ORDER BY name:str ASC");
        let q = Query::new()
            .schema("x")
            .order_by("p", AttrType::Dec, Dir::Desc);
        assert!(build(q).ends_with("ORDER BY p:dec DESC"));
    }

    #[test]
    fn order_by_bytes_rejected() {
        assert!(Query::new()
            .schema("x")
            .order_by("b", AttrType::Bytes, Dir::Asc)
            .build()
            .is_err());
    }

    #[test]
    fn order_by_bad_name_rejected() {
        assert!(Query::new()
            .schema("x")
            .order_by("1bad", AttrType::U64, Dir::Asc)
            .build()
            .is_err());
        assert!(Query::new()
            .schema("x")
            .order_by("$owner", AttrType::Addr, Dir::Asc)
            .build()
            .is_err());
    }

    #[test]
    fn last_order_wins() {
        let q = Query::new()
            .schema("x")
            .order_by("a", AttrType::U64, Dir::Asc)
            .order_by("b", AttrType::U64, Dir::Desc);
        assert!(build(q).ends_with("ORDER BY b:u64 DESC"));
    }

    #[test]
    fn system_names() {
        let k: Key = "0x59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807"
            .parse()
            .unwrap();
        assert_eq!(
            build(Query::new().key(k)),
            "$key = key(0x59c5ddf06b5605e27833d0a02c8f6e96cebf9f334a6470b39e31eccb34895807)"
        );
        assert_eq!(
            build(Query::new().owner(addr())),
            format!("$owner = addr({CREATOR})")
        );
        assert_eq!(
            build(Query::new().filter(lt("$expiresAt", Value::U64(9)))),
            "$expiresAt < u64(9)"
        );
    }

    #[test]
    fn system_name_type_mismatch() {
        assert!(Query::new().filter(eq("$creator", s("x"))).build().is_err());
        assert!(Query::new()
            .filter(eq("$expiresAt", Value::I32(1)))
            .build()
            .is_err());
        assert!(Query::new()
            .filter(eq("$key", Value::Addr(addr())))
            .build()
            .is_err());
    }

    #[test]
    fn unknown_system_name_rejected() {
        assert!(Query::new().filter(eq("$nope", s("x"))).build().is_err());
        assert!(Query::new().filter(exists("$owner")).build().is_err());
        assert!(Query::new()
            .filter(starts_with("$owner", "x"))
            .build()
            .is_err());
    }

    #[test]
    fn address_is_lowercased() {
        let a: Address = "0x0F05DF479FCB23B2281E28813FB47E57E47D1BB7"
            .parse()
            .unwrap();
        assert_eq!(
            build(Query::new().creator(a)),
            format!("$creator = addr({CREATOR})")
        );
    }

    #[test]
    fn comparison_operators() {
        let v = || Value::U64(5);
        assert_eq!(render(&eq("a", v()), false).unwrap(), "a = u64(5)");
        assert_eq!(render(&gt("a", v()), false).unwrap(), "a > u64(5)");
        assert_eq!(render(&gte("a", v()), false).unwrap(), "a >= u64(5)");
        assert_eq!(render(&lt("a", v()), false).unwrap(), "a < u64(5)");
        assert_eq!(render(&lte("a", v()), false).unwrap(), "a <= u64(5)");
    }

    #[test]
    fn between_renders() {
        let q = Query::new().filter(between("t", Value::U64(1), Value::U64(9)));
        assert_eq!(build(q), "t BETWEEN u64(1) AND u64(9)");
    }

    #[test]
    fn between_type_mismatch() {
        assert!(Query::new()
            .filter(between("t", Value::U64(1), Value::I32(9)))
            .build()
            .is_err());
    }

    #[test]
    fn between_bytes_rejected() {
        let b = Value::Bytes(vec![1]);
        assert!(Query::new()
            .filter(between("t", b.clone(), b))
            .build()
            .is_err());
    }

    #[test]
    fn starts_with_renders_and_escapes() {
        assert_eq!(
            build(Query::new().filter(starts_with("name", "ab"))),
            "name STARTSWITH str('ab')"
        );
        assert_eq!(
            build(Query::new().filter(starts_with("name", "o'k"))),
            "name STARTSWITH str('o''k')"
        );
    }

    #[test]
    fn exists_renders() {
        assert_eq!(
            build(Query::new().filter(exists("settledAt"))),
            "EXISTS(settledAt)"
        );
    }

    #[test]
    fn string_quote_doubling() {
        assert_eq!(literal(&s("it's")).unwrap(), "str('it''s')");
        assert_eq!(literal(&s("''")).unwrap(), "str('''''')");
        assert_eq!(literal(&s("")).unwrap(), "str('')");
        assert_eq!(literal(&s("a b\"c")).unwrap(), "str('a b\"c')");
    }

    #[test]
    fn scalar_literals() {
        assert_eq!(literal(&Value::Bool(true)).unwrap(), "true");
        assert_eq!(literal(&Value::Bool(false)).unwrap(), "false");
        assert_eq!(literal(&Value::I32(-5)).unwrap(), "i32(-5)");
        assert_eq!(literal(&Value::I32(i32::MIN)).unwrap(), "i32(-2147483648)");
        assert_eq!(
            literal(&Value::U64(u64::MAX)).unwrap(),
            "u64(18446744073709551615)"
        );
        assert_eq!(literal(&Value::U64(0)).unwrap(), "u64(0)");
    }

    #[test]
    fn u256_literals() {
        assert_eq!(literal(&Value::U256([0; 32])).unwrap(), "u256(0)");
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(literal(&Value::U256(one)).unwrap(), "u256(1)");
        let mut v = [0u8; 32];
        v[30] = 1; // 256
        assert_eq!(literal(&Value::U256(v)).unwrap(), "u256(256)");
        assert_eq!(
            literal(&Value::U256([0xff; 32])).unwrap(),
            "u256(115792089237316195423570985008687907853269984665640564039457584007913129639935)"
        );
        let mut e18 = [0u8; 32];
        e18[24..].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());
        assert_eq!(
            literal(&Value::U256(e18)).unwrap(),
            "u256(1000000000000000000)"
        );
    }

    #[test]
    fn dec_literals() {
        let d = |s: &str| literal(&Value::Dec(Decimal::parse(s).unwrap())).unwrap();
        assert_eq!(d("1.5"), "dec(1.5)");
        assert_eq!(d("1.50"), "dec(1.5)");
        assert_eq!(d("-0.25"), "dec(-0.25)");
        assert_eq!(d("0"), "dec(0)");
        assert_eq!(d("100"), "dec(100)");
    }

    #[test]
    fn addr_key_literals() {
        assert_eq!(
            literal(&Value::Addr(addr())).unwrap(),
            format!("addr({CREATOR})")
        );
        assert_eq!(
            literal(&Value::Key(B256([0xab; 32]))).unwrap(),
            format!("key(0x{})", "ab".repeat(32))
        );
    }

    #[test]
    fn bytes_literal_rejected() {
        assert!(literal(&Value::Bytes(vec![])).is_err());
        assert!(Query::new()
            .filter(eq("b", Value::Bytes(vec![1])))
            .build()
            .is_err());
    }

    #[test]
    fn bool_in_query() {
        assert_eq!(
            build(Query::new().filter(eq("ok", Value::Bool(true)))),
            "ok = true"
        );
    }

    #[test]
    fn or_parenthesised_inside_and() {
        let q = Query::new()
            .schema("x")
            .filter(or(vec![eq("a", Value::U64(1)), eq("a", Value::U64(2))]));
        assert_eq!(
            build(q),
            "arkiv.schema = str('x') AND (a = u64(1) OR a = u64(2))"
        );
    }

    #[test]
    fn lone_or_has_no_parens() {
        let q = Query::new().filter(or(vec![eq("a", Value::U64(1)), eq("a", Value::U64(2))]));
        assert_eq!(build(q), "a = u64(1) OR a = u64(2)");
    }

    #[test]
    fn and_inside_or_has_no_parens() {
        let e = or(vec![
            and(vec![eq("a", Value::U64(1)), eq("b", Value::U64(2))]),
            eq("c", Value::U64(3)),
        ]);
        assert_eq!(
            build(Query::new().filter(e)),
            "a = u64(1) AND b = u64(2) OR c = u64(3)"
        );
    }

    #[test]
    fn or_inside_and_inside_or_is_parenthesised() {
        let e = or(vec![
            and(vec![
                eq("a", Value::U64(1)),
                or(vec![eq("b", Value::U64(2)), eq("b", Value::U64(3))]),
            ]),
            eq("c", Value::U64(4)),
        ]);
        assert_eq!(
            build(Query::new().filter(e)),
            "a = u64(1) AND (b = u64(2) OR b = u64(3)) OR c = u64(4)"
        );
    }

    #[test]
    fn single_child_or_is_unwrapped() {
        let q = Query::new()
            .schema("x")
            .filter(or(vec![eq("a", Value::U64(1))]));
        assert_eq!(build(q), "arkiv.schema = str('x') AND a = u64(1)");
    }

    #[test]
    fn explicit_and_flattens_in_place() {
        let q = Query::new().filter(and(vec![eq("a", Value::U64(1)), eq("b", Value::U64(2))]));
        assert_eq!(build(q), "a = u64(1) AND b = u64(2)");
    }

    #[test]
    fn empty_and_or_rejected() {
        assert!(Query::new().filter(and(vec![])).build().is_err());
        assert!(Query::new().filter(or(vec![])).build().is_err());
    }

    #[test]
    fn invalid_names_rejected() {
        for bad in ["", "1a", "a b", "a--b", "and", "ORDER", "x'y", "a=b"] {
            assert!(
                Query::new().filter(eq(bad, Value::U64(1))).build().is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn names_with_dots_dashes_ok() {
        assert_eq!(
            build(Query::new().filter(eq("a.b-c_d", Value::U64(1)))),
            "a.b-c_d = u64(1)"
        );
    }

    #[test]
    fn error_is_invalid_query() {
        assert!(matches!(Query::new().build(), Err(Error::InvalidQuery(_))));
        assert!(matches!(
            Query::new().filter(eq("a", Value::Bytes(vec![]))).build(),
            Err(Error::InvalidQuery(_))
        ));
    }

    #[test]
    fn build_is_repeatable_and_clone_equal() {
        let q = Query::new().schema("x").filter(eq("a", Value::U64(1)));
        let c = q.clone();
        assert_eq!(q, c);
        assert_eq!(q.build().unwrap(), q.build().unwrap());
    }

    #[test]
    fn insertion_order_kept() {
        let q = Query::new()
            .filter(eq("z", Value::U64(1)))
            .schema("x")
            .filter(eq("a", Value::U64(2)));
        assert_eq!(
            build(q),
            "z = u64(1) AND arkiv.schema = str('x') AND a = u64(2)"
        );
    }

    #[test]
    fn unicode_string_passes_through() {
        assert_eq!(literal(&s("héllo")).unwrap(), "str('héllo')");
    }

    #[test]
    fn err_helper_mentions_reason() {
        assert!(err(Query::new()).contains("at least one filter"));
    }
}
