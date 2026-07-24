use phf::phf_set;

static SINGLE_KEY: phf::Set<&'static str> = phf_set! {
    "APPEND", "BITCOUNT", "BITFIELD", "BITFIELD_RO", "BITPOS", "DECR", "DECRBY", "DUMP",
    "EXPIRE", "EXPIREAT", "EXPIRETIME", "GET", "GETDEL", "GETEX", "GETRANGE", "GETSET",
    "HDEL", "HEXISTS", "HGET", "HGETALL", "HINCRBY", "HINCRBYFLOAT", "HKEYS", "HLEN",
    "HMGET", "HMSET", "HRANDFIELD", "HSCAN", "HSET", "HSETNX", "HSTRLEN", "INCR",
    "INCRBY", "INCRBYFLOAT", "LINDEX", "LLEN", "LPOP", "LPOS", "LPUSH", "LPUSHX",
    "LRANGE", "LREM", "LSET", "LTRIM", "PEXPIRE", "PEXPIREAT", "PEXPIRETIME", "PERSIST",
    "PTTL", "RPOP", "RPUSH", "RPUSHX", "SADD", "SETBIT", "SISMEMBER", "SMEMBERS",
    "SMISMEMBER", "SPOP", "SRANDMEMBER", "SREM", "SET", "STRLEN", "SUBSTR", "TTL",
    "ZCARD", "ZCOUNT", "ZINCRBY", "ZLEXCOUNT", "ZMSCORE", "ZPOPMAX", "ZPOPMIN",
    "ZRANDMEMBER", "ZRANGE", "ZRANGEBYLEX", "ZRANGEBYSCORE", "ZRANK", "ZREM",
    "ZREMRANGEBYLEX", "ZREMRANGEBYRANK", "ZSCAN", "ZSCORE", "GEOADD", "GEODIST",
    "GEOHASH", "GEOPOS", "GEORADIUS_RO", "GEORADIUSBYMEMBER_RO", "GEOSEARCH", "GETBIT",
    "LINSERT", "RESTORE", "RESTORE-ASKING", "XACK", "XADD", "XAUTOCLAIM", "XCLAIM", "XDEL",
    "XLEN", "XPENDING", "XRANGE", "XREVRANGE", "XSETID", "XTRIM",
};

static ALL_KEYS: phf::Set<&'static str> = phf_set! {
    "DEL", "EXISTS", "TOUCH", "UNLINK", "MGET", "SINTER", "SDIFF", "SUNION",
    "SDIFFSTORE", "SINTERSTORE", "SUNIONSTORE", "PFCOUNT", "PFMERGE",
};

static PAIR_KEYS: phf::Set<&'static str> = phf_set! {
    "RENAME", "RENAMENX", "COPY", "LMOVE", "RPOPLPUSH", "SMOVE", "GEOSEARCHSTORE",
};

static COUNTED_FROM_TWO: phf::Set<&'static str> = phf_set! {
    "LMPOP", "SINTERCARD", "ZDIFF", "ZINTER", "ZINTERCARD", "ZMPOP", "ZUNION",
};

static COUNTED_FROM_THREE: phf::Set<&'static str> = phf_set! {};

static DESTINATION_AND_COUNTED: phf::Set<&'static str> = phf_set! {
    "ZUNIONSTORE", "ZINTERSTORE", "ZDIFFSTORE",
};

static ALL_BUT_LAST: phf::Set<&'static str> = phf_set! {};

fn lookup_generated(name: &str) -> Option<GeneratedCommand> {
    let local = match name {
        "AUTH" => Some((PlanKind::Auth, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::TwoOrThree)),
        "HELLO" => Some((PlanKind::Hello, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastOne)),
        "PING" => Some((PlanKind::Ping, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::OneOrTwo)),
        "ECHO" => Some((PlanKind::Echo, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::ExactlyTwo)),
        "QUIT" => Some((PlanKind::Quit, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::ExactlyOne)),
        "MULTI" => Some((PlanKind::Multi, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::ExactlyOne)),
        "EXEC" => Some((PlanKind::Exec, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::ExactlyOne)),
        "DISCARD" => Some((PlanKind::Discard, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::ExactlyOne)),
        "SCAN" => Some((PlanKind::Scan, KeySpec::First, KeyMode::Pattern, ResponsePolicy::Raw, Arity::AtLeastTwo)),
        "KEYS" => Some((PlanKind::Forward, KeySpec::First, KeyMode::Pattern, ResponsePolicy::KeyArray, Arity::AtLeastTwo)),
        "MSET" | "MSETNX" => Some((PlanKind::Forward, KeySpec::Odd, KeyMode::Literal, ResponsePolicy::Raw, Arity::OddPairs)),
        "BITOP" => Some((PlanKind::Forward, KeySpec::FromTwo, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastFour)),
        "COPY" => Some((PlanKind::Forward, KeySpec::Copy, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastThree)),
        "XREAD" | "XREADGROUP" => Some((PlanKind::Forward, KeySpec::StreamKeys, KeyMode::Literal, ResponsePolicy::StreamRead, Arity::AtLeastFour)),
        "GEORADIUS" | "GEORADIUSBYMEMBER" => Some((PlanKind::Forward, KeySpec::GeoRadius, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastFive)),
        "XGROUP" | "XINFO" | "OBJECT" | "MEMORY" => Some((PlanKind::Forward, KeySpec::SubcommandKeyAtTwo, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastThree)),
        "LCS" => Some((PlanKind::Forward, KeySpec::LcsKeys, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastFour)),
        "LMPOP" | "ZMPOP" => Some((PlanKind::Forward, KeySpec::CountedFromTwo, KeyMode::Literal, ResponsePolicy::FirstKeyArray, Arity::AtLeastThree)),
        _ => None,
    };
    let (plan, keys, key_mode, response, arity) = local.or_else(|| {
        if SINGLE_KEY.contains(name) { Some((PlanKind::Forward, KeySpec::First, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastTwo)) }
        else if ALL_KEYS.contains(name) { Some((PlanKind::Forward, KeySpec::All, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastTwo)) }
        else if PAIR_KEYS.contains(name) { Some((PlanKind::Forward, KeySpec::Pair, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastThree)) }
        else if COUNTED_FROM_TWO.contains(name) { Some((PlanKind::Forward, KeySpec::CountedFromTwo, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastThree)) }
        else if COUNTED_FROM_THREE.contains(name) { Some((PlanKind::Forward, KeySpec::CountedFromThree, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastFour)) }
        else if DESTINATION_AND_COUNTED.contains(name) { Some((PlanKind::Forward, KeySpec::DestinationAndCountedFromThree, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastFour)) }
        else if ALL_BUT_LAST.contains(name) { Some((PlanKind::Forward, KeySpec::AllButLast, KeyMode::Literal, ResponsePolicy::Raw, Arity::AtLeastThree)) }
        else { None }
    })?;
    Some(GeneratedCommand { plan, keys, key_mode, response, arity })
}
