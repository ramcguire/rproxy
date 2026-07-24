use crate::protocol::Command;
use bytes::Bytes;
use smallvec::SmallVec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    Auth,
    Hello,
    Ping,
    Echo,
    Quit,
    Scan,
    Multi,
    Exec,
    Discard,
    Forward {
        keys: KeySpec,
        key_mode: KeyMode,
        response: ResponsePolicy,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySpec {
    First,
    All,
    AllButLast,
    Odd,
    Pair,
    Copy,
    FromTwo,
    CountedFromTwo,
    CountedFromThree,
    DestinationAndCountedFromThree,
    StreamKeys,
    GeoRadius,
    SubcommandKeyAtTwo,
    LcsKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    Literal,
    Pattern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsePolicy {
    Raw,
    KeyArray,
    FirstKeyArray,
    StreamRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanKind {
    Auth,
    Hello,
    Ping,
    Echo,
    Quit,
    Scan,
    Multi,
    Exec,
    Discard,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arity {
    ExactlyOne,
    ExactlyTwo,
    TwoOrThree,
    OneOrTwo,
    AtLeastOne,
    AtLeastTwo,
    AtLeastThree,
    AtLeastFour,
    AtLeastFive,
    OddPairs,
}

#[derive(Debug, Clone, Copy)]
struct GeneratedCommand {
    plan: PlanKind,
    keys: KeySpec,
    key_mode: KeyMode,
    response: ResponsePolicy,
    arity: Arity,
}

include!("catalog_static.rs");

pub fn plan(command: &Command) -> Result<Plan, &'static str> {
    let generated =
        lookup_static(command.name()).ok_or("ERR command is not supported by rproxy phase 2")?;
    if !generated.arity.accepts(command.args.len()) {
        return Err("ERR wrong number of arguments for command");
    }
    Ok(match generated.plan {
        PlanKind::Auth => Plan::Auth,
        PlanKind::Hello => Plan::Hello,
        PlanKind::Ping => Plan::Ping,
        PlanKind::Echo => Plan::Echo,
        PlanKind::Quit => Plan::Quit,
        PlanKind::Scan => Plan::Scan,
        PlanKind::Multi => Plan::Multi,
        PlanKind::Exec => Plan::Exec,
        PlanKind::Discard => Plan::Discard,
        PlanKind::Forward => Plan::Forward {
            keys: generated.keys,
            key_mode: generated.key_mode,
            response: generated.response,
        },
    })
}

impl Arity {
    fn accepts(self, count: usize) -> bool {
        match self {
            Self::ExactlyOne => count == 1,
            Self::ExactlyTwo => count == 2,
            Self::TwoOrThree => matches!(count, 2 | 3),
            Self::OneOrTwo => matches!(count, 1 | 2),
            Self::AtLeastOne => count >= 1,
            Self::AtLeastTwo => count >= 2,
            Self::AtLeastThree => count >= 3,
            Self::AtLeastFour => count >= 4,
            Self::AtLeastFive => count >= 5,
            Self::OddPairs => count >= 3 && (count - 1).is_multiple_of(2),
        }
    }
}

fn lookup_static(name: &[u8]) -> Option<GeneratedCommand> {
    let name = std::str::from_utf8(name).ok()?;
    if name.as_bytes().iter().all(u8::is_ascii_uppercase) {
        return lookup_generated(name);
    }
    if !name.is_ascii() {
        return None;
    }
    let mut uppercase = SmallVec::<[u8; 32]>::with_capacity(name.len());
    uppercase.extend(name.bytes().map(|byte| byte.to_ascii_uppercase()));
    lookup_generated(std::str::from_utf8(&uppercase).ok()?)
}

pub fn key_indices(command: &Command, spec: KeySpec) -> Result<SmallVec<[usize; 4]>, &'static str> {
    let count = command.args.len();
    let indices = match spec {
        KeySpec::First if count >= 2 => smallvec::smallvec![1],
        KeySpec::All if count >= 2 => (1..count).collect(),
        KeySpec::AllButLast if count >= 3 => (1..count - 1).collect(),
        KeySpec::Odd if count >= 3 && (count - 1).is_multiple_of(2) => {
            (1..count).step_by(2).collect()
        }
        KeySpec::Pair if count >= 3 => smallvec::smallvec![1, 2],
        KeySpec::Copy => copy_key_indices(command)?,
        KeySpec::FromTwo if count >= 4 => (2..count).collect(),
        KeySpec::CountedFromTwo => counted_indices(command, 1, 2, false)?,
        KeySpec::CountedFromThree => counted_indices(command, 2, 3, false)?,
        KeySpec::DestinationAndCountedFromThree => counted_indices(command, 2, 3, true)?,
        KeySpec::StreamKeys => stream_key_indices(command)?,
        KeySpec::GeoRadius => geo_radius_key_indices(command)?,
        KeySpec::SubcommandKeyAtTwo => subcommand_key_at_two(command)?,
        KeySpec::LcsKeys => lcs_key_indices(command)?,
        _ => return Err("ERR wrong number of arguments for command"),
    };
    Ok(indices)
}

fn geo_radius_key_indices(command: &Command) -> Result<SmallVec<[usize; 4]>, &'static str> {
    let mut index = match command.name() {
        name if name.eq_ignore_ascii_case(b"GEORADIUS") => 6,
        name if name.eq_ignore_ascii_case(b"GEORADIUSBYMEMBER") => 5,
        _ => return Err("ERR invalid geo radius command"),
    };
    if command.args.len() < index {
        return Err("ERR wrong number of arguments for command");
    }

    let mut indices = smallvec::smallvec![1];
    let mut has_store = false;
    while index < command.args.len() {
        let option = &command.args[index];
        if option.eq_ignore_ascii_case(b"WITHCOORD")
            || option.eq_ignore_ascii_case(b"WITHDIST")
            || option.eq_ignore_ascii_case(b"WITHHASH")
            || option.eq_ignore_ascii_case(b"ASC")
            || option.eq_ignore_ascii_case(b"DESC")
        {
            index += 1;
        } else if option.eq_ignore_ascii_case(b"COUNT") {
            if index + 1 >= command.args.len() {
                return Err("ERR invalid GEORADIUS COUNT option");
            }
            index += 2;
            if command
                .args
                .get(index)
                .is_some_and(|value| value.eq_ignore_ascii_case(b"ANY"))
            {
                index += 1;
            }
        } else if option.eq_ignore_ascii_case(b"STORE") || option.eq_ignore_ascii_case(b"STOREDIST")
        {
            if has_store || index + 1 >= command.args.len() {
                return Err("ERR invalid GEORADIUS store option");
            }
            indices.push(index + 1);
            has_store = true;
            index += 2;
        } else {
            return Err("ERR invalid GEORADIUS option");
        }
    }
    Ok(indices)
}

fn subcommand_key_at_two(command: &Command) -> Result<SmallVec<[usize; 4]>, &'static str> {
    let Some(subcommand) = command.args.get(1) else {
        return Err("ERR wrong number of arguments for command");
    };
    let supported = match command.name() {
        name if name.eq_ignore_ascii_case(b"XGROUP") => {
            subcommand.eq_ignore_ascii_case(b"CREATE")
                || subcommand.eq_ignore_ascii_case(b"CREATECONSUMER")
                || subcommand.eq_ignore_ascii_case(b"DELCONSUMER")
                || subcommand.eq_ignore_ascii_case(b"DESTROY")
                || subcommand.eq_ignore_ascii_case(b"SETID")
        }
        name if name.eq_ignore_ascii_case(b"XINFO") => {
            subcommand.eq_ignore_ascii_case(b"STREAM")
                || subcommand.eq_ignore_ascii_case(b"GROUPS")
                || subcommand.eq_ignore_ascii_case(b"CONSUMERS")
        }
        name if name.eq_ignore_ascii_case(b"OBJECT") => {
            subcommand.eq_ignore_ascii_case(b"ENCODING")
                || subcommand.eq_ignore_ascii_case(b"FREQ")
                || subcommand.eq_ignore_ascii_case(b"IDLETIME")
                || subcommand.eq_ignore_ascii_case(b"REFCOUNT")
        }
        name if name.eq_ignore_ascii_case(b"MEMORY") => subcommand.eq_ignore_ascii_case(b"USAGE"),
        _ => false,
    };
    if !supported || command.args.len() < 3 {
        return Err("ERR unsupported command subcommand");
    }
    Ok(smallvec::smallvec![2])
}

fn lcs_key_indices(command: &Command) -> Result<SmallVec<[usize; 4]>, &'static str> {
    if command.args.len() < 4 || !command.args[1].eq_ignore_ascii_case(b"KEYS") {
        return Err("ERR LCS requires KEYS key1 key2");
    }
    let mut index = 4;
    while index < command.args.len() {
        let option = &command.args[index];
        if option.eq_ignore_ascii_case(b"LEN")
            || option.eq_ignore_ascii_case(b"IDX")
            || option.eq_ignore_ascii_case(b"WITHMATCHLEN")
        {
            index += 1;
        } else if option.eq_ignore_ascii_case(b"MINMATCHLEN") {
            if index + 1 >= command.args.len() {
                return Err("ERR invalid LCS MINMATCHLEN option");
            }
            index += 2;
        } else {
            return Err("ERR invalid LCS option");
        }
    }
    Ok(smallvec::smallvec![2, 3])
}

fn copy_key_indices(command: &Command) -> Result<SmallVec<[usize; 4]>, &'static str> {
    if command.args.len() < 3 {
        return Err("ERR wrong number of arguments for command");
    }
    let mut index = 3;
    while index < command.args.len() {
        let option = &command.args[index];
        if option.eq_ignore_ascii_case(b"REPLACE") {
            index += 1;
        } else if option.eq_ignore_ascii_case(b"DB") {
            return Err("ERR COPY DB is not supported by rproxy");
        } else {
            return Err("ERR invalid COPY option");
        }
    }
    Ok(smallvec::smallvec![1, 2])
}

fn counted_indices(
    command: &Command,
    count_index: usize,
    first_key: usize,
    include_destination: bool,
) -> Result<SmallVec<[usize; 4]>, &'static str> {
    let key_count = std::str::from_utf8(
        command
            .args
            .get(count_index)
            .ok_or("ERR wrong number of arguments for command")?,
    )
    .ok()
    .and_then(|value| value.parse::<usize>().ok())
    .filter(|count| *count > 0)
    .ok_or("ERR invalid numkeys argument")?;
    let end = first_key
        .checked_add(key_count)
        .ok_or("ERR invalid numkeys argument")?;
    if end > command.args.len() {
        return Err("ERR wrong number of arguments for command");
    }
    let mut indices = SmallVec::new();
    if include_destination {
        indices.push(1);
    }
    indices.extend(first_key..end);
    Ok(indices)
}

fn stream_key_indices(command: &Command) -> Result<SmallVec<[usize; 4]>, &'static str> {
    let mut index = match command.name() {
        name if name.eq_ignore_ascii_case(b"XREAD") => 1,
        name if name.eq_ignore_ascii_case(b"XREADGROUP") => {
            if command.args.len() < 5 || !command.args[1].eq_ignore_ascii_case(b"GROUP") {
                return Err("ERR invalid XREADGROUP arguments");
            }
            4
        }
        _ => return Err("ERR invalid stream command"),
    };
    while index < command.args.len() {
        let argument = &command.args[index];
        if argument.eq_ignore_ascii_case(b"STREAMS") {
            let first_key = index + 1;
            let trailing = command.args.len().saturating_sub(first_key);
            if trailing == 0 || !trailing.is_multiple_of(2) {
                return Err("ERR invalid XREAD stream arguments");
            }
            return Ok((first_key..first_key + trailing / 2).collect());
        }
        if argument.eq_ignore_ascii_case(b"COUNT") {
            index += 2;
        } else if argument.eq_ignore_ascii_case(b"BLOCK") {
            return Err("ERR blocking XREAD is not supported by rproxy");
        } else if command.name().eq_ignore_ascii_case(b"XREADGROUP")
            && argument.eq_ignore_ascii_case(b"NOACK")
        {
            index += 1;
        } else {
            return Err("ERR invalid XREAD option");
        }
    }
    Err("ERR XREAD requires a STREAMS argument")
}

pub fn rewrite(
    command: &Command,
    key_indices: &[usize],
    mut rewrite_key: impl FnMut(&[u8]) -> Bytes,
) -> Vec<Bytes> {
    let mut arguments = command.args.clone();
    for index in key_indices {
        arguments[*index] = rewrite_key(&command.args[*index]);
    }
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_every_key_in_mset() {
        let command = Command {
            args: vec![
                Bytes::from_static(b"MSET"),
                Bytes::from_static(b"cart:42"),
                Bytes::from_static(b"active"),
                Bytes::from_static(b"cart:43"),
                Bytes::from_static(b"pending"),
            ],
        };
        let plan = plan(&command).unwrap();
        let Plan::Forward { keys, .. } = plan else {
            panic!("MSET must be forwarded");
        };
        let rewritten = rewrite(&command, &key_indices(&command, keys).unwrap(), |key| {
            Bytes::from([b"tenant:".as_slice(), key].concat())
        });
        assert_eq!(rewritten[1], b"tenant:cart:42"[..]);
        assert_eq!(rewritten[3], b"tenant:cart:43"[..]);
    }

    #[test]
    fn rejects_invalid_mset_pairing() {
        let command = Command {
            args: vec![Bytes::from_static(b"MSET"), Bytes::from_static(b"a")],
        };
        assert_eq!(
            plan(&command),
            Err("ERR wrong number of arguments for command")
        );
    }

    #[test]
    fn generated_lookup_is_case_insensitive_and_uses_specialized_metadata() {
        let get = Command {
            args: vec![Bytes::from_static(b"gEt"), Bytes::from_static(b"cart:42")],
        };
        assert!(matches!(
            plan(&get),
            Ok(Plan::Forward {
                keys: KeySpec::First,
                key_mode: KeyMode::Literal,
                response: ResponsePolicy::Raw,
            })
        ));

        let bitop = Command {
            args: vec![
                Bytes::from_static(b"BITOP"),
                Bytes::from_static(b"OR"),
                Bytes::from_static(b"destination"),
                Bytes::from_static(b"source"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&bitop).unwrap() else {
            panic!("BITOP must be forwarded");
        };
        assert_eq!(key_indices(&bitop, keys).unwrap().as_slice(), &[2, 3]);
    }

    #[test]
    fn counted_key_metadata_excludes_zunion_options_and_keeps_destination() {
        let command = Command {
            args: vec![
                Bytes::from_static(b"ZUNIONSTORE"),
                Bytes::from_static(b"destination"),
                Bytes::from_static(b"2"),
                Bytes::from_static(b"left"),
                Bytes::from_static(b"right"),
                Bytes::from_static(b"WEIGHTS"),
                Bytes::from_static(b"1"),
                Bytes::from_static(b"2"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&command).unwrap() else {
            panic!("ZUNIONSTORE must be forwarded");
        };
        assert_eq!(key_indices(&command, keys).unwrap().as_slice(), &[1, 3, 4]);
    }

    #[test]
    fn rejects_blocking_pop_without_a_dedicated_lane() {
        for name in [b"BLPOP".as_slice(), b"BLMOVE", b"BRPOPLPUSH"] {
            let command = Command {
                args: vec![
                    Bytes::copy_from_slice(name),
                    Bytes::from_static(b"ready"),
                    Bytes::from_static(b"1"),
                ],
            };
            assert_eq!(
                plan(&command),
                Err("ERR command is not supported by rproxy phase 2")
            );
        }
    }

    #[test]
    fn stream_metadata_rewrites_only_stream_keys_after_validated_options() {
        let command = Command {
            args: vec![
                Bytes::from_static(b"XREADGROUP"),
                Bytes::from_static(b"GROUP"),
                Bytes::from_static(b"STREAMS"),
                Bytes::from_static(b"consumer"),
                Bytes::from_static(b"COUNT"),
                Bytes::from_static(b"2"),
                Bytes::from_static(b"NOACK"),
                Bytes::from_static(b"STREAMS"),
                Bytes::from_static(b"orders"),
                Bytes::from_static(b"invoices"),
                Bytes::from_static(b">"),
                Bytes::from_static(b"$"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&command).unwrap() else {
            panic!("XREADGROUP must be forwarded");
        };
        assert_eq!(key_indices(&command, keys).unwrap().as_slice(), &[8, 9]);
    }

    #[test]
    fn rejects_counted_blocking_pop_without_a_dedicated_lane() {
        let command = Command {
            args: vec![
                Bytes::from_static(b"BLMPOP"),
                Bytes::from_static(b"1"),
                Bytes::from_static(b"2"),
                Bytes::from_static(b"ready"),
                Bytes::from_static(b"delayed"),
                Bytes::from_static(b"MIN"),
            ],
        };
        assert_eq!(
            plan(&command),
            Err("ERR command is not supported by rproxy phase 2")
        );
    }

    #[test]
    fn expanded_static_families_resolve_to_their_declared_key_indices() {
        let cases = [
            (
                vec![
                    b"GEOSEARCH".as_slice(),
                    b"places".as_slice(),
                    b"FROMLONLAT".as_slice(),
                ],
                vec![1],
            ),
            (
                vec![
                    b"XADD".as_slice(),
                    b"orders".as_slice(),
                    b"*".as_slice(),
                    b"status".as_slice(),
                ],
                vec![1],
            ),
            (
                vec![
                    b"SINTERCARD".as_slice(),
                    b"2".as_slice(),
                    b"left".as_slice(),
                    b"right".as_slice(),
                    b"LIMIT".as_slice(),
                    b"1".as_slice(),
                ],
                vec![2, 3],
            ),
            (
                vec![
                    b"ZMPOP".as_slice(),
                    b"2".as_slice(),
                    b"high".as_slice(),
                    b"low".as_slice(),
                    b"MIN".as_slice(),
                ],
                vec![2, 3],
            ),
        ];
        for (arguments, expected) in cases {
            let command = Command {
                args: arguments.into_iter().map(Bytes::copy_from_slice).collect(),
            };
            let Plan::Forward { keys, .. } = plan(&command).unwrap() else {
                panic!("command must be forwarded");
            };
            assert_eq!(key_indices(&command, keys).unwrap().as_slice(), expected);
        }
    }

    #[test]
    fn geo_radius_rewrites_source_and_store_destination() {
        let command = Command {
            args: vec![
                Bytes::from_static(b"GEORADIUS"),
                Bytes::from_static(b"source"),
                Bytes::from_static(b"0"),
                Bytes::from_static(b"0"),
                Bytes::from_static(b"10"),
                Bytes::from_static(b"km"),
                Bytes::from_static(b"COUNT"),
                Bytes::from_static(b"5"),
                Bytes::from_static(b"ANY"),
                Bytes::from_static(b"STORE"),
                Bytes::from_static(b"destination"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&command).unwrap() else {
            panic!("GEORADIUS must be forwarded");
        };
        let indices = key_indices(&command, keys).unwrap();
        assert_eq!(indices.as_slice(), &[1, 10]);
        let rewritten = rewrite(&command, &indices, |key| {
            Bytes::from([b"tenant:".as_slice(), key].concat())
        });
        assert_eq!(rewritten[1], b"tenant:source"[..]);
        assert_eq!(rewritten[10], b"tenant:destination"[..]);
    }

    #[test]
    fn geo_radius_rejects_unknown_option_forms() {
        let command = Command {
            args: vec![
                Bytes::from_static(b"GEORADIUSBYMEMBER"),
                Bytes::from_static(b"source"),
                Bytes::from_static(b"member"),
                Bytes::from_static(b"10"),
                Bytes::from_static(b"km"),
                Bytes::from_static(b"UNSAFE"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&command).unwrap() else {
            panic!("GEORADIUSBYMEMBER must be forwarded");
        };
        assert_eq!(
            key_indices(&command, keys),
            Err("ERR invalid GEORADIUS option")
        );
    }

    #[test]
    fn contextual_subcommands_rewrite_only_documented_key_positions() {
        let commands = [
            vec![
                b"XGROUP".as_slice(),
                b"CREATE".as_slice(),
                b"orders".as_slice(),
                b"group".as_slice(),
                b"$".as_slice(),
            ],
            vec![
                b"XINFO".as_slice(),
                b"STREAM".as_slice(),
                b"orders".as_slice(),
            ],
            vec![
                b"OBJECT".as_slice(),
                b"FREQ".as_slice(),
                b"orders".as_slice(),
            ],
            vec![
                b"MEMORY".as_slice(),
                b"USAGE".as_slice(),
                b"orders".as_slice(),
            ],
        ];
        for arguments in commands {
            let command = Command {
                args: arguments.into_iter().map(Bytes::copy_from_slice).collect(),
            };
            let Plan::Forward { keys, .. } = plan(&command).unwrap() else {
                panic!("contextual command must be forwarded");
            };
            assert_eq!(key_indices(&command, keys).unwrap().as_slice(), &[2]);
        }
    }

    #[test]
    fn rejects_unrecognized_contextual_subcommands() {
        let command = Command {
            args: vec![
                Bytes::from_static(b"MEMORY"),
                Bytes::from_static(b"STATS"),
                Bytes::from_static(b"unrelated"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&command).unwrap() else {
            panic!("MEMORY must be classified before its subcommand is validated");
        };
        assert_eq!(
            key_indices(&command, keys),
            Err("ERR unsupported command subcommand")
        );
    }

    #[test]
    fn lcs_keys_rewrites_both_inputs_and_rejects_string_mode() {
        let command = Command {
            args: vec![
                Bytes::from_static(b"LCS"),
                Bytes::from_static(b"KEYS"),
                Bytes::from_static(b"left"),
                Bytes::from_static(b"right"),
                Bytes::from_static(b"IDX"),
                Bytes::from_static(b"MINMATCHLEN"),
                Bytes::from_static(b"2"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&command).unwrap() else {
            panic!("LCS must be forwarded");
        };
        assert_eq!(key_indices(&command, keys).unwrap().as_slice(), &[2, 3]);

        let strings = Command {
            args: vec![
                Bytes::from_static(b"LCS"),
                Bytes::from_static(b"STRINGS"),
                Bytes::from_static(b"left"),
                Bytes::from_static(b"right"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&strings).unwrap() else {
            panic!("LCS must be forwarded");
        };
        assert_eq!(
            key_indices(&strings, keys),
            Err("ERR LCS requires KEYS key1 key2")
        );
    }

    #[test]
    fn rejects_blocking_stream_reads_and_copy_db() {
        let blocking_read = Command {
            args: vec![
                Bytes::from_static(b"XREAD"),
                Bytes::from_static(b"BLOCK"),
                Bytes::from_static(b"0"),
                Bytes::from_static(b"STREAMS"),
                Bytes::from_static(b"orders"),
                Bytes::from_static(b"$"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&blocking_read).unwrap() else {
            panic!("XREAD must be classified before options are validated");
        };
        assert_eq!(
            key_indices(&blocking_read, keys),
            Err("ERR blocking XREAD is not supported by rproxy")
        );

        let copy = Command {
            args: vec![
                Bytes::from_static(b"COPY"),
                Bytes::from_static(b"source"),
                Bytes::from_static(b"destination"),
                Bytes::from_static(b"DB"),
                Bytes::from_static(b"1"),
            ],
        };
        let Plan::Forward { keys, .. } = plan(&copy).unwrap() else {
            panic!("COPY must be classified before options are validated");
        };
        assert_eq!(
            key_indices(&copy, keys),
            Err("ERR COPY DB is not supported by rproxy")
        );
    }
}
