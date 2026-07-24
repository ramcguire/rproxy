use bytes::Bytes;
use memchr::memchr;
use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub args: Vec<Bytes>,
}

impl Command {
    pub fn name(&self) -> &[u8] {
        self.args.first().map(Bytes::as_ref).unwrap_or_default()
    }
}

pub async fn read_command<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> io::Result<Option<Command>> {
    let Some(header) = read_line(reader, max_frame_bytes).await? else {
        return Ok(None);
    };
    if header.first() != Some(&b'*') {
        return invalid_data("requests must be RESP arrays");
    }

    let count = parse_usize(&header[1..], "invalid array length")?;
    if count == 0 {
        return invalid_data("commands must not be empty");
    }

    if count > max_frame_bytes / 6 {
        return invalid_data("RESP command has too many arguments");
    }

    let mut remaining = header.len();
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(length_header) =
            read_line(reader, max_frame_bytes.saturating_sub(remaining)).await?
        else {
            return unexpected_eof();
        };
        remaining = checked_add(remaining, length_header.len(), max_frame_bytes)?;
        if length_header.first() != Some(&b'$') {
            return invalid_data("command arguments must be bulk strings");
        }
        let length = parse_usize(&length_header[1..], "invalid bulk string length")?;
        let payload_and_terminator = length.checked_add(2).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "bulk string length overflow")
        })?;
        remaining = checked_add(remaining, payload_and_terminator, max_frame_bytes)?;

        let mut value = vec![0; length];
        reader.read_exact(&mut value).await?;
        let mut terminator = [0; 2];
        reader.read_exact(&mut terminator).await?;
        if terminator != *b"\r\n" {
            return invalid_data("bulk string is missing CRLF terminator");
        }
        args.push(Bytes::from(value));
    }

    Ok(Some(Command { args }))
}

pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    let Some(first_line) = read_line(reader, max_frame_bytes).await? else {
        return Ok(None);
    };
    let mut frame = first_line;
    read_frame_after_first_line(reader, &mut frame, max_frame_bytes, 0).await?;
    Ok(Some(frame))
}

async fn read_frame_after_first_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    max_frame_bytes: usize,
    depth: usize,
) -> io::Result<()> {
    let header = frame.clone();
    consume_value(reader, frame, &header, max_frame_bytes, depth).await
}

async fn consume_value<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    header: &[u8],
    max_frame_bytes: usize,
    depth: usize,
) -> io::Result<()> {
    const MAX_NESTING: usize = 64;
    if depth > MAX_NESTING {
        return invalid_data("RESP nesting limit exceeded");
    }

    match header.first() {
        Some(b'+' | b'-' | b':' | b'_' | b'#' | b',' | b'(') => Ok(()),
        Some(b'$' | b'!' | b'=') => read_bulk_tail(reader, frame, header, max_frame_bytes).await,
        Some(b'*' | b'~' | b'>') => {
            read_aggregate_tail(reader, frame, header, max_frame_bytes, depth, 1).await
        }
        Some(b'%' | b'|') => {
            read_aggregate_tail(reader, frame, header, max_frame_bytes, depth, 2).await
        }
        _ => invalid_data("unsupported RESP frame type"),
    }
}

async fn read_nested_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    max_frame_bytes: usize,
    depth: usize,
) -> io::Result<()> {
    let Some(header) = read_line(reader, max_frame_bytes.saturating_sub(frame.len())).await? else {
        return unexpected_eof();
    };
    append(frame, &header, max_frame_bytes)?;
    consume_value(reader, frame, &header, max_frame_bytes, depth).await
}

async fn read_bulk_tail<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    header: &[u8],
    max_frame_bytes: usize,
) -> io::Result<()> {
    let length = parse_i64(&header[1..], "invalid bulk length")?;
    if length == -1 {
        return Ok(());
    }
    if length < -1 {
        return invalid_data("invalid negative bulk length");
    }
    let length = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bulk length overflow"))?;
    let total = length
        .checked_add(2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bulk length overflow"))?;
    if frame.len().saturating_add(total) > max_frame_bytes {
        return invalid_data("RESP frame exceeds configured limit");
    }

    let start = frame.len();
    frame.resize(start + total, 0);
    reader.read_exact(&mut frame[start..]).await?;
    if frame[start + length..] != *b"\r\n" {
        return invalid_data("bulk response is missing CRLF terminator");
    }
    Ok(())
}

async fn read_aggregate_tail<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    header: &[u8],
    max_frame_bytes: usize,
    depth: usize,
    multiplier: usize,
) -> io::Result<()> {
    let count = parse_i64(&header[1..], "invalid aggregate length")?;
    if count == -1 {
        return Ok(());
    }
    if count < -1 {
        return invalid_data("invalid negative aggregate length");
    }
    let count = usize::try_from(count)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aggregate length overflow"))?;
    let children = count
        .checked_mul(multiplier)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "aggregate length overflow"))?;
    for _ in 0..children {
        Box::pin(read_nested_frame(reader, frame, max_frame_bytes, depth + 1)).await?;
    }
    Ok(())
}

async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let (consumed, complete, chunk) = {
            let buffer = reader.fill_buf().await?;
            if buffer.is_empty() {
                if line.is_empty() {
                    return Ok(None);
                }
                return unexpected_eof();
            }
            let consumed = memchr(b'\n', buffer).map_or(buffer.len(), |position| position + 1);
            let complete = buffer[consumed - 1] == b'\n';
            (consumed, complete, buffer[..consumed].to_vec())
        };
        append(&mut line, &chunk, limit)?;
        reader.consume(consumed);
        if complete {
            if line.len() < 3 || !line.ends_with(b"\r\n") {
                return invalid_data("RESP line is missing CRLF terminator");
            }
            return Ok(Some(line));
        }
    }
}

fn append(target: &mut Vec<u8>, source: &[u8], limit: usize) -> io::Result<()> {
    if target.len().saturating_add(source.len()) > limit {
        return invalid_data("RESP frame exceeds configured limit");
    }
    target.extend_from_slice(source);
    Ok(())
}

fn checked_add(current: usize, added: usize, limit: usize) -> io::Result<usize> {
    let total = current
        .checked_add(added)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RESP frame length overflow"))?;
    if total > limit {
        return invalid_data("RESP frame exceeds configured limit");
    }
    Ok(total)
}

fn parse_usize(value: &[u8], message: &'static str) -> io::Result<usize> {
    let value = strip_crlf(value);
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, message))
}

fn parse_i64(value: &[u8], message: &'static str) -> io::Result<i64> {
    let value = strip_crlf(value);
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, message))
}

fn strip_crlf(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\r\n").unwrap_or(value)
}

fn invalid_data<T>(message: &'static str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn unexpected_eof<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "truncated RESP frame",
    ))
}

pub fn encode_command(args: &[Bytes]) -> Vec<u8> {
    let payload_len = args
        .iter()
        .map(|argument| argument.len() + 32)
        .sum::<usize>();
    let mut encoded = Vec::with_capacity(payload_len + 32);
    encoded.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for argument in args {
        encoded.extend_from_slice(format!("${}\r\n", argument.len()).as_bytes());
        encoded.extend_from_slice(argument);
        encoded.extend_from_slice(b"\r\n");
    }
    encoded
}

pub fn simple(value: &str) -> Vec<u8> {
    format!("+{value}\r\n").into_bytes()
}

pub fn error(value: &str) -> Vec<u8> {
    format!("-{value}\r\n").into_bytes()
}

pub fn bulk(value: &[u8]) -> Vec<u8> {
    let mut encoded = format!("${}\r\n", value.len()).into_bytes();
    encoded.extend_from_slice(value);
    encoded.extend_from_slice(b"\r\n");
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_binary_command_arguments() {
        let encoded = encode_command(&[Bytes::from_static(b"SET"), Bytes::from_static(b"a\0b")]);
        assert_eq!(encoded, b"*2\r\n$3\r\nSET\r\n$3\r\na\0b\r\n");
    }

    #[test]
    fn formats_bulk_reply() {
        assert_eq!(bulk(b"hello"), b"$5\r\nhello\r\n");
    }
}
