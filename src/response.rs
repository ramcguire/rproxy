use crate::tenant::Tenant;

pub fn sanitize_key_array(response: &[u8], tenant: &Tenant) -> Result<Vec<u8>, &'static str> {
    if response.starts_with(b"-") {
        return Ok(response.to_vec());
    }
    let (header, mut offset) = take_line(response, 0)?;
    let count = parse_count(header, b'*', "ERR invalid upstream key response")?;
    if count > response.len().saturating_sub(offset) / 6 {
        return Err("ERR invalid upstream key response");
    }
    let mut logical_keys = Vec::with_capacity(count);

    for _ in 0..count {
        let (key, next_offset) =
            bulk_payload(response, offset, "ERR invalid upstream key response")?;
        if let Some(logical_key) = tenant.strip_key(key) {
            logical_keys.push(logical_key);
        }
        offset = next_offset;
    }
    if offset != response.len() {
        return Err("ERR invalid upstream key response");
    }

    let mut sanitized = format!("*{}\r\n", logical_keys.len()).into_bytes();
    for key in logical_keys {
        append_bulk(&mut sanitized, &key);
    }
    Ok(sanitized)
}

pub fn sanitize_first_key_array(response: &[u8], tenant: &Tenant) -> Result<Vec<u8>, &'static str> {
    const MESSAGE: &str = "ERR invalid upstream keyed response";
    if response.starts_with(b"-") || response == b"*-1\r\n" || response == b"_\r\n" {
        return Ok(response.to_vec());
    }
    let (header, offset) = take_line(response, 0)?;
    let count = parse_count(header, b'*', MESSAGE)?;
    if count == 0 {
        return Err(MESSAGE);
    }

    let mut sanitized = Vec::with_capacity(response.len());
    sanitized.extend_from_slice(&response[..offset]);
    let rest_offset = append_sanitized_bulk(response, offset, tenant, &mut sanitized, MESSAGE)?;
    sanitized.extend_from_slice(&response[rest_offset..]);
    Ok(sanitized)
}

pub fn sanitize_scan(response: &[u8], tenant: &Tenant) -> Result<Vec<u8>, &'static str> {
    if response.starts_with(b"-") {
        return Ok(response.to_vec());
    }
    let (header, header_end) = take_line(response, 0)?;
    if parse_count(header, b'*', "ERR invalid upstream scan response")? != 2 {
        return Err("ERR invalid upstream scan response");
    }
    let cursor_end = bulk_end(response, header_end, "ERR invalid upstream scan response")?;
    let sanitized_keys = sanitize_key_array(&response[cursor_end..], tenant)?;
    let mut sanitized = b"*2\r\n".to_vec();
    sanitized.extend_from_slice(&response[header_end..cursor_end]);
    sanitized.extend_from_slice(&sanitized_keys);
    Ok(sanitized)
}

pub fn sanitize_stream_read(response: &[u8], tenant: &Tenant) -> Result<Vec<u8>, &'static str> {
    const MESSAGE: &str = "ERR invalid upstream stream response";
    if response.starts_with(b"-") || response == b"*-1\r\n" || response == b"_\r\n" {
        return Ok(response.to_vec());
    }
    let (header, mut offset) = take_line(response, 0)?;
    let count = parse_count(header, b'*', MESSAGE)?;
    let mut sanitized = Vec::with_capacity(response.len());
    sanitized.extend_from_slice(&response[..offset]);

    for _ in 0..count {
        let stream_header_start = offset;
        let (stream_header, stream_payload_offset) = take_line(response, offset)?;
        if parse_count(stream_header, b'*', MESSAGE)? != 2 {
            return Err(MESSAGE);
        }
        sanitized.extend_from_slice(&response[stream_header_start..stream_payload_offset]);
        let entries_offset = append_sanitized_bulk(
            response,
            stream_payload_offset,
            tenant,
            &mut sanitized,
            MESSAGE,
        )?;
        let stream_end = frame_end(response, entries_offset, MESSAGE)?;
        sanitized.extend_from_slice(&response[entries_offset..stream_end]);
        offset = stream_end;
    }
    if offset != response.len() {
        return Err(MESSAGE);
    }
    Ok(sanitized)
}

fn append_sanitized_bulk(
    input: &[u8],
    offset: usize,
    tenant: &Tenant,
    output: &mut Vec<u8>,
    message: &'static str,
) -> Result<usize, &'static str> {
    let (physical_key, next_offset) = bulk_payload(input, offset, message)?;
    let logical_key = tenant.strip_key(physical_key).ok_or(message)?;
    append_bulk(output, &logical_key);
    Ok(next_offset)
}

fn append_bulk(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(format!("${}\r\n", value.len()).as_bytes());
    output.extend_from_slice(value);
    output.extend_from_slice(b"\r\n");
}

fn bulk_end(input: &[u8], offset: usize, message: &'static str) -> Result<usize, &'static str> {
    bulk_payload(input, offset, message).map(|(_, end)| end)
}

fn bulk_payload<'a>(
    input: &'a [u8],
    offset: usize,
    message: &'static str,
) -> Result<(&'a [u8], usize), &'static str> {
    let (header, payload_offset) = take_line(input, offset)?;
    let length = parse_count(header, b'$', message)?;
    let end = payload_offset
        .checked_add(length)
        .and_then(|index| index.checked_add(2))
        .ok_or(message)?;
    if end > input.len() || &input[payload_offset + length..end] != b"\r\n" {
        return Err(message);
    }
    Ok((&input[payload_offset..payload_offset + length], end))
}

fn frame_end(input: &[u8], offset: usize, message: &'static str) -> Result<usize, &'static str> {
    frame_end_with_depth(input, offset, message, 0)
}

fn frame_end_with_depth(
    input: &[u8],
    offset: usize,
    message: &'static str,
    depth: usize,
) -> Result<usize, &'static str> {
    if depth > 64 {
        return Err(message);
    }
    let (header, payload_offset) = take_line(input, offset)?;
    match header.first() {
        Some(b'+' | b'-' | b':' | b'_' | b'#' | b',' | b'(') => Ok(payload_offset),
        Some(b'$' | b'!' | b'=') => bulk_end(input, offset, message),
        Some(b'*' | b'~' | b'>') => aggregate_end(input, payload_offset, header, 1, message, depth),
        Some(b'%' | b'|') => aggregate_end(input, payload_offset, header, 2, message, depth),
        _ => Err(message),
    }
}

fn aggregate_end(
    input: &[u8],
    mut offset: usize,
    header: &[u8],
    multiplier: usize,
    message: &'static str,
    depth: usize,
) -> Result<usize, &'static str> {
    let Some(count) = parse_len(header, header[0], message)? else {
        return Ok(offset);
    };
    let children = count.checked_mul(multiplier).ok_or(message)?;
    for _ in 0..children {
        offset = frame_end_with_depth(input, offset, message, depth + 1)?;
    }
    Ok(offset)
}

fn take_line(input: &[u8], offset: usize) -> Result<(&[u8], usize), &'static str> {
    let suffix = input
        .get(offset..)
        .ok_or("ERR invalid upstream key response")?;
    let line_end = suffix
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or("ERR invalid upstream key response")?;
    Ok((&suffix[..line_end], offset + line_end + 2))
}

fn parse_count(
    header: &[u8],
    expected_type: u8,
    message: &'static str,
) -> Result<usize, &'static str> {
    parse_len(header, expected_type, message)?.ok_or(message)
}

fn parse_len(
    header: &[u8],
    expected_type: u8,
    message: &'static str,
) -> Result<Option<usize>, &'static str> {
    if header.first() != Some(&expected_type) {
        return Err(message);
    }
    let value = std::str::from_utf8(&header[1..])
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(message)?;
    if value == -1 {
        return Ok(None);
    }
    if value < -1 {
        return Err(message);
    }
    usize::try_from(value).map(Some).map_err(|_| message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::TenantConfig, tenant::TenantRegistry};

    #[test]
    fn strips_only_the_authenticated_tenant_prefix() {
        let registry = TenantRegistry::new(&[TenantConfig {
            id: "payments".to_owned(),
            username: None,
            password: "secret".to_owned(),
            partition_count: 256,
        }]);
        let tenant = registry.authenticate(None, b"secret").unwrap();
        let physical = tenant.rewrite_key(b"cart:42");
        let unrelated = b"__rproxy:v1:{t/other/d/0/p/0}:cart:43";
        let response = [
            format!("*2\r\n${}\r\n", physical.len()).into_bytes(),
            physical.to_vec(),
            b"\r\n".to_vec(),
            format!("${}\r\n", unrelated.len()).into_bytes(),
            unrelated.to_vec(),
            b"\r\n".to_vec(),
        ]
        .concat();

        assert_eq!(
            sanitize_key_array(&response, &tenant).unwrap(),
            b"*1\r\n$7\r\ncart:42\r\n"
        );
    }

    #[test]
    fn preserves_scan_cursor_while_sanitizing_keys() {
        let registry = TenantRegistry::new(&[TenantConfig {
            id: "payments".to_owned(),
            username: None,
            password: "secret".to_owned(),
            partition_count: 256,
        }]);
        let tenant = registry.authenticate(None, b"secret").unwrap();
        let physical = tenant.rewrite_key(b"cart:42");
        let response = [
            b"*2\r\n$1\r\n7\r\n*1\r\n".to_vec(),
            format!("${}\r\n", physical.len()).into_bytes(),
            physical.to_vec(),
            b"\r\n".to_vec(),
        ]
        .concat();

        assert_eq!(
            sanitize_scan(&response, &tenant).unwrap(),
            b"*2\r\n$1\r\n7\r\n*1\r\n$7\r\ncart:42\r\n"
        );
    }

    #[test]
    fn sanitizes_key_bearing_pop_and_stream_replies() {
        let registry = TenantRegistry::new(&[TenantConfig {
            id: "payments".to_owned(),
            username: None,
            password: "secret".to_owned(),
            partition_count: 256,
        }]);
        let tenant = registry.authenticate(None, b"secret").unwrap();
        let physical = tenant.rewrite_key(b"orders");

        let pop_response = [
            format!("*2\r\n${}\r\n", physical.len()).into_bytes(),
            physical.to_vec(),
            b"\r\n$5\r\nvalue\r\n".to_vec(),
        ]
        .concat();
        assert_eq!(
            sanitize_first_key_array(&pop_response, &tenant).unwrap(),
            b"*2\r\n$6\r\norders\r\n$5\r\nvalue\r\n"
        );

        let stream_response = [
            b"*1\r\n*2\r\n".to_vec(),
            format!("${}\r\n", physical.len()).into_bytes(),
            physical.to_vec(),
            b"\r\n*1\r\n*2\r\n$1\r\n0\r\n*2\r\n$1\r\nf\r\n$1\r\nv\r\n".to_vec(),
        ]
        .concat();
        assert_eq!(
            sanitize_stream_read(&stream_response, &tenant).unwrap(),
            b"*1\r\n*2\r\n$6\r\norders\r\n*1\r\n*2\r\n$1\r\n0\r\n*2\r\n$1\r\nf\r\n$1\r\nv\r\n"
        );
    }

    #[test]
    fn rejects_an_impossible_key_count_before_reserving() {
        let registry = TenantRegistry::new(&[TenantConfig {
            id: "payments".to_owned(),
            username: None,
            password: "secret".to_owned(),
            partition_count: 256,
        }]);
        let tenant = registry.authenticate(None, b"secret").unwrap();
        assert!(sanitize_key_array(b"*100000000\r\n", &tenant).is_err());
    }
}
