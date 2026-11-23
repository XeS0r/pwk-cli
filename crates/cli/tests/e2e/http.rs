//! A minimal HTTP/1.1 server on `std::net` for the fake Passwork API.
//!
//! One thread per connection, one request per connection (`Connection: close`), JSON
//! responses. Good enough for a blocking reqwest client on localhost, and it lets the
//! fake server keep state across requests (create → get), which mockito cannot do.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use serde_json::Value;

/// A parsed request.
#[derive(Debug, Clone)]
pub struct Request {
    /// Upper-case method.
    pub method: String,
    /// Percent-decoded path without the query string.
    pub path: String,
    /// Percent-decoded query parameters in order.
    pub query: Vec<(String, String)>,
    /// Headers, names lower-cased.
    pub headers: HashMap<String, String>,
    /// Raw body.
    pub body: Vec<u8>,
}

impl Request {
    /// The body as JSON (`Null` if empty or invalid).
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// All values of query parameter `key`.
    pub fn query_all(&self, key: &str) -> Vec<&str> {
        self.query
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The first value of query parameter `key`.
    pub fn query_one(&self, key: &str) -> Option<&str> {
        self.query_all(key).into_iter().next()
    }

    /// Header value by (case-insensitive) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Builds a request from a method and a relative URL with optional query string (used
    /// for the sub-requests of `/batch`).
    pub fn from_relative(method: &str, url: &str, parent: &Request, body: Vec<u8>) -> Self {
        let (path, query) = split_target(url);
        Self {
            method: method.to_ascii_uppercase(),
            path,
            query,
            headers: parent.headers.clone(),
            body,
        }
    }
}

/// A response: status and JSON body.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Value,
}

impl Response {
    pub fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }

    pub fn error(status: u16, code: &str, message: &str) -> Self {
        Self {
            status,
            body: serde_json::json!({ "errors": [{ "code": code, "message": message }] }),
        }
    }

    pub fn not_found(what: &str) -> Self {
        Self::error(404, "notFound", &format!("{what} not found"))
    }
}

/// Handler of every request.
pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

/// Starts the server on a random localhost port and returns its base URL
/// (`http://127.0.0.1:PORT`). The accept thread lives until the test process exits.
pub fn serve(handler: Handler) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handler = handler.clone();
            thread::spawn(move || {
                // A broken connection only fails the request that used it.
                let _ = handle_connection(stream, &handler);
            });
        }
    });
    url
}

fn handle_connection(stream: TcpStream, handler: &Handler) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default().to_owned();

    let mut headers = HashMap::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;

    let (path, query) = split_target(&target);
    let request = Request {
        method,
        path,
        query,
        headers,
        body,
    };
    let response = handler(&request);
    let text = serde_json::to_string(&response.body).expect("serialise response");
    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        response.status,
        reason(response.status),
        text.len(),
        text
    )?;
    stream.flush()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Status",
    }
}

fn split_target(target: &str) -> (String, Vec<(String, String)>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k, true), percent_decode(v, true))
        })
        .collect();
    (percent_decode(path, false), query)
}

/// Decodes `%XX` escapes (and `+` as space in query strings).
pub fn percent_decode(text: &str, plus_is_space: bool) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' if plus_is_space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
