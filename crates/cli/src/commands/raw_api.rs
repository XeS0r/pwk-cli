//! `api METHOD PATH [--data …] [--query k=v]…`: a raw request, JSON out.

use std::io::Read as _;
use std::process::ExitCode;

use anyhow::Context as _;
use serde_json::Value;

use super::Context;
use super::client::with_api;
use crate::cli::{ApiArgs, ApiData};
use crate::output;

/// Reads and parses the request body of `--data`.
pub fn request_body(data: Option<&ApiData>) -> anyhow::Result<Option<Value>> {
    let text = match data {
        None => return Ok(None),
        Some(ApiData::Json(text)) => text.clone(),
        Some(ApiData::File(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?,
        Some(ApiData::Stdin) => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("cannot read the request body from stdin")?;
            text
        }
    };
    let value = serde_json::from_str(&text).context("--data is not valid JSON")?;
    Ok(Some(value))
}

/// `api`.
pub fn run(ctx: &Context, args: &ApiArgs) -> anyhow::Result<ExitCode> {
    let body = request_body(args.data.as_ref())?;
    with_api(ctx, |api| {
        let response =
            api.client
                .call(args.method.as_str(), &args.path, &args.query, body.as_ref())?;
        output::print_json(&response)?;
        Ok(ExitCode::SUCCESS)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies() {
        assert_eq!(request_body(None).unwrap(), None);
        let json = ApiData::Json(r#"{"a":1}"#.into());
        assert_eq!(
            request_body(Some(&json)).unwrap(),
            Some(serde_json::json!({"a": 1}))
        );
        let bad = ApiData::Json("{".into());
        assert!(request_body(Some(&bad)).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.json");
        std::fs::write(&path, "[1]").unwrap();
        assert_eq!(
            request_body(Some(&ApiData::File(path))).unwrap(),
            Some(serde_json::json!([1]))
        );
    }
}
