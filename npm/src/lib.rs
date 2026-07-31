#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use napi::{bindgen_prelude::*, Error, Status};
use pledgeshield::models::{Category, Finding, ScanResult, Severity};

#[napi(object)]
pub struct NapiScanOptions {
  pub cve: Option<bool>,
  pub format: Option<String>,
  pub min_severity: Option<String>,
  pub offline: Option<bool>,
}

#[napi]
pub fn scan_sync(options: Option<NapiScanOptions>) -> Result<String> {
  let _opts = options.unwrap_or(NapiScanOptions {
    cve: None,
    format: None,
    min_severity: None,
    offline: None,
  });

  // Run a basic scan and return text output
  let mut result = ScanResult::new();

  // Placeholder: in production, this would invoke the full scan pipeline
  result.finalize();

  let mut buf = String::new();
  buf.push_str(&format!("PledgeShield Scan Report\n"));
  buf.push_str(&format!("Host: {}\n", result.hostname));
  buf.push_str(&format!("Findings: {}\n", result.summary.total));

  Ok(buf)
}

#[napi]
pub async fn run_scan(options: Option<NapiScanOptions>) -> Result<String> {
  // For async, we use tokio to run the scan in a blocking task
  let result = tokio::task::spawn_blocking(move || {
    scan_sync(options)
  })
  .await
  .map_err(|e| Error::new(Status::GenericFailure, format!("Scan task failed: {}", e)))?;

  result
}
