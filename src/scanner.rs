use crate::extract::{extract_secrets_filtered, is_env_content, parse_env};
use reqwest::Client;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

pub static PATHS: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.env.dev",
    "/.env.development",
    "/.env.prod",
    "/.env.production",
    "/.env.staging",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/.env.save",
    "/.env.swp",
    "/config/.env",
    "/api/.env",
    "/backend/.env",
    "/app/.env",
];

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub target: String,
    pub url: String,
    pub len: usize,
    /// category -> [(name, value), ...]
    pub secrets: BTreeMap<String, Vec<(String, String)>>,
    pub env: BTreeMap<String, String>,
    /// Raw .env lines that matched, preserved in original order & form.
    pub lines: Vec<String>,
    #[serde(skip)]
    pub raw: String,
}

/// Normalize a target into a full URL. Does NOT strip paths.
///   example.com            -> https://example.com
///   example.com/           -> https://example.com
///   example.com/.env       -> https://example.com/.env
///   http://lab.local/.env  -> http://lab.local/.env
fn normalize(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

/// True if the URL has a real path beyond "/".
fn has_explicit_path(url: &str) -> bool {
    match reqwest::Url::parse(url) {
        Ok(u) => {
            let p = u.path();
            !p.is_empty() && p != "/"
        }
        Err(_) => false,
    }
}

/// Decide which URLs to actually request for a target.
///
/// - Target already contains a path (e.g. `host/.env`) -> request exactly it.
/// - Bare host -> sweep the PATHS list.
fn urls_for_target(target: &str) -> Vec<String> {
    let base = normalize(target);
    if has_explicit_path(&base) {
        vec![base]
    } else {
        PATHS.iter().map(|p| format!("{}{}", base, p)).collect()
    }
}

pub async fn scan_target(
    client: &Client,
    semaphore: Arc<Semaphore>,
    target: &str,
    cats: &[String],
) -> Vec<Finding> {
    let urls = urls_for_target(target);
    let mut findings: Vec<Finding> = Vec::new();

    for url in urls {
        let _permit = match semaphore.acquire().await {
            Ok(p) => p,
            Err(_) => break,
        };

        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        if resp.status() != reqwest::StatusCode::OK {
            continue;
        }

        let body: String = match resp.text().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        if !is_env_content(&body) {
            continue;
        }

        let secrets = extract_secrets_filtered(&body, cats);
        if secrets.is_empty() {
            continue; // nothing matched our filter
        }

        // Collect every matched value so we can keep only the .env lines
        // that actually contained a hit.
        let flat_values: std::collections::HashSet<String> = secrets
            .values()
            .flat_map(|v| v.iter().map(|(_, val)| val.clone()))
            .collect();

        let lines: Vec<String> = body
            .lines()
            .map(|l| l.trim_end().to_string())
            .filter(|l| {
                let t = l.trim();
                if t.is_empty() || t.starts_with('#') {
                    return false;
                }
                if let Some((_, v)) = t.split_once('=') {
                    let v = v.trim().trim_matches('"').trim_matches('\'');
                    if flat_values.contains(v) {
                        return true;
                    }
                }
                secrets
                    .values()
                    .flatten()
                    .any(|(name, _)| t.contains(name.as_str()))
            })
            .collect();

        findings.push(Finding {
            target: target.to_string(),
            url,
            len: body.len(),
            secrets,
            env: parse_env(&body),
            lines,
            raw: body,
        });
    }

    findings
}
