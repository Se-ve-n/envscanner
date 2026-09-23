use crate::scanner::Finding;
use async_channel::Receiver;
use colored::Colorize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

pub async fn printer_task(
    rx: Receiver<Finding>,
    json: bool,
    quiet: bool,
    output_path: Option<String>,
    hits_counter: Arc<AtomicUsize>,
) {
    let mut file = match &output_path {
        Some(p) => match tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(p)
            .await
        {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("[!] Could not open output file {}: {}", p, e);
                None
            }
        },
        None => None,
    };

    // Header once, so the file is self-describing.
    if let Some(fh) = file.as_mut() {
        if !json {
            let _ = fh
                .write_all(b"# envscanner results\n# format: \"<category> found\" then the leaked lines\n\n")
                .await;
        }
    }

    while let Ok(f) = rx.recv().await {
        hits_counter.fetch_add(1, Ordering::Relaxed);

        let plain = if json {
            // One JSON object per line.
            let mut s = serde_json::to_string(&f).unwrap_or_default();
            s.push('\n');
            s
        } else {
            render_text(&f, false)
        };

        let colored = if json {
            String::new()
        } else {
            render_text(&f, true)
        };

        if !quiet {
            if json {
                print!("{}", plain);
            } else {
                print!("{}", colored);
            }
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        if let Some(fh) = file.as_mut() {
            if let Err(e) = fh.write_all(plain.as_bytes()).await {
                eprintln!("[!] Write error: {}", e);
            }
        }
    }

    if let Some(mut fh) = file.take() {
        let _ = fh.flush().await;
    }
}

/// Renders one Finding in the exact format:
///
///     SMTP found
///     #test-domain.com/.env
///     MAIL_DRIVER=smtp
///     MAIL_HOST=smtp.mailtrap.io
///     ...
fn render_text(f: &Finding, color: bool) -> String {
    let mut s = String::new();

    for (cat, entries) in &f.secrets {
        let header = format!("{} found", cat.to_uppercase());
        if color {
            s.push_str(&format!("{}\n", header.cyan().bold()));
            s.push_str(&format!("{}\n", format!("#{}", f.url).dimmed()));
        } else {
            s.push_str(&format!("{}\n", header));
            s.push_str(&format!("#{}\n", f.url));
        }

        // Prefer the original raw lines preserved in f.lines.
        if !f.lines.is_empty() {
            for line in &f.lines {
                s.push_str(line);
                s.push('\n');
            }
        } else {
            // Fallback: reconstruct from the (name, value) pairs.
            for (name, val) in entries {
                s.push_str(&format!(
                    "{}={}\n",
                    name.to_uppercase().replace(' ', "_"),
                    val
                ));
            }
        }
        s.push('\n');
    }

    s
}
