mod cli;
mod extract;
mod input;
mod output;
mod scanner;

use clap::Parser;
use cli::Args;
use colored::*;
use output::printer_task;
use scanner::{scan_target, Finding};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use async_channel::bounded;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // --- Authorization confirmation (reads from /dev/tty so it works with pipes) ---
    if !args.no_confirm {
        use std::io::BufRead;
        eprintln!(
            "{}",
            "[!] By continuing you confirm you have authorization to test these targets.".yellow()
        );
        eprintln!("[!] Type 'yes' to proceed:");

        let tty = std::fs::File::open("/dev/tty")
            .map_err(|_| anyhow::anyhow!("No TTY available; use --no-confirm when piping input"))?;
        let mut line = String::new();
        std::io::BufReader::new(tty).read_line(&mut line)?;

        if line.trim().to_lowercase() != "yes" {
            eprintln!("[!] Aborted.");
            std::process::exit(1);
        }
    }

    // --- Validate input source ---
    if args.file.is_none() && input::stdin_is_tty() {
        eprintln!(
            "{}",
            "[!] No input. Usage:\n    cat targets.txt | envscanner [OPTIONS]\n    envscanner -f targets.txt [OPTIONS]"
                .red()
        );
        std::process::exit(2);
    }

    // --- Resolve filters & output format ---
    let categories = args.categories();
    let json_out = args.is_json_output();

    if !categories.is_empty() && !args.quiet {
        eprintln!("[*] Category filter: {}", categories.join(", "));
    }

    // --- HTTP client ---
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("EnvScanner/0.1 (Authorized Assessment)")
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(4)
        .build()?;

    // --- Shared state ---
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let scanned = Arc::new(AtomicUsize::new(0));
    let hits = Arc::new(AtomicUsize::new(0));

    // --- Channels (bounded = backpressure, no memory blow-up) ---
    let (work_tx, work_rx) = bounded::<String>(500);
    let (hit_tx, hit_rx) = bounded::<Finding>(100);

    // --- Printer task ---
    let printer_hits = hits.clone();
    let printer = tokio::spawn(printer_task(
        hit_rx,
        json_out,
        args.quiet,
        args.output.clone(),
        printer_hits,
    ));

    // --- Reader task ---
    let file_opt = args.file.clone();
    let reader = tokio::spawn(async move {
        let result = match file_opt {
            Some(path) => input::read_file(&path, work_tx.clone()).await,
            None => input::read_stdin(work_tx.clone()).await,
        };
        drop(work_tx); // close work channel so workers exit
        match result {
            Ok(n) => {
                eprintln!("[*] Loaded {} targets", n);
                n
            }
            Err(e) => {
                eprintln!("[!] Input error: {}", e);
                0
            }
        }
    });

    // --- Progress reporter (stderr only, so stdout stays clean) ---
    let progress_scanned = scanned.clone();
    let progress_hits = hits.clone();
    let quiet = args.quiet;
    let progress = tokio::spawn(async move {
        if quiet {
            return;
        }
        let mut last = 0usize;
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let n = progress_scanned.load(Ordering::Relaxed);
            let h = progress_hits.load(Ordering::Relaxed);
            if n != last {
                eprint!("\r[*] scanned: {} | hits: {}    ", n, h);
                last = n;
            }
            if n == usize::MAX {
                break;
            }
        }
    });

    // --- Worker pool ---
    let n_workers = args.concurrency.min(256).max(1);
    let mut workers = Vec::with_capacity(n_workers);

    for _ in 0..n_workers {
        let client = client.clone();
        let sem = semaphore.clone();
        let work_rx = work_rx.clone();
        let hit_tx = hit_tx.clone();
        let scanned = scanned.clone();
        let cats = categories.clone();

        workers.push(tokio::spawn(async move {
            while let Ok(target) = work_rx.recv().await {
                let findings = scan_target(&client, sem.clone(), &target, &cats).await;
                scanned.fetch_add(1, Ordering::Relaxed);
                for f in findings {
                    if hit_tx.send(f).await.is_err() {
                        break;
                    }
                }
            }
        }));
    }

    // Drop our copies so channels close when workers finish.
    drop(work_rx);
    drop(hit_tx);

    // --- Wait for workers ---
    for w in workers {
        let _ = w.await;
    }

    // --- Wait for printer to drain ---
    let _ = printer.await;
    let _ = reader.await;

    // Stop progress reporter
    progress.abort();

    // Final newline so the last progress line doesn't clash
    if !args.quiet {
        eprintln!();
    }

    eprintln!(
        "[*] Done. Scanned: {} | Findings: {}",
        scanned.load(Ordering::Relaxed),
        hits.load(Ordering::Relaxed)
    );

    Ok(())
}
