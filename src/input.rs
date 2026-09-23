use async_channel::Sender;
use std::io::IsTerminal;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Read lines from a file asynchronously, pushing into work queue.
pub async fn read_file(path: &str, tx: Sender<String>) -> std::io::Result<usize> {
    let file = tokio::fs::File::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut count = 0usize;

    while let Some(line) = lines.next_line().await? {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if tx.send(t.to_string()).await.is_err() {
            break;
        }
        count += 1;
    }
    Ok(count)
}

/// Read lines from stdin asynchronously.
pub async fn read_stdin(tx: Sender<String>) -> std::io::Result<usize> {
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();
    let mut count = 0usize;

    while let Some(line) = lines.next_line().await? {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if tx.send(t.to_string()).await.is_err() {
            break;
        }
        count += 1;
    }
    Ok(count)
}

/// Detect if stdin is a TTY (i.e., no pipe/file provided).
pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}
