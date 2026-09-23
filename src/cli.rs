use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "envscanner", version, about = "Scan for exposed .env files")]
pub struct Args {
    /// Read targets from a file instead of stdin
    #[arg(short, long)]
    pub file: Option<String>,

    /// Write results here. .json -> JSONL, anything else -> text
    #[arg(short, long)]
    pub output: Option<String>,

    /// Emit JSON Lines to stdout
    #[arg(long)]
    pub json: bool,

    /// Suppress per-finding stdout output
    #[arg(short, long)]
    pub quiet: bool,

    /// Skip the authorization prompt
    #[arg(long)]
    pub no_confirm: bool,

    /// HTTP timeout (seconds)
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Concurrency (in-flight requests)
    #[arg(short = 'c', long, default_value_t = 32)]
    pub concurrency: usize,

    // ---- category filters ----
    #[arg(long)]
    pub smtp: bool,
    #[arg(long)]
    pub aws: bool,
    #[arg(long)]
    pub stripe: bool,
    #[arg(long)]
    pub google: bool,
    #[arg(long)]
    pub mpesa: bool,
    #[arg(long)]
    pub db: bool,
    #[arg(long)]
    pub twilio: bool,
    #[arg(long)]
    pub admin: bool,
    #[arg(long)]
    pub auth: bool,
    #[arg(long)]
    pub crypto: bool,
    #[arg(long)]
    pub generic: bool,

    /// Or: comma-separated categories, e.g. --only smtp,aws,db
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
}

impl Args {
    /// Returns the list of categories to scan for. Empty = all.
    pub fn categories(&self) -> Vec<String> {
        let mut cats: Vec<String> = Vec::new();

        if self.smtp {
            cats.push("smtp".into());
        }
        if self.aws {
            cats.push("aws".into());
        }
        if self.stripe {
            cats.push("stripe".into());
        }
        if self.google {
            cats.push("google".into());
        }
        if self.mpesa {
            cats.push("mpesa".into());
        }
        if self.db {
            cats.push("db".into());
        }
        if self.twilio {
            cats.push("twilio".into());
        }
        if self.admin {
            cats.push("admin".into());
        }
        if self.auth {
            cats.push("auth".into());
        }
        if self.crypto {
            cats.push("crypto".into());
        }
        if self.generic {
            cats.push("generic".into());
        }

        for c in &self.only {
            let c = c.trim().to_lowercase();
            if !c.is_empty() && !cats.contains(&c) {
                cats.push(c);
            }
        }
        cats
    }

    pub fn is_json_output(&self) -> bool {
        if self.json {
            return true;
        }
        self.output
            .as_deref()
            .map(|p| p.to_lowercase().ends_with(".json"))
            .unwrap_or(false)
    }
}
