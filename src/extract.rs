use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::BTreeMap;

static KV_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=").unwrap());

/// (category, human-name, regex)
static SECRET_PATTERNS: Lazy<Vec<(&'static str, &'static str, Regex)>> = Lazy::new(|| {
    let mut p: Vec<(&'static str, &'static str, Regex)> = Vec::new();
    let mut add = |cat: &'static str, name: &'static str, pat: &str| {
        if let Ok(re) = Regex::new(pat) {
            p.push((cat, name, re));
        }
    };

    // ---------- Google ----------
    add("google", "Google API Key", r"AIza[0-9A-Za-z\-_]{35}");
    add("google", "Google OAuth", r"ya29\.[0-9A-Za-z\-_]+");
    add("google", "Google Captcha Key", r"6L[0-9A-Za-z\-_]{38}");
    add(
        "google",
        "Firebase Key",
        r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
    );
    add("google", "Firebase URL", r"[a-z0-9\-]+\.firebaseio\.com");

    // ---------- AWS ----------
    add("aws", "AWS Access Key ID", r"AKIA[0-9A-Z]{16}");
    add(
        "aws",
        "AWS Secret",
        r#"(?i)aws.{0,20}?(secret|key).{0,5}[:=]\s*["']?([A-Za-z0-9/+=]{40})"#,
    );
    add(
        "aws",
        "AWS MWS Auth Token",
        r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    );
    add(
        "aws",
        "AWS URL",
        r"s3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com",
    );
    add(
        "aws",
        "AWS Session Token",
        r#"(?i)aws_session_token\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})"#,
    );
    add(
        "aws",
        "AWS Access Key (Laravel)",
        r#"(?im)^\s*AWS_ACCESS_KEY_ID\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "aws",
        "AWS Secret (Laravel)",
        r#"(?im)^\s*AWS_SECRET_ACCESS_KEY\s*[:=]\s*["']?([^\s"']+)"#,
    );

    // ---------- Stripe / payments ----------
    add(
        "stripe",
        "Stripe Standard API Key",
        r"sk_live_[0-9a-zA-Z]{24,}",
    );
    add(
        "stripe",
        "Stripe Restricted API Key",
        r"rk_live_[0-9a-zA-Z]{24,}",
    );
    add(
        "stripe",
        "Stripe Publishing API Key",
        r"pk_live_[0-9a-zA-Z]{24,}",
    );
    add("stripe", "Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24,}");
    add(
        "paypal",
        "PayPal Braintree Access Token",
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    );
    add(
        "paypal",
        "PayPal Client Secret",
        r#"(?i)paypal.{0,20}?(client.?secret|secret).{0,5}[:=]\s*["']?([A-Za-z0-9_\-]{20,})"#,
    );

    // ---------- M-Pesa ----------
    add(
        "mpesa",
        "M-Pesa Consumer Key",
        r#"(?i)mpesa.{0,30}?consumer.?key\s*[:=]\s*["']?([A-Za-z0-9]{20,})"#,
    );
    add(
        "mpesa",
        "M-Pesa Consumer Secret",
        r#"(?i)mpesa.{0,30}?consumer.?secret\s*[:=]\s*["']?([A-Za-z0-9]{20,})"#,
    );
    add(
        "mpesa",
        "M-Pesa Passkey",
        r#"(?i)mpesa.{0,30}?passkey\s*[:=]\s*["']?([A-Za-z0-9\-]{20,})"#,
    );
    add(
        "mpesa",
        "M-Pesa Shortcode",
        r#"(?i)(mpesa|paybill|till).{0,20}?(shortcode|short.?code|business.?short.?code)\s*[:=]\s*["']?(\d{5,7})"#,
    );
    add(
        "mpesa",
        "M-Pesa Initiator Password",
        r#"(?i)mpesa.{0,30}?initiator.{0,10}?password\s*[:=]\s*["']?([A-Za-z0-9]{20,})"#,
    );
    add(
        "mpesa",
        "M-Pesa Security Credential",
        r#"(?i)(security.?credential|mpesa.{0,20}?credential)\s*[:=]\s*["']?([A-Za-z0-9+/=]{50,})"#,
    );
    add(
        "mpesa",
        "Daraja Consumer Key",
        r#"(?i)daraja.{0,30}?(consumer.?key|key)\s*[:=]\s*["']?([A-Za-z0-9]{20,})"#,
    );

    // ---------- SMTP / Mail ----------
    add(
        "smtp",
        "SMTP Host",
        r#"(?im)^\s*smtp[_\.]?host\s*[:=]\s*["']?([a-z0-9\.\-]+\.[a-z]{2,})"#,
    );
    add(
        "smtp",
        "SMTP Username",
        r#"(?im)^\s*smtp[_\.]?user(name)?\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "smtp",
        "SMTP Password",
        r#"(?im)^\s*smtp[_\.]?pass(word)?\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "smtp",
        "SMTP Port",
        r#"(?im)^\s*smtp[_\.]?port\s*[:=]\s*["']?(\d{2,5})"#,
    );
    add("smtp", "SMTP URL", r#"(?i)smtp(s)?://[^\s"']+"#);

    add(
        "smtp",
        "MAIL_DRIVER",
        r#"(?im)^\s*MAIL_DRIVER\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "smtp",
        "MAIL_HOST",
        r#"(?im)^\s*MAIL_HOST\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "smtp",
        "MAIL_PORT",
        r#"(?im)^\s*MAIL_PORT\s*[:=]\s*["']?(\d{2,5})"#,
    );
    add(
        "smtp",
        "MAIL_USERNAME",
        r#"(?im)^\s*MAIL_USERNAME\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "smtp",
        "MAIL_PASSWORD",
        r#"(?im)^\s*MAIL_PASSWORD\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "smtp",
        "MAIL_ENCRYPTION",
        r#"(?im)^\s*MAIL_ENCRYPTION\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "smtp",
        "MAIL_FROM_ADDRESS",
        r#"(?im)^\s*MAIL_FROM_ADDRESS\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "smtp",
        "MAIL_FROM_NAME",
        r#"(?im)^\s*MAIL_FROM_NAME\s*[:=]\s*["']?([^\s"']+)"#,
    );

    add("smtp", "Mailgun API Key", r"key-[0-9a-zA-Z]{32}");
    add(
        "smtp",
        "Mailgun Domain",
        r#"(?i)mailgun.{0,20}?domain\s*[:=]\s*["']?([a-z0-9\.\-]+\.[a-z]{2,})"#,
    );
    add("smtp", "MailChimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}");
    add(
        "smtp",
        "SendGrid API Key",
        r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    );
    add(
        "smtp",
        "Postmark Token",
        r#"(?i)postmark.{0,20}?(token|server).{0,5}[:=]\s*["']?([0-9a-f\-]{36})"#,
    );
    add(
        "smtp",
        "Mailto String",
        r"(?i)mailto:[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9.\-]+",
    );

    // ---------- DB ----------
    add(
        "db",
        "Database URL",
        r#"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|rediss|amqp|amqps|mssql|sqlite)://[^\s"']+"#,
    );
    add("db", "Redis URL", r#"(?i)redis(s)?://[^\s"']+"#);
    add("db", "MongoDB URI", r#"mongodb(\+srv)?://[^\s"']+"#);
    add(
        "db",
        "DB_CONNECTION",
        r#"(?im)^\s*DB_CONNECTION\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "db",
        "DB_HOST",
        r#"(?im)^\s*DB_HOST\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "db",
        "DB_DATABASE",
        r#"(?im)^\s*DB_DATABASE\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "db",
        "DB_USERNAME",
        r#"(?im)^\s*DB_USERNAME\s*[:=]\s*["']?([^\s"']+)"#,
    );
    add(
        "db",
        "DB_PASSWORD",
        r#"(?im)^\s*DB_PASSWORD\s*[:=]\s*["']?([^\s"']+)"#,
    );

    // ---------- Twilio ----------
    add("twilio", "Twilio Account SID", r"AC[a-f0-9]{32}");
    add(
        "twilio",
        "Twilio Auth Token",
        r#"(?i)twilio.{0,20}?(auth.?token|token).{0,5}[:=]\s*["']?([a-f0-9]{32})"#,
    );

    // ---------- Admin / debug flags ----------
    add(
        "admin",
        "Debug Flag Enabled",
        r#"(?im)^\s*(APP_DEBUG|DEBUG|DEV|DEVELOPMENT)\s*[:=]\s*["']?(true|1|yes|on)"#,
    );
    add(
        "admin",
        "Admin Flag Enabled",
        r#"(?im)^\s*(ADMIN|SUPERUSER|ROOT)\s*[:=]\s*["']?(true|1|yes|on)"#,
    );
    add(
        "admin",
        "App Key (Laravel)",
        r#"(?im)^\s*APP_KEY\s*[:=]\s*["']?(base64:[A-Za-z0-9+/=]{40,})"#,
    );
    add(
        "admin",
        "App Env",
        r#"(?im)^\s*APP_ENV\s*[:=]\s*["']?([^\s"']+)"#,
    );

    // ---------- Auth providers ----------
    add("auth", "GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,}");
    add("auth", "GitLab Token", r"glpat-[A-Za-z0-9_\-]{20,}");
    add("auth", "Slack Token", r"xox[baprs]-[0-9a-zA-Z\-]{10,}");
    add(
        "auth",
        "Slack Webhook",
        r"https://hooks\.slack\.com/services/[A-Z0-9/]{40,}",
    );
    add(
        "auth",
        "Discord Webhook",
        r"https://(canary\.|ptb\.)?discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
    );
    add(
        "auth",
        "Telegram Bot Token",
        r"\b\d{9,10}:[a-zA-Z0-9_\-]{35}\b",
    );
    add(
        "auth",
        "JWT",
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    );
    add("auth", "Bearer Token", r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]+");
    add(
        "auth",
        "Basic Auth",
        r"(?i)basic\s+[a-zA-Z0-9=:_\+\/\-]{5,200}",
    );

    // ---------- Crypto ----------
    add(
        "crypto",
        "RSA Private Key",
        r"-----BEGIN RSA PRIVATE KEY-----",
    );
    add(
        "crypto",
        "DSA Private Key",
        r"-----BEGIN DSA PRIVATE KEY-----",
    );
    add(
        "crypto",
        "EC Private Key",
        r"-----BEGIN EC PRIVATE KEY-----",
    );
    add(
        "crypto",
        "OpenSSH Private Key",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
    );
    add(
        "crypto",
        "PGP Private Key Block",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    );
    add(
        "crypto",
        "Generic Private Key",
        r"-----BEGIN PRIVATE KEY-----",
    );

    // ---------- Generic (broadest, last) ----------
    add(
        "generic",
        "Generic API Key",
        r#"(?i)api[_]?key\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,64})"#,
    );
    add(
        "generic",
        "Generic Secret",
        r#"(?i)(secret|passwd|password|pwd)\s*[:=]\s*["']?([^\s"']{8,})"#,
    );
    add(
        "generic",
        "Generic Token",
        r#"(?i)token\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{16,})"#,
    );

    p
});

pub fn is_env_content(text: &str) -> bool {
    if text.len() < 8 {
        return false;
    }
    let mut total = 0usize;
    let mut kv = 0usize;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        total += 1;
        if KV_RE.is_match(l) {
            kv += 1;
        }
    }
    if total == 0 {
        return false;
    }
    kv >= 3 || (kv as f64 / total as f64) > 0.3
}

/// Extract matches, filtered to the given categories.
/// `cats` empty = all categories.
pub fn extract_secrets_filtered(
    text: &str,
    cats: &[String],
) -> BTreeMap<String, Vec<(String, String)>> {
    let want_all = cats.is_empty();
    let mut out: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();

    for (cat, name, re) in SECRET_PATTERNS.iter() {
        if !want_all && !cats.iter().any(|c| c.eq_ignore_ascii_case(cat)) {
            continue;
        }

        let mut hits: Vec<(String, String)> = Vec::new();
        for cap in re.captures_iter(text) {
            let val = cap
                .iter()
                .skip(1)
                .flatten()
                .last()
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| {
                    cap.get(0)
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default()
                });
            let val = val.trim().trim_matches('"').trim_matches('\'').to_string();
            if !val.is_empty() {
                hits.push(((*name).to_string(), val));
            }
        }

        if hits.is_empty() {
            for m in re.find_iter(text) {
                hits.push(((*name).to_string(), m.as_str().to_string()));
            }
        }

        hits.sort();
        hits.dedup();

        if !hits.is_empty() {
            out.entry((*cat).to_string()).or_default().extend(hits);
        }
    }

    out
}

pub fn parse_env(text: &str) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_string();
            let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
            if !key.is_empty() {
                env.insert(key, val);
            }
        }
    }
    env
}
