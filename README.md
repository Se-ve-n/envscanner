# envscanner

A fast, concurrent scanner for exposed `.env` files. Given a list of hosts,
`envscanner` probes common environment-file paths, confirms which responses
actually look like `.env` content, and extracts secrets grouped by category
(SMTP, AWS, Stripe, Google, M-Pesa, databases, Twilio, admin flags, auth
tokens, crypto material, and generic key/value secrets).

Output can be human-readable text or JSONL, written to stdout or a file.

> **Authorized use only.** This tool sends HTTP requests to the hosts you
> give it. Only run it against systems you own or have explicit written
> permission to test. See [Legal](#legal).

---

## Table of contents

- [Features](#features)
- [Install](#install)
  - [Download the binary](#download-the-binary)
  - [Linux — install](#linux--install)
  - [Windows — install](#windows--install)
  - [Verify the install](#verify-the-install)
  - [Build from source](#build-from-source)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Command-line reference](#command-line-reference)
- [Category filters](#category-filters)
- [Output formats](#output-formats)
- [Examples](#examples)
- [How it works](#how-it-works)
- [Cross-compiling](#cross-compiling)
- [Contributing](#contributing)
- [Legal](#legal)
- [License](#license)

---

## Features

- **Concurrent scanning** — configurable in-flight requests via a tokio
  semaphore and a bounded worker pool. Backpressure is built in, so memory
  stays flat even on large target lists.
- **Smart target handling** — feed it a bare host (`example.com`) and it
  sweeps 16 common `.env` paths. Feed it a full URL
  (`example.com/.env`) and it scans exactly that URL. No wrong-URL guessing.
- **Content gating** — responses are checked with a heuristic before being
  reported, so 404 pages and generic HTML don't produce false positives.
- **Categorized secret extraction** — 100+ regex patterns grouped into
  filterable categories.
- **Category filters** — `--smtp`, `--aws`, `--stripe`, … or
  `--only smtp,aws,db` to scan for a subset.
- **Two output formats** — human-readable text grouped by category, or
  JSONL for pipelines. Format is inferred from the `--output` file
  extension, or forced with `--json`.
- **Authorization gate** — an interactive confirmation prompt that reads
  from the terminal, so it works even when targets are piped in.
- **Single static binary** — no runtime, no interpreter, no config files.

---

## Install

Prebuilt binaries are the fastest path. No Rust, no compiler, no build
steps. Download, extract, drop on your `PATH`, done.

### Download the binary

Go to the [Releases](https://github.com/se-ve-n/envscanner/releases) page
and pick the file for your platform:

| Platform             | File                                  | Notes                                                                                  |
| -------------------- | ------------------------------------- | -------------------------------------------------------------------------------------- |
| Linux x86_64 (glibc) | `envscanner-x86_64-linux-gnu.tar.gz`  | Ubuntu 20.04+, Debian 11+, Fedora, RHEL, Arch.                                         |
| Linux x86_64 (musl)  | `envscanner-x86_64-linux-musl.tar.gz` | **Fully static.** Runs anywhere, including Alpine and containers. Pick this if unsure. |
| Windows x86_64       | `envscanner-x86_64-windows.zip`       | Windows 10 / 11, 64-bit.                                                               |

---

### Linux — install

The goal: get the `envscanner` binary into a directory that's on your
`PATH`, so you can run it from anywhere.

#### 1. Download

```bash
cd ~/Downloads
curl -LO https://github.com/se-ve-n/envscanner/releases/latest/download/envscanner-x86_64-linux-musl.tar.gz
```
