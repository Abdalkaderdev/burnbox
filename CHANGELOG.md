# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Static scan: npm lifecycle scripts, Python build hooks, Makefile default target, VS Code folder-open tasks and settings, dev container commands, git hooks.
- Static scan: JavaScript AST rules for `eval`, `new Function`, `child_process`, split URLs and `String.fromCharCode`; line-based rules for TypeScript and Python.
- Static scan: encoded blobs, raw IP URLs, home-directory credential paths, typosquatted dependencies, lockfile mismatches, install-script dependencies.
- Sandbox: offline Docker container with dropped capabilities, read-only repository, decoy home directory, strace-based process, file and connection tracing, logging DNS stub.
- Verdicts CLEAN, REVIEW and DANGEROUS with exit codes 0, 1 and 2.
- Terminal, JSON and single-file HTML reports.
- Agent skill and composite GitHub Action.
