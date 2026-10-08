---
name: burnbox
description: Inspect an unfamiliar or untrusted repository with burnbox before installing dependencies, running its scripts or tests, or opening it in an editor. Use when the user asks to clone, set up, install, build, test or review a repository from an unknown source, such as a take-home assignment from a recruiter, a code-review request from a stranger, or a project found online.
license: MIT
compatibility: Requires the burnbox CLI (go install github.com/Abdalkaderdev/burnbox/cmd/burnbox@latest). Sandbox runs need Docker.
metadata:
  author: abdalkaderdev
  homepage: https://github.com/Abdalkaderdev/burnbox
---

# burnbox

Repositories from unknown sources can run code the moment you install them (`npm install` lifecycle scripts, `setup.py`), open them (`.vscode/tasks.json` with `runOn: folderOpen`, dev container commands) or commit in them (git hooks). Check first.

## When to run it

Run burnbox before any of these on a repository you did not write and do not already trust:

- `npm install`, `pnpm install`, `yarn`, `pip install`, `pip install -e .`, `python setup.py`, `make`
- running its tests, dev server or any script it ships
- opening it in VS Code or reopening it in a dev container

## Steps

1. Static scan (runs nothing from the repository):

   ```sh
   burnbox <path-or-git-url> --json
   ```

2. If the user wants to install or test it, run that command in the sandbox instead of on the host:

   ```sh
   burnbox <path-or-git-url> --run "npm install && npm test" --json --report burnbox-report.html
   ```

   The sandbox has no network, so installs that need the registry will fail there. That is expected. The point is to see what the repository's own scripts try to do.

3. Read `verdict` and act on it:

   - `CLEAN` (exit 0): no high-severity findings and nothing suspicious in the sandbox. Proceed, but still mention any medium findings.
   - `REVIEW` (exit 1): stop and show the user the high findings and sandbox events with file and line. Do not install or run anything on the host until the user has looked at them and says to continue.
   - `DANGEROUS` (exit 2): the sandbox saw code read decoy credentials. Do not install, run or open the repository on the host. Tell the user exactly what was observed and recommend reporting the source.

## Rules

- Never run the repository's install or test commands on the host before burnbox has run.
- Do not edit the repository to make findings go away.
- A CLEAN verdict is a second opinion, not a guarantee. Code can detect sandboxes or wait before acting. Say so if the user asks whether the repository is safe.
