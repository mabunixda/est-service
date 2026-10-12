# AGENTS.md

## Repository Environment

This repository uses **mise** for toolchain management, runtime versions, environment variables, and task execution.

### Required Setup

Before performing any work, ensure the repository environment is installed:

```bash
mise install
```

Do not assume globally installed tools are the correct versions.

---

## Command Execution Policy

Prefer executing commands through **mise tasks** whenever possible:

```bash
mise run <task>
```

Examples:

```bash
mise run test
mise run lint
mise run build
mise run format
```

### Why

- Ensures correct tool versions
- Ensures repository environment variables are loaded


These rules are loaded by opencode before loop work.

## Loop Mode

- Start in L1 report-only mode.
- Read `STATE.md` before any triage.
- Update `STATE.md` after every loop run.
- Do not edit source code until the human explicitly enables L2.

## Safety

- Never push or merge without human approval.
- Never edit `.env`, `.env.*`
- Use a git worktree for every code-changing attempt.
- Max 3 fix attempts per item; escalate after that.

## Verification

- For L2+ changes, dispatch a verifier sub-agent after implementation.
- Run the project's documented tests before proposing a fix.
- Record test evidence in `STATE.md`.
