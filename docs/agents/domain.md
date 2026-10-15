# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Layout

This repo uses a **single-context** layout:

- `CONTEXT.md` at the repo root: the domain model and key concepts for the whole repo
- `docs/adr/`: architecture decision records, one markdown file per decision

If the repo later grows into a genuine multi-context monorepo, switch to a root `CONTEXT-MAP.md` pointing at per-context `CONTEXT.md` files, and update this file.

## Consumer rules

- **Read `CONTEXT.md` before exploring the codebase** when a task touches an unfamiliar area. It holds the vocabulary and invariants the skills assume.
- **Check `docs/adr/` for decisions** before proposing an architectural change. If an ADR already settled the question, follow it or explicitly argue to supersede it.
- **If a needed concept isn't documented**, surface that gap to the user rather than guessing. New findings that would help the next session can be proposed as additions to `CONTEXT.md` or a new ADR, but only with user sign-off.
- **`AGENTS.md` rules take precedence** over anything in `CONTEXT.md` or an ADR if they conflict.
