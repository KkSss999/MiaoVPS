# AGENTS.md

This project uses pmem for project memory.

pmem stores source-of-truth memory as Markdown cards under `.pmem/` and rebuilds SQLite indexes for fast agent recall. Do not edit `.pmem/pmem.db` directly.

## Daily Workflow

```bash
pmem context "<current task>"
# Complete and verify the work.
pmem sync -s "<what changed>" -n "<next step>"
pmem verify
```

For a specific memory lookup:

```bash
pmem ask "<task or memory card>" --format compact
```

## Read

Only read memory cards returned by pmem unless more context is needed.

## Advanced Update Diagnostics

Use the expanded workflow only when you need to inspect each update stage:
```bash
pmem status --format json
pmem mark-dirty --auto
pmem update --suggest --format json
pmem update --confirm -s "<what changed>" -n "<next step>"
```

`pmem update --suggest` exits 0. Parse the JSON output (e.g., check `summary.has_actionable`) to see if any memory update is suggested.

## Source Of Truth

- Markdown cards in `.pmem/**/*.md` are canonical.
- `.pmem/pmem.db` is a rebuildable SQLite runtime index.
- `pmem sync` keeps the index current; use `pmem rebuild` after manual card edits.

## More Workflows

Task-specific workflows are in:

```txt
.pmem/skills/
```
