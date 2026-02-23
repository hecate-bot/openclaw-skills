---
name: session-learnings
description: "Tracks errors, corrections, and non-obvious discoveries across sessions to build persistent institutional knowledge. Use when: (1) a command or operation fails unexpectedly, (2) the user corrects the agent ('No, actually...', 'That's wrong...'), (3) a tool or API behaves differently than expected, (4) something took significantly longer than it should due to a knowledge gap, (5) a better approach is discovered for something previously done the hard way. Also scan .learnings/ before starting work in an area where past issues are likely."
---

# Session Learnings

Log errors and corrections to `.learnings/` files so future sessions don't repeat the same mistakes. When patterns recur or are broadly applicable, promote them to permanent workspace files.

## File Structure

```
workspace/
└── .learnings/
    ├── ERRORS.md      # Command failures, tool/API surprises
    └── LEARNINGS.md   # Corrections, knowledge gaps, better approaches
```

Create on first use:
```bash
mkdir -p /mnt/openclaw/workspace/.learnings
```

Copy templates from `assets/` if starting fresh.

## When to Log

| Trigger | File | Category |
|---------|------|----------|
| Command fails unexpectedly | ERRORS.md | — |
| Tool/API behaves differently than expected | ERRORS.md | — |
| User corrects the agent | LEARNINGS.md | `correction` |
| Knowledge was wrong or outdated | LEARNINGS.md | `knowledge_gap` |
| Found a better approach | LEARNINGS.md | `best_practice` |

Log immediately — context is freshest right after the issue. One concise entry beats a perfect entry written later.

## Log Format

### Error Entry (ERRORS.md)

```markdown
## [ERR-YYYYMMDD-XXX] brief-description

**Logged**: ISO timestamp
**Priority**: low | medium | high | critical
**Status**: pending | resolved | wont_fix

### What failed
Command or operation attempted, and what went wrong.

### Error output
```
Actual error message
```

### Fix / workaround
What resolved it, or what to try.

### Metadata
- Reproducible: yes | no | unknown
- See Also: ERR-YYYYMMDD-XXX (if recurring)
---
```

### Learning Entry (LEARNINGS.md)

```markdown
## [LRN-YYYYMMDD-XXX] category: brief-description

**Logged**: ISO timestamp
**Priority**: low | medium | high | critical
**Status**: pending | promoted | resolved

### What was learned
What happened, what was wrong, what's correct.

### Suggested action
Concrete fix or promotion target.

### Metadata
- Source: correction | error | discovery
- Recurrence-Count: 1
- See Also: LRN-YYYYMMDD-XXX (if related)
---
```

**ID format:** `TYPE-YYYYMMDD-XXX` — e.g. `ERR-20260222-001`, `LRN-20260222-A3F`

## Promotion Rules

When a learning is broadly applicable — not a one-off — promote it to a permanent workspace file and mark `Status: promoted`.

| What it is | Promote to |
|------------|------------|
| Tool behavior, API gotcha, CLI quirk | `TOOLS.md` |
| Workflow pattern, delegation rule | `AGENTS.md` |
| Behavioral principle, communication pattern | `SOUL.md` |
| Project/context fact | `MEMORY.md` or `memory/YYYY-MM-DD.md` |

**Promotion threshold:** If the same issue appears in `See Also` chains across 2+ sessions, promote it. Don't wait for a third.

Write promoted rules as short prevention notes, not incident write-ups.

## Recurrence Detection

Before logging a new error, check for existing entries:
```bash
grep -i "keyword" /mnt/openclaw/workspace/.learnings/*.md
```

If found: add `See Also` link and increment `Recurrence-Count`. If `Recurrence-Count >= 2`, promote.

## Quick Status

```bash
# Count pending items
grep -h "Status\*\*: pending" /mnt/openclaw/workspace/.learnings/*.md | wc -l

# High priority pending
grep -B5 "Priority\*\*: high\|Priority\*\*: critical" /mnt/openclaw/workspace/.learnings/*.md | grep "^## \["
```

## OpenClaw-Specific Notes

- Workspace path: `/mnt/openclaw/workspace/.learnings/`
- Primary promotion targets: `TOOLS.md` (tool gotchas), `AGENTS.md` (workflow), `SOUL.md` (behavior)
- `.learnings/` is gitignored by default — add to workspace repo if you want learnings persisted across machines
- Review `.learnings/` at the start of sessions involving infra, gateway config, or anything that's broken before
