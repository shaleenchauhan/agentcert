# AgentCert — Phase 4: Web Dashboard Session Summary

## Overview

Added a server-rendered web dashboard to the AgentCert anchoring service. The dashboard makes the product visually demo-able — a compliance officer or potential customer opens a browser and can browse agents, audit trails, batches, and verify any entry against Bitcoin. No terminal, no JSON, no CLI.

Built with Jinja2 templates, custom CSS, and minimal JavaScript. No React, no npm, no build step. Served by the same FastAPI server under `/dashboard`.

## Build Steps

| Step | Description | Status |
|------|-------------|--------|
| 1 | Setup — `jinja2` dep, `templates/` and `static/` dirs, 9 new DB query methods in `models.py` | Done |
| 2 | CSS (`static/style.css`) — complete stylesheet: layout, nav, cards, tables, status badges, hash truncation, responsive | Done |
| 3 | JS (`static/main.js`) — copy-to-clipboard, auto-refresh, collapsible sections, verify form handler | Done |
| 4 | Base template (`base.html`) — nav bar, footer, CSS/JS includes, page structure | Done |
| 5 | Overview page (`dashboard.py` + `overview.html`) — stats cards, recent activity, recent batches | Done |
| 6 | Agents list page (`agents.html`) — table with entry counts, risk tier dots, last active | Done |
| 7 | Agent detail page (`agent_detail.html`) — certificate info + full audit trail table with status columns | Done |
| 8 | Entry detail page (`entry_detail.html`) — entry info, verification panel, Merkle proof path, Bitcoin anchor | Done |
| 9 | Batches list + batch detail pages (`batches.html`, `batch_detail.html`) | Done |
| 10 | Verification tool page (`verify.html`) — paste entry ID, verify via fetch, show results | Done |
| 11 | Mount dashboard routes and static files in existing `app.py` | Done |
| 12 | Tests (`test_dashboard.py`) — 28 tests: all pages return 200, expected data, empty state, static files, navigation | Done |
| 13 | README — added dashboard section, updated project structure and test count | Done |

## Files Created

| File | Description |
|------|-------------|
| `src/agentcert/service/dashboard.py` | Dashboard route handlers, 7 routes, helper functions (~310 lines) |
| `src/agentcert/service/templates/base.html` | Base template with nav, footer, CSS/JS includes |
| `src/agentcert/service/templates/overview.html` | Overview page: stats cards, recent activity, recent batches |
| `src/agentcert/service/templates/agents.html` | Agents list with risk tier dots, entry counts, status badges |
| `src/agentcert/service/templates/agent_detail.html` | Certificate info + audit trail table with pagination |
| `src/agentcert/service/templates/entry_detail.html` | Entry info, live verification panel, Merkle proof path, anchor section |
| `src/agentcert/service/templates/batches.html` | Batches list with anchor status |
| `src/agentcert/service/templates/batch_detail.html` | Batch info + entries table + anchor link |
| `src/agentcert/service/templates/verify.html` | Verification tool: paste entry ID, verify via fetch |
| `src/agentcert/service/static/style.css` | Complete stylesheet (~500 lines) |
| `src/agentcert/service/static/main.js` | Copy-to-clipboard, auto-refresh, collapsible sections, verify form (~110 lines) |
| `tests/test_dashboard.py` | 28 tests across 9 test classes |

## Files Modified

| File | Changes |
|------|---------|
| `pyproject.toml` | Added `jinja2>=3.0.0` to `service` and `dev` dependency groups |
| `src/agentcert/service/models.py` | Added 9 dashboard query methods: `get_all_certificates`, `get_recent_entries`, `get_recent_batches`, `get_entries_by_cert`, `get_entry_count_by_cert`, `get_entries_by_batch`, `get_all_batches`, `get_last_active_by_cert` |
| `src/agentcert/service/app.py` | Added `StaticFiles` import, mounted dashboard router and static files |
| `README.md` | Added web dashboard section, updated project structure (dashboard.py, templates/, static/), updated test count (396 → 424) |

## Architecture

### Dashboard Routes (dashboard.py)

7 routes under `/dashboard`, using `APIRouter`:

| Route | Page | Description |
|-------|------|-------------|
| `GET /dashboard` | Overview | Stats cards, recent 10 entries, recent 5 batches |
| `GET /dashboard/agents` | Agents List | All certs with entry count, risk tier, last active, status |
| `GET /dashboard/agents/{cert_id}` | Agent Detail | Certificate info + paginated audit trail (50/page) |
| `GET /dashboard/entries/{entry_id}` | Entry Detail | Entry info, live verification, Merkle proof path, anchor |
| `GET /dashboard/batches` | Batches List | All batches with anchor status |
| `GET /dashboard/batches/{batch_id}` | Batch Detail | Batch info + entries in batch |
| `GET /dashboard/verify` | Verify Tool | Form to paste entry ID, verify via fetch |

Helper functions: `_action_label()` (action type icons), `_time_ago()` (relative time), `_format_ts()` (UTC timestamp), `_db()` (get DB from app state), `_ctx()` (build template context).

### Templates (Jinja2)

- `base.html` — Shared layout: nav bar (Overview, Agents, Batches, Verify + health dot), footer, CSS/JS includes
- `overview.html` — 5 stat cards, recent activity table, recent batches table, auto-refresh every 30s
- `agents.html` — Agent table with risk tier dots (filled/empty), status badges
- `agent_detail.html` — Detail grid for cert fields, capability/constraint tags, paginated audit trail with Signed/Batched/Anchored columns
- `entry_detail.html` — Detail grid, live verification via fetch, Merkle proof tree visualization, Bitcoin anchor with explorer link
- `batches.html` / `batch_detail.html` — Batch tables with anchor status, entries list
- `verify.html` — Form + JS-driven verification

### Static Assets

- `style.css` — CSS custom properties for theming, system font stack, card layout, tables with striping, status badges (green/amber/red), risk tier dots, hash truncation with ellipsis, copy buttons, proof path styling, responsive breakpoint at 768px
- `main.js` — Copy-to-clipboard with "Copied!" feedback, auto-refresh (30s), collapsible sections, verify form handler with `renderVerificationResult()`, HTML escaping

### Database Queries Added to models.py

| Method | Description |
|--------|-------------|
| `get_all_certificates()` | All certs, newest first, with `_registered_at` |
| `get_recent_entries(limit)` | Latest entries across all agents, with `_batch_id` |
| `get_recent_batches(limit)` | Latest batches |
| `get_entries_by_cert(cert_id, offset, limit)` | Entries for a cert, newest first, with `_batch_id` |
| `get_entry_count_by_cert(cert_id)` | Entry count for a cert |
| `get_entries_by_batch(batch_id)` | All entries in a batch |
| `get_all_batches()` | All batches, newest first |
| `get_last_active_by_cert(cert_id)` | Most recent entry timestamp for a cert |

## Test Count

| | Before | After | Delta |
|-|--------|-------|-------|
| Tests | 396 | 424 | +28 |

### test_dashboard.py (28 tests)

| Test class | Count | Covers |
|------------|-------|--------|
| `TestEmptyState` | 4 | Overview, agents, batches, verify — all empty |
| `TestOverview` | 2 | With data (agent name, entries), stats cards |
| `TestAgents` | 3 | List, detail, not found (404) |
| `TestEntryDetail` | 3 | Detail with data, proof present, not found |
| `TestBatches` | 3 | List, detail, not found |
| `TestStaticFiles` | 2 | CSS served, JS served |
| `TestNavigation` | 2 | Nav links present, agent links to entries |
| `TestDashboardQueries` | 9 | All 9 new DB methods |

## Dependencies

| Package | Group | Purpose |
|---------|-------|---------|
| `jinja2>=3.0.0` | service | Template rendering |

Added to both `service` and `dev` optional dependency groups.

## Open Items

- **Dark mode**: CSS custom properties are in place for easy theming. A dark mode toggle could be added with minimal effort.
- **Sorting**: Agent/batch tables don't have client-side column sorting yet. Could add with minimal JS.
- **Search**: No global search across entries/agents. Would be useful for large deployments.
- **Real-time updates**: Overview auto-refreshes every 30s via full page reload. WebSocket/SSE could provide live updates.
- **Export**: No CSV/JSON export from the dashboard. Would help compliance workflows.
- **Authentication**: Dashboard has no auth (same as the API). A future phase could gate access.
