# Runbook — turn on the recall benchmark

One-time setup to start measuring Redstrike's recall over time. After this, each dispatch runs a real
autonomous engagement against OWASP Juice Shop in CI and gates on recall regressions. See `README.md` for
how scoring works; this is just the operator wiring.

**Prerequisites:** admin on the `0xnookie/redstrike-ai` repo, and an Anthropic credential —
`ANTHROPIC_API_KEY` (an API key) **or** `CLAUDE_CODE_OAUTH_TOKEN` (a long-lived token from
`claude setup-token`). Each dispatch spends model budget (bounded by `max_budget_usd`, default $15).

---

## 1. Add the credential as a repo secret

Interactive (keeps the key out of your shell history — paste when prompted):

```bash
gh secret set ANTHROPIC_API_KEY --repo 0xnookie/redstrike-ai
# or, for a long-lived token instead:
gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo 0xnookie/redstrike-ai
```

Or in the UI: **Settings → Secrets and variables → Actions → New repository secret**. Without this secret the
workflow still runs but **skips the engagement + gate** (it only validates tooling), so this step is what
turns it on.

Verify: `gh secret list --repo 0xnookie/redstrike-ai` shows `ANTHROPIC_API_KEY`.

## 2. Record the autonomous baseline (`mode=baseline`)

The committed baseline (40/116) is an **assisted** ceiling — a `mode=check` run would fail against it
honestly. Dispatch once in `baseline` mode to record the true autonomous floor:

```bash
gh workflow run recall-benchmark.yml --repo 0xnookie/redstrike-ai \
  -f mode=baseline -f max_turns=300 -f max_budget_usd=15
```

(Or **Actions → recall-benchmark → Run workflow**.) Watch it:

```bash
gh run watch "$(gh run list --workflow recall-benchmark.yml -L1 --json databaseId -q '.[0].databaseId')" --repo 0xnookie/redstrike-ai
```

It spins up Juice Shop, installs the CLI + Claude Code, runs `redstrike run --autonomous` (benign-PoC,
scoped to the service, budget-capped), scores, and **uploads the new baseline as an artifact**.

## 3. Commit the recorded baseline

```bash
RID="$(gh run list --workflow recall-benchmark.yml -L1 --json databaseId -q '.[0].databaseId')"
gh run download "$RID" --repo 0xnookie/redstrike-ai -n juice-shop-baseline -D /tmp/rsbl
cp /tmp/rsbl/juice-shop.json benchmark/baselines/juice-shop.json
git checkout -b chore/autonomous-baseline
git add benchmark/baselines/juice-shop.json
git commit -m "benchmark: record autonomous Juice Shop recall baseline"
gh pr create --fill && gh pr merge --merge
```

Now `benchmark/baselines/juice-shop.json` is the floor future runs must not drop below.

## 4. Gate on recall thereafter (`mode=check`)

```bash
gh workflow run recall-benchmark.yml --repo 0xnookie/redstrike-ai \
  -f mode=check -f tolerance=0.05
```

A run **fails** if overall or any category recall drops more than `tolerance` (default 0.05, to absorb
run-to-run LLM variance) below the committed baseline. To run it on a cadence, uncomment the weekly
`schedule:` block in `.github/workflows/recall-benchmark.yml`.

## Reading the result

A successful run prints two recall signals:

- **Challenge-solve recall** (`juice-shop`, live `/api/Challenges`) — overall + per Juice Shop category + per
  difficulty. The headline number.
- **Findings-coverage recall** (`generic-web`, findings-match against `findings.json`) — how many OWASP-Top-10
  classes the run produced accepted findings for. Target-agnostic; the same signal works for any future target.

Re-record the baseline (step 2–3) after a deliberate capability improvement, so the floor tracks upward.

## Tuning & troubleshooting

| Symptom | Cause / fix |
|---|---|
| Engagement + gate steps **skipped** | No `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` secret — do step 1. |
| Run step warns "exited non-zero" | Hit `max_turns` / `max_budget_usd`, or a command deferred. Raise the caps; scoring still runs on whatever it achieved. |
| `check` fails right after enabling | You skipped step 2 — it's comparing an autonomous run to the assisted 40/116 ceiling. Record a `baseline` first. |
| Flaky pass/fail near the line | Raise `-f tolerance` (e.g. 0.08); LLM runs vary. |
| Want deeper runs | Raise `-f max_turns` / `-f max_budget_usd`; watch spend. |
| Job time | `timeout-minutes: 60` on the job; a full run is well under that. |

**Cost:** each run spends up to `max_budget_usd` (default $15). Keep it `workflow_dispatch` (manual) unless
you accept the weekly `schedule` spend.
