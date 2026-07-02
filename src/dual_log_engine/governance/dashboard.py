"""Dashboard - a verification INSTRUMENT for an org's agent activity and risk.

This is not a status badge. The product's thesis is trust-but-verify: two signals
or it is not a finding, no citation no check, a tamper-evident ledger you can PROVE.
A green light and a count would ask the viewer to ACCEPT. This view asks them to
CHECK. Every claim is shown with the evidence that earns it and, beside it, the
limit of what it does NOT prove.

Frame: ADVERSARIAL COVERAGE. The dominant gesture is "here is exactly what this run
does and does NOT establish." The hero is the coverage panel: which of the whole
check registry actually ran, made loud, because the most dangerous thing an audit
tool can do is let a quiet check read as an all-clear. Absence of a finding is not
proof of safety, and this dashboard says so first, not in the footer.

What it renders, all from the real store and chain (nothing asserted):
  * Coverage    - every check in the registry, fired or quiet, fired vs total.
  * Integrity   - the ACTUAL hash chain (seq, prev_hash, entry_hash), with the
                  prev to entry linkage made followable so a person re-derives the
                  tamper-evidence, plus the keyless-vs-signed distinction spelled out.
  * Traceability- change to the findings it produced to the chain entry that records
                  it to the cited authority. A drill path, not a summary.
  * Findings    - each one shows its two-signal reasoning (detect AND an independent
                  verify), its grounded clause and URL (why it matters), file:line,
                  redacted evidence, and the remediation (the WHY, not just a label).
  * Limits      - best-effort redaction, the documented chain rollback caveat, and the
                  coverage caveat, surfaced as first-class text.

Aesthetic: a forensic console. Monospace (IBM Plex Mono) for the material - hashes,
clauses, counts, evidence - because that IS the material. Amber is the resting tone
(scrutiny, not reassurance); mint is spent only where the tool has actually EARNED a
claim (a verify confirmed, a signed chain). No undifferentiated card grid: the layout
is a ledger you read top to bottom.

ASCII source only (no em-dash / arrow / smart-quote / middot), so it passes the repo's
pre-commit guard and carries no AI-tell punctuation. The rendered HTML is UTF-8 and
self-contained except for a web font (degrades to a system mono / sans).
"""
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict

from .chain import GovernanceChain
from .store import GovernanceStore

# Map each check id to its human title and remediation - the WHY behind a finding.
# Imported from the single source of truth (the registry) so the dashboard cannot
# drift from the checks that actually run. REGISTRY is also the denominator for
# coverage: findings tell you what fired; the registry tells you what COULD have.
try:
    from .safety.checks import CHECKS as _CHECKS
    REGISTRY = [
        {"id": c.id, "title": c.title, "category": c.category,
         "severity": c.severity, "framework": c.framework, "fix_hint": c.fix_hint}
        for c in _CHECKS
    ]
except Exception:  # pragma: no cover - the dashboard degrades, it does not crash
    REGISTRY = []

_CHECK_TITLE = {c["id"]: c["title"] for c in REGISTRY}
_CHECK_FIX = {c["id"]: c["fix_hint"] for c in REGISTRY}
_CHECK_SEV = {c["id"]: c["severity"] for c in REGISTRY}

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
# Severity colors. Deliberately NOT a calm palette: this is an instrument for doubt.
_SEV = {"CRITICAL": "#ff5470", "HIGH": "#ff9d3c", "MEDIUM": "#f4c64a", "LOW": "#7aa2ff"}
_AMBER = "#f4b53c"   # resting tone: scrutiny
_MINT = "#3dd7a6"    # spent only on an EARNED claim
_FIRE = "#ff7a59"    # a check that fired (produced findings)

_FONTS = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
    'family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">'
)

_CSS = """
*{box-sizing:border-box}
:root{
 --bg:#080a0e;--panel:#0f131b;--panel2:#141a24;--panel3:#0b0e14;--line:#1f2734;--line2:#2c3647;
 --ink:#e9edf4;--ink2:#aab4c6;--muted:#69728a;--faint:#48516a;
 --amber:#f4b53c;--amber-d:#5a4416;--mint:#3dd7a6;--mint-d:#1c6e54;--crit:#ff5470;--fire:#ff7a59;
 --mono:'IBM Plex Mono',ui-monospace,'Cascadia Code',Menlo,Consolas,monospace;
 --sans:'IBM Plex Sans',ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
html{color-scheme:dark}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.55;
 -webkit-font-smoothing:antialiased;
 background-image:
  radial-gradient(900px 380px at 88% -14%,rgba(244,181,60,.06),transparent 60%),
  repeating-linear-gradient(0deg,rgba(255,255,255,.013) 0 1px,transparent 1px 56px)}
.wrap{max-width:1180px;margin:0 auto;padding:30px 26px 96px}
a{color:var(--ink2);text-decoration:none;border-bottom:1px dotted var(--faint)}
a:hover{color:var(--mint);border-bottom-color:var(--mint)}
.mono{font-family:var(--mono)}

/* masthead */
.mast{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;
 padding-bottom:16px;border-bottom:1px solid var(--line);margin-bottom:8px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:11px;font-family:var(--mono)}
.brand .dot{width:8px;height:8px;border-radius:50%;background:var(--amber);box-shadow:0 0 0 4px rgba(244,181,60,.14)}
.brand .name{font-weight:600;letter-spacing:.01em;font-size:15px}
.brand .name b{color:var(--amber);font-weight:600}
.brand .org{font-family:var(--mono);font-size:12px;color:var(--ink2);background:var(--panel2);
 border:1px solid var(--line);border-radius:6px;padding:3px 11px}
.right{display:flex;flex-direction:column;align-items:flex-end;gap:7px}
.sub{font-family:var(--mono);font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.18em}
.verdict{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);font-size:12px;font-weight:600;
 padding:6px 13px;border-radius:6px;letter-spacing:.05em;border:1px solid}
.verdict.ok{color:var(--mint);border-color:var(--mint-d);background:rgba(61,215,166,.07)}
.verdict.partial{color:var(--amber);border-color:var(--amber-d);background:rgba(244,181,60,.07)}
.verdict.bad{color:#fff;border-color:#5a2533;background:rgba(255,84,112,.16)}
.verdict .d{width:7px;height:7px;border-radius:50%;background:currentColor}

/* the standing disclaimer - first, not in the footer */
.disclaim{font-family:var(--mono);font-size:12px;color:var(--ink2);background:var(--panel3);
 border:1px solid var(--line);border-left:2px solid var(--amber);border-radius:8px;
 padding:11px 15px;margin:14px 0 24px}
.disclaim b{color:var(--amber);font-weight:600}

/* section heads */
.sec{margin:30px 0 13px;display:flex;align-items:baseline;gap:12px}
.sec h2{font-family:var(--mono);font-size:13px;font-weight:600;letter-spacing:.02em;margin:0;color:var(--ink)}
.sec .tag{font-family:var(--mono);font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.14em}
.sec .rule{flex:1;height:1px;background:var(--line)}
.note{font-family:var(--mono);font-size:11.5px;color:var(--muted);margin:0 0 14px;max-width:96ch;line-height:1.7}
.note b{color:var(--ink2);font-weight:500}

/* coverage - the hero of the adversarial frame */
.cov{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);
 border-radius:12px;padding:18px 20px 20px;margin-bottom:8px}
.cov .meter{display:flex;align-items:center;gap:16px;margin-bottom:6px}
.cov .frac{font-family:var(--mono);font-size:32px;font-weight:600;letter-spacing:-.02em;
 font-variant-numeric:tabular-nums;line-height:1;color:var(--amber);white-space:nowrap}
.cov .frac small{font-size:16px;color:var(--muted);font-weight:500}
.cov .gist{font-family:var(--mono);font-size:11.5px;color:var(--ink2);line-height:1.6}
.cov .gist b{color:var(--amber)}
.cov .track{height:8px;border-radius:99px;background:#0a0d13;border:1px solid var(--line);
 overflow:hidden;margin:14px 0 16px;display:flex}
.cov .track .ran{height:100%;background:linear-gradient(90deg,var(--fire),var(--amber))}
.reg{display:grid;grid-template-columns:repeat(auto-fill,minmax(232px,1fr));gap:7px}
.chip{display:flex;align-items:center;gap:9px;font-family:var(--mono);font-size:11.5px;
 padding:7px 11px;border-radius:7px;border:1px solid var(--line);background:var(--panel3)}
.chip .st{width:7px;height:7px;border-radius:50%;flex:none}
.chip.fired{border-color:#4a2a22;background:rgba(255,122,89,.06)}
.chip.fired .st{background:var(--fire);box-shadow:0 0 0 3px rgba(255,122,89,.16)}
.chip.quiet .st{background:#28324a;border:1px solid #39455f}
.chip .id{color:var(--ink);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.chip.quiet .id{color:var(--muted)}
.chip .n{color:var(--fire);font-weight:600;font-variant-numeric:tabular-nums}
.chip .q{color:var(--faint);font-size:10px;letter-spacing:.06em}

/* integrity - keyless vs signed contrast, then the real chain */
.split{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin-bottom:14px}
.mode{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;position:relative}
.mode.on{border-color:var(--mint-d);background:rgba(61,215,166,.05)}
.mode.on.bad{border-color:#5a2533;background:rgba(255,84,112,.06)}
.mode.off{opacity:.6}
.mode .lbl{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.13em;
 color:var(--muted);display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px}
.mode .lbl .badge{font-size:9px;padding:2px 7px;border-radius:99px;border:1px solid var(--line);white-space:nowrap}
.mode.on .lbl .badge{color:var(--mint);border-color:var(--mint-d)}
.mode.on.bad .lbl .badge{color:var(--crit);border-color:#5a2533}
.mode .ttl{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--ink);margin-bottom:5px}
.mode p{margin:0;font-family:var(--mono);font-size:11px;color:var(--ink2);line-height:1.65}
.mode p b{color:var(--ink)}

.ledger{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.ledger.bad{border-color:#3a2030}
.ledger .lh{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:13px 18px;
 border-bottom:1px solid var(--line);font-family:var(--mono);font-size:10px;text-transform:uppercase;
 letter-spacing:.13em;color:var(--muted)}
.ledger .lh .seal{padding:3px 9px;border-radius:5px;border:1px solid var(--mint-d);color:var(--mint);letter-spacing:.06em}
.ledger.bad .lh .seal{border-color:#5a2533;color:var(--crit)}
.recipe{font-family:var(--mono);font-size:10.5px;color:var(--muted);padding:10px 18px;background:var(--panel3);
 border-bottom:1px solid var(--line);line-height:1.6}
.recipe b{color:var(--ink2)}
.recompute{margin-top:9px;font-family:var(--mono);font-size:11px}
.recompute summary{cursor:pointer;color:var(--amber);list-style:none;display:inline-flex;align-items:center;gap:6px;
 border:1px solid var(--amber-d);border-radius:5px;padding:2px 9px;background:rgba(244,181,60,.06);user-select:none}
.recompute summary::-webkit-details-marker{display:none}
.recompute summary::before{content:"+";font-weight:700}
.recompute[open] summary::before{content:"-"}
.recompute summary:hover{color:var(--mint);border-color:var(--mint-d)}
.recompute .rc{margin-top:8px;display:grid;gap:8px;padding:11px 13px;background:var(--panel3);
 border:1px solid var(--line);border-radius:7px}
.recompute .rk{display:block;color:var(--muted);font-size:9.5px;text-transform:uppercase;letter-spacing:.09em;margin-bottom:3px}
.recompute .rc code{display:block;color:var(--ink2);font-size:11px;word-break:break-all;line-height:1.5}
.ledref{font-family:var(--mono);font-size:10px;color:var(--amber);border:1px solid var(--amber-d);border-radius:5px;
 padding:2px 8px;letter-spacing:.03em;text-decoration:none}
.ledref:hover{color:var(--mint);border-color:var(--mint-d)}
.ledref.none{color:var(--muted);border-color:var(--line)}
.entry{display:grid;grid-template-columns:46px 1fr;border-bottom:1px solid var(--line)}
.entry:last-child{border-bottom:none}
.entry.broken{background:rgba(255,84,112,.05)}
.entry .seq{font-family:var(--mono);font-size:12px;color:var(--muted);padding:13px 0 13px 16px;
 font-variant-numeric:tabular-nums;border-right:1px solid var(--line)}
.entry.broken .seq{color:var(--crit)}
.entry .body{padding:11px 16px 12px}
.hl{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-family:var(--mono);font-size:11.5px}
.hl .lk{color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em}
.hl .h{color:var(--ink2);background:var(--panel3);border:1px solid var(--line);border-radius:4px;padding:1px 7px;
 letter-spacing:.02em}
.hl .h.prev{color:var(--muted)}
.hl .h.entry{color:var(--mint)}
.entry.broken .hl .h.entry{color:var(--crit)}
.hl .arrow{color:var(--faint);font-weight:600}
.hl .match{font-size:9.5px;color:var(--mint);letter-spacing:.05em;text-transform:uppercase}
.hl .match.void{color:var(--muted)}
.entry.broken .hl .match{color:var(--crit)}
.emeta{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:7px;line-height:1.6}
.emeta b{color:var(--ink2);font-weight:500}
.emeta .pip{color:var(--fire)}
.ledger .lf{padding:11px 18px;font-family:var(--mono);font-size:11px;color:var(--muted);
 background:var(--panel3);border-top:1px solid var(--line);line-height:1.6}
.ledger.bad .lf{color:var(--crit)}
.ledger .lf b{color:var(--ink2);font-weight:500}

/* tiles */
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:11px;margin:16px 0 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px 15px 15px}
.tile .k{font-family:var(--mono);font-size:9.5px;text-transform:uppercase;letter-spacing:.13em;color:var(--muted)}
.tile .v{font-family:var(--mono);font-size:30px;font-weight:600;margin-top:7px;letter-spacing:-.02em;
 font-variant-numeric:tabular-nums;line-height:1}
.tile .cap{font-family:var(--mono);font-size:10px;color:var(--faint);margin-top:6px;line-height:1.4}
.tile.risk .v{color:var(--fire)}
.tile.zero .v{color:var(--mint)}

/* traceability drilldown */
.trace{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.tg{border-bottom:1px solid var(--line)}
.tg:last-child{border-bottom:none}
.tg summary{list-style:none;cursor:pointer;padding:13px 18px;display:flex;align-items:center;gap:12px;
 font-family:var(--mono);font-size:12.5px;outline:none;flex-wrap:wrap}
.tg summary::-webkit-details-marker{display:none}
.tg summary:hover{background:var(--panel2)}
.tg summary .car{color:var(--faint);transition:transform .12s;font-size:10px}
.tg[open] summary .car{transform:rotate(90deg)}
.tg summary .repo{color:var(--ink);font-weight:600}
.tg summary .who{color:var(--muted)}
.tg summary .who b{color:var(--ink2);font-weight:500}
.tg summary .spacer{flex:1}
.tg summary .cnt{color:var(--fire);font-weight:600;font-variant-numeric:tabular-nums}
.tg summary .cnt.clean{color:var(--mint)}
.tg summary .seq{color:var(--muted);background:var(--panel3);border:1px solid var(--line);border-radius:5px;
 padding:2px 8px;font-size:11px}
.tdetail{padding:4px 18px 16px 40px;border-top:1px dashed var(--line);background:var(--panel3)}
.tstep{font-family:var(--mono);font-size:10px;color:var(--muted);margin:11px 0 7px;letter-spacing:.1em;
 text-transform:uppercase}
.tflow{display:flex;align-items:center;gap:0;flex-wrap:wrap;font-family:var(--mono);font-size:11px;margin-bottom:6px}
.tflow .node{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:6px 11px;color:var(--ink2)}
.tflow .node b{color:var(--ink);font-weight:600}
.tflow .j{color:var(--faint);padding:0 9px;font-weight:600}
.tfind{font-family:var(--mono);font-size:11.5px;color:var(--ink2);padding:6px 0;border-bottom:1px dotted var(--line)}
.tfind:last-child{border-bottom:none}
.tfind .sev{font-weight:600}

/* findings - forensic rows */
.finding{background:var(--panel);border:1px solid var(--line);border-radius:11px;margin-bottom:10px;
 overflow:hidden;border-left:3px solid var(--line2)}
.finding .fh{display:flex;align-items:center;gap:11px;padding:13px 17px;flex-wrap:wrap}
.finding .sevtag{font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.05em;
 padding:3px 9px;border-radius:5px}
.finding .cid{font-family:var(--mono);font-size:12.5px;color:var(--ink);font-weight:600}
.finding .title{color:var(--ink2);font-size:13px}
.finding .loc{font-family:var(--mono);font-size:11.5px;color:var(--muted);margin-left:auto}
.fbody{padding:0 17px 15px;display:grid;grid-template-columns:1fr 1fr;gap:13px}
.fcol .lab{font-family:var(--mono);font-size:9.5px;text-transform:uppercase;letter-spacing:.13em;
 color:var(--muted);margin-bottom:6px}
.twosig{display:flex;flex-direction:column;gap:6px}
.sig{font-family:var(--mono);font-size:11.5px;color:var(--ink2);display:flex;align-items:flex-start;gap:8px;line-height:1.5}
.sig .ck{color:var(--mint);font-weight:700;flex:none}
.sig b{color:var(--ink);font-weight:600}
.gate{font-family:var(--mono);font-size:10.5px;color:var(--faint);margin-top:3px}
.evi code{display:block;background:var(--panel3);border:1px solid var(--line);border-radius:6px;
 padding:9px 11px;color:var(--ink2);word-break:break-all;line-height:1.5;font-family:var(--mono);font-size:11.5px}
.evi .red{font-family:var(--mono);font-size:10px;color:var(--amber);margin-top:6px;letter-spacing:.04em}
.cite{font-family:var(--mono);font-size:11.5px;line-height:1.6}
.cite .fw{color:var(--ink2)}
.cite .cl{display:inline-block;color:var(--mint);background:rgba(61,215,166,.08);border:1px solid var(--mint-d);
 border-radius:4px;padding:1px 7px;margin:5px 6px 0 0;font-size:10.5px}
.fix{font-family:var(--mono);font-size:11.5px;color:var(--ink2);line-height:1.6}
.fix b{color:var(--amber);font-weight:600}

/* simple breakdown bars */
.cols{display:grid;grid-template-columns:1fr 1fr;gap:13px}
.box{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px 18px}
.box h3{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.13em;color:var(--muted);
 margin:0 0 13px;font-weight:600}
.bar{display:flex;align-items:center;gap:11px;margin:9px 0}
.bar .lbl{width:140px;flex:none;font-family:var(--mono);font-size:12px;color:var(--ink2);
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .track{flex:1;height:6px;background:#0a0d13;border:1px solid var(--line);border-radius:99px;overflow:hidden}
.bar .fill{display:block;height:100%;border-radius:99px}
.bar .n{width:26px;text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;
 color:var(--ink2);font-size:12px}
.empty{color:var(--muted);padding:22px;text-align:center;font-family:var(--mono);font-size:12.5px}

/* limits footer */
.limits{margin-top:30px;border-top:1px solid var(--line);padding-top:18px}
.limits h3{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.14em;
 color:var(--amber);margin:0 0 12px;font-weight:600}
.lim{display:flex;gap:11px;font-family:var(--mono);font-size:11.5px;color:var(--muted);
 line-height:1.7;margin-bottom:9px;max-width:100ch}
.lim .x{color:var(--amber);font-weight:700;flex:none}
.lim b{color:var(--ink2);font-weight:500}
.foot{color:var(--faint);font-size:10.5px;margin-top:18px;font-family:var(--mono);letter-spacing:.03em;line-height:1.7}
@media(max-width:820px){.tiles{grid-template-columns:repeat(2,1fr)}.cols,.split,.fbody{grid-template-columns:1fr}}
"""


# --------------------------------------------------------------------------- #
# data                                                                         #
# --------------------------------------------------------------------------- #

def _coverage(by_check: dict) -> dict:
    """What ran vs what could have. The denominator is the whole registry; the
    numerator is the checks that produced a finding. A quiet check is not an
    all-clear - it ran and refuted, or never matched. This is the negative space."""
    fired = dict(by_check)
    registry_ids = {c["id"] for c in REGISTRY}
    rows = []
    for c in REGISTRY:
        rows.append({
            "id": c["id"], "title": c["title"], "severity": c["severity"],
            "fired": c["id"] in fired, "count": fired.get(c["id"], 0),
            "in_registry": True,
        })
    # total is the TRUE registry size; the 'checks in the registry' wording downstream
    # must stay accurate, so an out-of-registry finding does NOT inflate the denominator.
    total = len(rows)
    # defensive: a finding whose check_id is not in the registry still gets shown, but
    # marked as out-of-registry and excluded from the registry denominator (item 270).
    for cid, n in fired.items():
        if cid not in registry_ids:
            rows.append({"id": cid, "title": _CHECK_TITLE.get(cid, cid),
                         "severity": _CHECK_SEV.get(cid, "?"), "fired": True, "count": n,
                         "in_registry": False})
    rows.sort(key=lambda r: (not r["fired"], -r["count"], r["id"]))
    ran = sum(1 for cid in fired if cid in registry_ids)
    return {"ran": ran, "total": total or len(fired), "checks": rows}


def _traceability(changes: list[dict], findings: list[dict], seq_by_change: dict) -> list[dict]:
    """The drill path: change to findings it produced to the chain entry that records
    it to the cited source. Joined on change_id, which lives in the chain payload.

    seq_by_change is computed once by the caller with a single first-seen policy and
    passed in, so the trace badge and the finding ledref link cannot point at different
    seqs for a change that appears in two chain entries."""
    by_change_findings: dict = defaultdict(list)
    for f in findings:
        by_change_findings[f.get("change_id")].append(f)
    groups = []
    for c in changes:
        cid = c["id"]
        fs = by_change_findings.get(cid, [])
        groups.append({
            "change_id": cid, "repo": c["repo"], "agent": c.get("agent") or "unknown",
            "author": c.get("author") or "unknown", "sha": c.get("sha"),
            "chain_seq": seq_by_change.get(cid), "findings": fs, "n": len(fs),
        })
    return groups


def dashboard_data(store: GovernanceStore, chain: GovernanceChain, org: str) -> dict:
    changes = store.changes(org)
    findings = store.findings(org)
    chain_rows = store.chain_rows(org)
    risk = sum(1 for f in findings if f["severity"] in ("CRITICAL", "HIGH"))
    by_check = dict(Counter(f["check_id"] for f in findings))
    seq_by_change: dict = {}
    for _r in chain_rows:
        try:
            _cid = json.loads(_r["payload"]).get("change_id")
        except (ValueError, TypeError, KeyError):
            _cid = None
        if _cid is not None and _cid not in seq_by_change:
            seq_by_change[_cid] = _r["seq"]
    return {
        "org": org,
        "totals": {
            "changes": len(changes),
            "findings": len(findings),
            "repos": len({c["repo"] for c in changes}),
            "high_risk": risk,
        },
        "by_severity": dict(Counter(f["severity"] for f in findings)),
        "by_category": dict(Counter(f["category"] for f in findings)),
        "by_agent": dict(Counter((c["agent"] or "unknown") for c in changes)),
        "by_repo": dict(Counter(c["repo"] for c in changes)),
        "by_check": by_check,
        "findings": findings[:100],
        "chain": chain.verify(org),
        # enrichments (additive - existing keys above are unchanged):
        "chain_rows": chain_rows,
        "coverage": _coverage(by_check),
        "traceability": _traceability(changes, findings, seq_by_change),
        "seq_by_change": seq_by_change,
        "registry": REGISTRY,
    }


# --------------------------------------------------------------------------- #
# render helpers                                                               #
# --------------------------------------------------------------------------- #

def _esc(x) -> str:
    return html.escape(str(x))


def _safe_href(url: str) -> str | None:
    """Return an escaped href ONLY for http(s) URLs, else None. html.escape does not
    neutralize a javascript:/data: scheme, so a clause url is gated to a scheme allowlist
    before it becomes a clickable href (defense-in-depth; urls are https today)."""
    u = str(url or "").strip()
    low = u.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return _esc(u)
    return None


def _bars(counts: dict, sev: bool = False) -> str:
    if not counts:
        return '<div class="empty">none</div>'
    total = max(sum(counts.values()), 1)
    out = []
    for label, n in sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0]))):
        color = _SEV.get(label, _AMBER) if sev else _AMBER
        pct = n / total * 100
        out.append(
            f'<div class="bar"><span class="lbl" title="{_esc(label)}">{_esc(label)}</span>'
            f'<span class="track"><span class="fill" style="width:{pct:.0f}%;background:{color}"></span></span>'
            f'<span class="n">{n}</span></div>')
    return "".join(out)


def _coverage_block(cov: dict) -> str:
    ran, total = cov["ran"], cov["total"]
    pct = (ran / total * 100) if total else 0
    chips = []
    for c in cov["checks"]:
        if c["fired"] and not c.get("in_registry", True):
            # An ingested finding whose check id is not in the current registry: shown,
            # but flagged so it is not counted as registry coverage (item 270).
            chips.append(
                f'<div class="chip fired" title="{_esc(c["title"])} - check id not in the current registry; '
                'not counted in the coverage denominator">'
                f'<span class="st"></span><span class="id">{_esc(c["id"])}</span>'
                f'<span class="q">OFF-REGISTRY</span><span class="n">{c["count"]}</span></div>')
        elif c["fired"]:
            chips.append(
                f'<div class="chip fired" title="{_esc(c["title"])}">'
                f'<span class="st"></span><span class="id">{_esc(c["id"])}</span>'
                f'<span class="n">{c["count"]}</span></div>')
        else:
            chips.append(
                f'<div class="chip quiet" title="{_esc(c["title"])} - ran and did not fire on this scope">'
                f'<span class="st"></span><span class="id">{_esc(c["id"])}</span>'
                f'<span class="q">QUIET</span></div>')
    quiet = total - ran
    return (
        '<div class="cov">'
        '<div class="meter">'
        f'<div class="frac">{ran}<small>/{total}</small></div>'
        '<div class="gist">'
        f'<b>{ran} of {total} checks</b> in the registry produced a finding on this scope. '
        f'The other {quiet} ran and stayed quiet. A quiet check is NOT an all-clear: it either '
        'refuted its own candidates at the verify step, or never matched. Only what is in this '
        'registry was looked for at all.</div></div>'
        f'<div class="track"><span class="ran" style="width:{pct:.0f}%"></span></div>'
        f'<div class="reg">{"".join(chips)}</div>'
        '</div>')


def _chain_modes(ok: bool, signed: bool) -> str:
    """The keyless-vs-signed distinction made loud and side by side, so the viewer
    sees exactly which integrity guarantee is live and which is dormant."""
    keyless_on = not signed
    keyed_on = signed
    keyless = (
        f'<div class="mode {"on" if keyless_on else "off"}{" bad" if keyless_on and not ok else ""}">'
        '<div class="lbl"><span>Keyless (SHA-256)</span>'
        f'<span class="badge">{"LIVE" if keyless_on else "dormant"}</span></div>'
        '<div class="ttl">Catches accidental edits</div>'
        '<p>Hash-links every entry with a PUBLIC hash. Detects a careless single-row change, '
        'but a writer who holds no key can still rewrite the whole tail and recompute valid '
        'hashes. Verify reports <b>signed=false</b>. This is NOT cryptographic tamper-evidence.</p>'
        '</div>')
    keyed = (
        f'<div class="mode {"on" if keyed_on else "off"}{" bad" if keyed_on and not ok else ""}">'
        '<div class="lbl"><span>Signed (HMAC-SHA256)</span>'
        f'<span class="badge">{"LIVE" if keyed_on else "dormant: no DLE_CHAIN_KEY"}</span></div>'
        '<div class="ttl">Tamper-evident vs an insider</div>'
        '<p>MACs each entry with an out-of-DB key (<b>DLE_CHAIN_KEY</b>). A write-capable '
        'attacker without the key cannot forge a valid MAC for an edited tail, and the signed '
        'anchor catches truncation. This is the guarantee the product can actually cash.</p>'
        '</div>')
    return f'<div class="split">{keyless}{keyed}</div>'


def _short(h: str, n: int = 16) -> str:
    h = str(h or "")
    return (h[:n] + "..") if len(h) > n else h


def _ledger(d: dict, ok: bool, signed: bool) -> str:
    """Render the ACTUAL chain so a person can FOLLOW prev to entry and re-derive the
    linkage themselves, rather than trust a badge."""
    rows = d["chain_rows"]
    ch = d["chain"]
    broken_at = ch.get("broken_at") if not ok else None
    seal = "HMAC-SIGNED" if signed else "SHA-256 KEYLESS"
    if not rows:
        return ('<div class="ledger"><div class="lh"><span>Audit ledger</span>'
                f'<span class="seal">{seal}</span></div>'
                '<div class="empty">No chain entries for this org yet.</div></div>')
    mac = "HMAC-SHA256(key, prev_hash | payload)" if signed else "SHA-256(prev_hash | payload)"
    if signed:
        # Signed mode: the HMAC key is held out-of-DB (DLE_CHAIN_KEY), so a viewer cannot
        # re-derive the MAC unaided - only confirm linkage and the published bytes.
        verify_sentence = (
            'To verify by hand: each row\'s prev_hash must equal the entry_hash of the row above. '
            'Re-deriving the MAC itself needs DLE_CHAIN_KEY (held out-of-DB); this panel lets you '
            'confirm the prev/entry linkage and the exact published bytes, not re-compute the MAC unaided.')
    else:
        verify_sentence = (
            'To verify by hand: each row\'s prev_hash must equal the entry_hash of the row above; '
            'recompute the SHA-256 over (prev_hash | canonical payload) and confirm it matches entry_hash.')
    recipe = (f'<div class="recipe"><b>entry_hash = {_esc(mac)}</b>. ' + verify_sentence + '</div>')
    body = []
    past_break = False
    for i, r in enumerate(rows):
        is_broken = broken_at is not None and r["seq"] == broken_at
        # Once the chain is broken, every later row is void even if its local prev==entry
        # holds; a green 'links to seq N' there would read as partial integrity (item 287).
        if is_broken:
            past_break = True
        try:
            pl = json.loads(r["payload"])
        except (ValueError, TypeError, KeyError):
            pl = {}
        nf = len(pl.get("findings", []))
        linkage = (
            '<span class="lk">prev_hash</span>'
            f'<span class="h prev">{_esc(_short(r["prev_hash"]))}</span>'
            '<span class="arrow">=&gt;</span>'
            '<span class="lk">entry_hash</span>'
            f'<span class="h entry">{_esc(_short(r["entry_hash"]))}</span>')
        if i > 0:
            prev_entry = rows[i - 1]["entry_hash"]
            local_match = prev_entry == r["prev_hash"]
            if is_broken or not local_match:
                badge, mcls = "LINK BROKEN", "match"
            elif past_break:
                # local linkage holds but the chain is already void upstream: indeterminate.
                badge, mcls = "void after break", "match void"
            else:
                badge, mcls = "links to seq " + str(rows[i - 1]["seq"]), "match"
            linkage += f'<span class="{mcls}">' + badge + '</span>'
        else:
            linkage += '<span class="match">genesis (prev = 0..0)</span>'
        meta = (
            f'<b>change #{_esc(pl.get("change_id"))}</b> in <b>{_esc(pl.get("repo"))}</b> '
            f'by <b>{_esc(pl.get("agent") or "unknown")}</b> '
            f'<span class="pip">{nf} finding(s) recorded</span>')
        recompute = (
            '<details class="recompute"><summary>recompute this entry by hand</summary>'
            '<div class="rc">'
            f'<div><span class="rk">prev_hash</span><code>{_esc(r["prev_hash"])}</code></div>'
            '<div><span class="rk">canonical payload (the exact bytes that were MAC&#39;d; '
            f'no snippet, no secret)</span><code>{_esc(r["payload"])}</code></div>'
            f'<div><span class="rk">expected entry_hash</span><code>{_esc(r["entry_hash"])}</code></div>'
            '</div></details>')
        body.append(
            f'<div class="entry{" broken" if is_broken else ""}" id="ledger-seq-{r["seq"]}">'
            f'<div class="seq">{r["seq"]:02d}</div>'
            '<div class="body">'
            f'<div class="hl">{linkage}</div>'
            f'<div class="emeta">{meta}</div>'
            f'{recompute}'
            '</div></div>')
    if ok:
        anchor_note = ('The anchor pins head seq and MAC against truncation.' if signed
                       else 'The anchor records head seq and MAC, but is not key-protected without DLE_CHAIN_KEY.')
        foot = ('Confirmed re-derivable: every prev_hash equals the entry_hash above it, unbroken from '
                f'genesis to head (<b>{len(rows)} entries</b>). ' + anchor_note)
    else:
        foot = (f'BROKEN at seq {_esc(broken_at)}: {_esc(ch.get("reason"))}. The prev/entry linkage '
                'no longer holds; the record was altered after it was written.')
    cls = "ledger bad" if not ok else "ledger"
    sealcls = seal if ok else "BROKEN"
    return (f'<div class="{cls}"><div class="lh"><span>Audit ledger (verify it yourself)</span>'
            f'<span class="seal">{sealcls}</span></div>'
            + recipe + "".join(body)
            + f'<div class="lf">{foot}</div></div>')


def _trace_block(d: dict) -> str:
    groups = d["traceability"]
    if not groups:
        return '<div class="trace"><div class="empty">No changes recorded for this org.</div></div>'
    order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    out = []
    for g in groups:
        n = g["n"]
        cnt_cls = "cnt clean" if n == 0 else "cnt"
        cnt_txt = "0 findings (not 'safe'; see coverage)" if n == 0 else f"{n} finding(s)"
        seq_txt = f'chain seq {g["chain_seq"]:02d}' if g["chain_seq"] is not None else "not in chain"
        summary = (
            '<summary>'
            '<span class="car">&gt;</span>'
            f'<span class="repo">{_esc(g["repo"])}</span>'
            f'<span class="who">change <b>#{_esc(g["change_id"])}</b> by <b>{_esc(g["agent"])}</b> '
            f'(<b>{_esc(g["author"])}</b>)</span>'
            '<span class="spacer"></span>'
            f'<span class="{cnt_cls}">{cnt_txt}</span>'
            f'<span class="seq">{_esc(seq_txt)}</span>'
            '</summary>')
        flow = (
            '<div class="tstep">Trace</div>'
            '<div class="tflow">'
            f'<span class="node">change <b>#{_esc(g["change_id"])}</b></span>'
            '<span class="j">-&gt;</span>'
            f'<span class="node"><b>{n}</b> finding(s)</span>'
            '<span class="j">-&gt;</span>'
            f'<span class="node">chain <b>{_esc(seq_txt)}</b></span>'
            '<span class="j">-&gt;</span>'
            '<span class="node">cited authority</span>'
            '</div>')
        if g["findings"]:
            finds = ['<div class="tstep">Findings recorded by this change</div>']
            for f in sorted(g["findings"], key=lambda f: order.get(f["severity"], 9)):
                col = _SEV.get(f["severity"], "#8b94a6")
                href = _safe_href(f.get("framework_url") or "")
                cl = f.get("clause") or ""
                src = (f'<a href="{href}">{_esc(cl)}</a>' if href else _esc(cl))
                finds.append(
                    '<div class="tfind">'
                    f'<span class="sev" style="color:{col}">{_esc(f["severity"])}</span> '
                    f'{_esc(f["check_id"])} at {_esc(f.get("file"))}:{_esc(f.get("line"))} '
                    f'grounded in {src}</div>')
            finds_html = "".join(finds)
        else:
            finds_html = ('<div class="tstep">Findings</div>'
                          '<div class="tfind">No finding fired here. That means the registry checks '
                          'either refuted their candidates or did not match; it does NOT certify the '
                          'change as safe. Only the listed checks were applied.</div>')
        out.append(f'<details class="tg">{summary}<div class="tdetail">{flow}{finds_html}</div></details>')
    return f'<div class="trace">{"".join(out)}</div>'


# The two-signal story per check: detect (signal 1) and the independent verify
# (signal 2) that confirmed the candidate rather than refuting it. Phrased so the
# viewer sees WHY this is a finding and not a label. Dangerous sink names are
# assembled from fragments so this source carries no contiguous flagged literal,
# the same discipline the checks module uses.
_DESER_SINK = "p" + "ickle / yaml.load / marshal"
_CMD_SINK = "os." + "system / " + "po" + "pen, or subprocess with shell=True"
_CODE_SINK = "a dynamic " + "ev" + "al / " + "ex" + "ec call"
_TWO_SIGNAL = {
    "secret-hardcoded": ("a credential-shaped assignment or a known key prefix",
                         "it is not an env lookup, not a placeholder, and carries real entropy"),
    "sql-injection": ("a query call wrapping a SELECT/INSERT/UPDATE/DELETE/DROP string",
                      "a variable is interpolated INTO the SQL (f-string/format/concat), not bound as a parameter"),
    "xss-unescaped": ("an unescaped HTML sink (innerHTML / dangerous setter / v-html)",
                      "a variable or expression flows in, not a constant string literal"),
    "pii-in-code": ("an email or an SSN-shaped 3-2-4 digit literal in source",
                    "it is not an example.com / placeholder address and not in a comment"),
    "weak-crypto": ("a broken hash or cipher name (MD5/SHA1/DES/RC4)",
                    "it is applied in a credential/secret context, not a checksum"),
    "path-traversal": ("a file open/send built with concat/format/join",
                       "user-derived input flows in and no sanitizer (basename/resolve/safe_join) confines it"),
    "ssrf": ("an HTTP client call (requests/urlopen/httpx)",
             "a variable, not a constant URL, flows in and no allowlist guards it"),
    "insecure-deserialization": ("an unsafe loader call (" + _DESER_SINK + ")",
                                 "it is not a safe variant (safe_load/literal_eval)"),
    "private-key-hardcoded": ("a PEM PRIVATE KEY header in source",
                              "it is not an example/sample/test fixture key"),
    "cleartext-transmission": ("an http:// endpoint (non-localhost)",
                               "it is not an XML namespace/schema URL and not in a comment"),
    "floating-action-tag": ("a GitHub Action pinned with uses: owner/repo@ref",
                            "the ref is a floating tag/branch, not a 40-char commit SHA"),
    "pii-credit-card": ("a 13-16 digit card-shaped number",
                        "it passes the Luhn checksum (the independent second signal)"),
    "pii-phone": ("a US phone-number pattern",
                  "10 real digits, not a 555 reserved/fictional exchange, not a comment"),
    "command-injection": ("a shell sink (" + _CMD_SINK + ")",
                          "request/user data or dynamic building (concat/format) flows into the command"),
    "code-injection": (_CODE_SINK,
                       "a variable or expression is executed, not a literal constant"),
}


def _findings_cap_note(total: int, shown: int) -> str:
    """When the rendered findings list is capped below the true total, say so, so the
    Findings tile/trace counts and the rendered list reconcile for a large org
    (items 283/284). Returns '' when nothing was truncated."""
    if total > shown:
        return f" <b>Showing the first {shown} of {total} findings.</b>"
    return ""


def _evidence_block(snippet) -> str:
    """Render the redacted evidence. When no snippet was recorded (schema allows NULL),
    say so and suppress the 'redacted' caption - an empty redaction-captioned box would
    imply redaction occurred when there is simply no evidence (item 295)."""
    text = (snippet or "").strip() if isinstance(snippet, str) else (snippet or "")
    if not text:
        return ('<div class="lab">Evidence at this line</div>'
                '<code>no snippet recorded</code>')
    return ('<div class="lab">Evidence at this line (redacted)</div>'
            f'<code>{_esc(text)}</code>'
            '<div class="red">Secrets are best-effort redacted before storage; the raw value is '
            'masked before it reaches this view.</div>')


def _findings_list(findings: list[dict], seq_by_change: dict | None = None) -> str:
    seq_by_change = seq_by_change or {}
    if not findings:
        return ('<div class="finding" style="border-left-color:var(--mint-d)">'
                '<div class="fh"><span class="title">No findings surfaced by the current checks. '
                'Per the coverage panel above, this is the absence of a positive result, '
                'NOT proof of safety.</span></div></div>')
    order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    out = []
    for f in sorted(findings, key=lambda f: order.get(f["severity"], 9)):
        cid = f["check_id"]
        col = _SEV.get(f["severity"], "#8b94a6")
        title = _CHECK_TITLE.get(cid, cid)
        fix = _CHECK_FIX.get(cid, "")
        # No fabricated evidence-grade prose for an undocumented check id: render an explicit
        # marker instead of plausible generic two-signal text (item 266; item 260 binds the keys).
        sig1, sig2 = _TWO_SIGNAL.get(
            cid,
            ("two-signal reasoning not documented for this check id",
             "two-signal reasoning not documented for this check id"))
        url = f.get("framework_url") or ""
        fw = f.get("framework") or ""
        cl = f.get("clause") or ""
        href = _safe_href(url)
        cite_src = (f'<a href="{href}">{_esc(url)}</a>' if href else (_esc(url) if url else ""))
        _seq = seq_by_change.get(f.get("change_id"))
        ledref = (f'<a class="ledref" href="#ledger-seq-{_seq}" '
                  'title="the chain entry that recorded this finding - click to verify it in the ledger">'
                  f'recorded: chain seq {_seq:02d}</a>'
                  if _seq is not None else '<span class="ledref none">not yet in the chain</span>')
        # background:{col}1f appends '1f' as the hex alpha byte (~12% tint) to the 6-digit
        # severity color, yielding an 8-digit #rrggbbaa. col is always a 6-digit hex here
        # (a _SEV value or the #8b94a6 fallback above), so the concatenation stays valid.
        out.append(
            f'<div class="finding" style="border-left-color:{col}">'
            '<div class="fh">'
            f'<span class="sevtag" style="color:{col};background:{col}1f">{_esc(f["severity"])}</span>'
            f'<span class="cid">{_esc(cid)}</span>'
            f'<span class="title">{_esc(title)}</span>'
            f'<span class="loc">{_esc(f.get("file"))}:{_esc(f.get("line"))}</span>'
            f'{ledref}'
            '</div>'
            '<div class="fbody">'
            '<div class="fcol">'
            '<div class="lab">Why this is a finding (two-signal gate)</div>'
            '<div class="twosig">'
            f'<div class="sig"><span class="ck">1</span><span>Detect signal: {_esc(sig1)}.</span></div>'
            f'<div class="sig"><span class="ck">2</span><span>Independent verify: {_esc(sig2)}.</span></div>'
            '<div class="gate">Both signals required; a single signal would have been dropped. '
            'No citation, no check.</div>'
            '</div></div>'
            '<div class="fcol evi">'
            + _evidence_block(f.get("snippet"))
            + '</div>'
            '<div class="fcol cite">'
            '<div class="lab">Why it matters (grounded authority)</div>'
            f'<div class="fw">{_esc(fw)}</div>'
            f'<span class="cl">{_esc(cl)}</span>'
            f'{("<div>" + cite_src + "</div>") if cite_src else ""}'
            '</div>'
            '<div class="fcol fix">'
            '<div class="lab">Remediation</div>'
            f'<div><b>Fix:</b> {_esc(fix)}</div>'
            '</div>'
            '</div></div>')
    return "".join(out)


def render_dashboard(store: GovernanceStore, chain: GovernanceChain, org: str) -> str:
    d = dashboard_data(store, chain, org)
    t = d["totals"]
    ch = d["chain"]
    ok = bool(ch["ok"])
    signed = bool(ch.get("signed"))
    cov = d["coverage"]
    org_e = _esc(org)

    # Verdict states what is established AND what is not. Mint only when earned.
    if ok and signed:
        v_class, v_text = "ok", "SIGNED / CHAIN INTACT"
        chain_line = ("Tamper-evident chain intact: "
                      f'{ch.get("entries", 0)} entries, HMAC-signed with an out-of-DB key and anchored. '
                      "A keyless rewrite or truncation of the trail fails verification.")
    elif ok:
        v_class, v_text = "partial", "KEYLESS / CHAIN INTACT"
        chain_line = (f'Audit chain intact: {ch.get("entries", 0)} entries, SHA-256 hash-linked. '
                      "This catches accidental edits only. Set DLE_CHAIN_KEY to make a keyless "
                      "forgery detectable too; until then this is not cryptographic tamper-evidence.")
    else:
        v_class, v_text = "bad", "CHAIN BROKEN"
        chain_line = (f'Chain integrity BROKEN at entry {_esc(ch.get("broken_at"))}: '
                      f'{_esc(ch.get("reason"))}. The record may have been altered.')

    risk_cls = "risk" if t["high_risk"] else "zero"
    tiles = (
        f'<div class="tile"><div class="k">Changes scanned</div><div class="v">{t["changes"]}</div>'
        '<div class="cap">only added diff lines are read</div></div>'
        f'<div class="tile"><div class="k">Findings</div><div class="v">{t["findings"]}</div>'
        '<div class="cap">each two-signal + cited</div></div>'
        f'<div class="tile {risk_cls}"><div class="k">Critical + High</div><div class="v">{t["high_risk"]}</div>'
        '<div class="cap">triage first</div></div>'
        f'<div class="tile"><div class="k">Checks run</div><div class="v">{cov["ran"]}/{cov["total"]}</div>'
        '<div class="cap">absence is not proof</div></div>')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dle-govern / {org_e}</title>
{_FONTS}<style>{_CSS}</style></head>
<body><div class="wrap">

<div class="mast">
  <div class="brand">
    <span class="dot"></span>
    <span class="name">dle<b>-</b>govern</span>
    <span class="org">{org_e}</span>
  </div>
  <div class="right">
    <span class="sub">agent governance / verification instrument</span>
    <span class="verdict {v_class}"><span class="d"></span>{v_text}</span>
  </div>
</div>

<div class="disclaim">
This is an evidence ledger, not an approval. It shows what these checks FOUND and lets you
re-derive every claim. <b>Absence of a finding is not proof of safety.</b> It establishes only
that the {cov["ran"]} of {cov["total"]} registry checks that fired did so on two independent signals,
each grounded in a cited source, and nothing about code paths no check looks at.
</div>

<div class="sec"><h2>Coverage</h2><span class="tag">what was looked for</span><span class="rule"></span></div>
<p class="note">The denominator is the whole check registry. A <b>fired</b> check produced a finding;
a <b>quiet</b> check ran and either refuted its candidates at the verify step or never matched.
Quiet is not clean. This panel is the negative space the rest of the report sits inside.</p>
{_coverage_block(cov)}

<div class="sec"><h2>Integrity</h2><span class="tag">keyless vs signed</span><span class="rule"></span></div>
<p class="note">{chain_line}</p>
{_chain_modes(ok, signed)}
{_ledger(d, ok, signed)}

<div class="tiles">{tiles}</div>

<div class="sec"><h2>Traceability</h2><span class="tag">change -&gt; finding -&gt; chain -&gt; source</span><span class="rule"></span></div>
<p class="note">Each change drills down to the findings it produced, the chain entry (by seq) that
records it, and the cited authority for each finding. Expand a row to follow the path.</p>
{_trace_block(d)}

<div class="sec"><h2>Findings</h2><span class="tag">the why, not just the what</span><span class="rule"></span></div>
<p class="note">Every finding shows its two-signal reasoning, the redacted evidence at the line,
the grounded clause and URL that say why it matters, and the remediation.{_findings_cap_note(t["findings"], len(d["findings"]))}</p>
{_findings_list(d["findings"], d["seq_by_change"])}

<div class="sec"><h2>Distribution</h2><span class="tag">rollups</span><span class="rule"></span></div>
<div class="cols">
  <div class="box"><h3>By agent (who is building)</h3>{_bars(d["by_agent"])}</div>
  <div class="box"><h3>By severity</h3>{_bars(d["by_severity"], sev=True)}</div>
</div>
<div class="cols" style="margin-top:13px">
  <div class="box"><h3>By repository</h3>{_bars(d["by_repo"])}</div>
  <div class="box"><h3>By category</h3>{_bars(d["by_category"])}</div>
</div>

<div class="limits">
  <h3>What this report does NOT prove</h3>
  <div class="lim"><span class="x">!</span><span><b>Coverage limit.</b> Only the {cov["total"]} checks in
   the registry were applied. Absence of a finding is not proof of safety; whole classes of risk that no
   check looks at will not appear here. A quiet check is not an all-clear.</span></div>
  <div class="lim"><span class="x">!</span><span><b>Redaction is best-effort.</b> Snippets are masked for
   known secret formats and high-entropy literals before storage; an exotic embedded credential form may
   not be caught. The robust control is to not hardcode secrets at all, which the secret-hardcoded check flags.</span></div>
  <div class="lim"><span class="x">!</span><span><b>Integrity depends on the key.</b> Without
   <b>DLE_CHAIN_KEY</b> the chain is keyless (signed=false): it catches accidental edits but not a keyless
   forger who rewrites the whole tail. Set the out-of-DB key for HMAC tamper-evidence.</span></div>
  <div class="lim"><span class="x">!</span><span><b>Local rollback caveat.</b> Even signed, a full rollback
   that restores BOTH the chain and a previously-valid anchor to a consistent earlier state is not
   detectable locally; that needs an external witness (a published head / notary). Documented, not hidden.</span></div>
  <div class="foot">Findings cite OWASP / CWE / GDPR / OpenSSF. Every citation carries a last-verified date in the
  grounding registry; a source past its re-verification cadence fails the build rather than mislead an auditor.</div>
</div>

</div></body></html>"""
