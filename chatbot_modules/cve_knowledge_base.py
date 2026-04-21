import os
import json
import logging
import threading
import re
from typing import Dict, List, Optional, Any, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global in-memory indexes
# ---------------------------------------------------------------------------
_CVE_ID_INDEX: Dict[str, dict] = {}
_CWE_INDEX: Dict[str, List[dict]] = {}          # CWE-XX  -> list of CVE records
_KEYWORD_INDEX: Dict[str, List[str]] = {}        # keyword -> list of CVE IDs
_CWE_PROFILES: Dict[str, dict] = {}             # clean numeric ID -> profile dict
_LOADED_YEARS = set()

_kb_lock = threading.Lock()
_kb_initialized = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DEFAULT_YEARS = [2024, 2025, 2026]
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR    = os.path.join(os.path.dirname(BASE_DIR), "CWE_Profiles")
PROCESSED_CVES_DIR = os.path.join(PROFILES_DIR, "Processed_CVEs")
CWE_SUMMARY_FILE   = os.path.join(PROFILES_DIR, "cwe_text_summary.json")

# ---------------------------------------------------------------------------
# Initialisation / Loading
# ---------------------------------------------------------------------------

def _init_kb_if_needed(years_to_load: Optional[List[int]] = None):
    global _kb_initialized
    if not _kb_initialized:
        with _kb_lock:
            if not _kb_initialized:
                _load_cwe_profiles()
                _load_cve_years(years_to_load or DEFAULT_YEARS)
                _kb_initialized = True
    elif years_to_load:
        with _kb_lock:
            missing = [y for y in years_to_load if y not in _LOADED_YEARS]
            if missing:
                _load_cve_years(missing)


def _load_cwe_profiles():
    global _CWE_PROFILES
    try:
        if os.path.exists(CWE_SUMMARY_FILE):
            with open(CWE_SUMMARY_FILE, "r", encoding="utf-8") as f:
                _CWE_PROFILES = json.load(f)
            logger.info(f"Loaded {len(_CWE_PROFILES)} CWE profiles.")
    except Exception as exc:
        logger.error(f"Failed to load CWE profiles: {exc}")


def _load_cve_years(years: List[int]):
    global _CVE_ID_INDEX, _CWE_INDEX, _KEYWORD_INDEX, _LOADED_YEARS
    for year in years:
        if year in _LOADED_YEARS:
            continue
        file_path = os.path.join(PROCESSED_CVES_DIR, f"processed_cves_{year}.json")
        if not os.path.exists(file_path):
            logger.warning(f"CVE data file not found: {file_path}")
            continue
        logger.info(f"Loading CVE data for {year}…")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            for rec in records:
                cve_id = rec.get("cve_id")
                if not cve_id:
                    continue
                _CVE_ID_INDEX[cve_id] = rec
                # CWE reverse index
                cwe_id = rec.get("cwe_id")
                if cwe_id:
                    _CWE_INDEX.setdefault(cwe_id, []).append(rec)
                # Keyword inverted index
                for kw in rec.get("keywords", []):
                    _KEYWORD_INDEX.setdefault(kw.lower(), []).append(cve_id)
            _LOADED_YEARS.add(year)
            logger.info(f"Indexed {year}: {len(records)} records.")
        except Exception as exc:
            logger.error(f"Error loading {file_path}: {exc}")


# ---------------------------------------------------------------------------
# Query Detection – returns {"handler": fn, "args": dict} or None
# ---------------------------------------------------------------------------

# Intents that the detector recognises
_RECENT_WORDS   = {"recent", "latest", "newest", "last", "most recent", "most-recent"}
_CRITICAL_WORDS = {"critical", "severe", "highest", "worst", "most severe", "most dangerous"}
_COUNT_PHRASES  = {"how many", "count", "number of", "total number", "total"}
_FREQ_PHRASES   = {"common", "frequent", "top", "popular", "prevalence", "most reported"}
_OLDEST_WORDS   = {"oldest", "earliest", "first"}
_VECTOR_WORDS   = {"all", "list", "show", "summarise", "summarize", "overview"}
_CVE_KEYWORDS   = {"cve", "vulnerabilit", "exploit", "vuln"}
_CWE_KEYWORDS   = {"cwe", "weakness", "weaknesses"}


def _q_has(q: str, terms) -> bool:
    return any(t in q for t in terms)


def detect_cve_cwe_query(query: str) -> Optional[Dict[str, Any]]:
    """
    Classify the user query and route it to the correct local KB handler.
    Returns {"handler": callable, "args": dict} or None if not a KB query.
    """
    _init_kb_if_needed()
    q = query.lower()

    # ── 1. Direct CVE ID lookup ──────────────────────────────────────────
    cve_match = re.search(r"cve[- ]?(\d{4})[- ]?(\d{4,7})", q)
    if cve_match:
        year   = int(cve_match.group(1))
        cve_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
        _init_kb_if_needed([year])
        return {"handler": lookup_cve, "args": {"cve_id": cve_id}}

    # ── 2. Direct CWE ID lookup ──────────────────────────────────────────
    cwe_match = re.search(r"cwe[- ]?(\d+)", q)
    if cwe_match:
        return {"handler": lookup_cwe, "args": {"cwe_id": cwe_match.group(1)}}

    # ── Decide if this is a CVE/CWE-related query at all ────────────────
    touches_cve = any(kw in q for kw in _CVE_KEYWORDS)
    touches_cwe = any(kw in q for kw in _CWE_KEYWORDS)
    if not (touches_cve or touches_cwe):
        return None  # Not our territory

    # ── 3. "Most common / top CWEs" ──────────────────────────────────────
    if touches_cwe and _q_has(q, _FREQ_PHRASES):
        top_n = _extract_top_n(q, default=5)
        return {"handler": get_top_cwes, "args": {"top_n": top_n}}

    # ── 4. Analytical CVE query (recent / critical / count / oldest) ─────
    is_recent   = _q_has(q, _RECENT_WORDS)
    is_oldest   = _q_has(q, _OLDEST_WORDS)
    is_critical = _q_has(q, _CRITICAL_WORDS)
    is_count    = _q_has(q, _COUNT_PHRASES)
    is_list     = _q_has(q, _VECTOR_WORDS)

    if is_recent or is_oldest or is_critical or is_count or is_list:
        top_n = _extract_top_n(q, default=5)
        context_words = _extract_context_words(q)
        return {
            "handler": analyze_cve_database,
            "args": {
                "is_recent":   is_recent,
                "is_oldest":   is_oldest,
                "is_critical": is_critical,
                "is_count":    is_count,
                "context":     context_words,
                "top_k":       top_n,
            },
        }

    # ── 5. Generic keyword context search ───────────────────────────────
    stop_words = {"cve", "cves", "vulnerabilities", "vulnerability", "exploit",
                  "cwe", "weakness", "show", "list", "find", "tell", "what",
                  "about", "give", "which", "with", "that", "have", "does",
                  "related", "regarding", "information", "details", "the",
                  "a", "an", "of", "for", "in", "to", "me", "and", "or"}
    words = [w for w in re.findall(r"\w+", q) if w not in stop_words and len(w) > 3]
    if words:
        return {"handler": search_cve_by_context, "args": {"query": " ".join(words), "top_k": 5}}

    return None


def _extract_top_n(q: str, default: int = 5) -> int:
    """Pull 'top 10', '5 latest', etc. from the query."""
    m = re.search(r"\b(\d+)\b", q)
    return int(m.group(1)) if m and 1 <= int(m.group(1)) <= 50 else default


def _extract_context_words(q: str) -> str:
    """Remove analytics stop-words from a query to get the product / vendor context."""
    analytics_stop = {
        "recent", "latest", "newest", "oldest", "earliest", "most", "critical",
        "severe", "highest", "worst", "common", "frequent", "how", "many",
        "count", "number", "total", "list", "show", "tell", "give", "find",
        "what", "which", "the", "a", "an", "of", "for", "is", "are", "was",
        "cve", "cves", "vulnerability", "vulnerabilities", "exploit",
        "cwe", "weakness", "weaknesses", "in", "on", "to", "me", "and", "or",
        # filler / deictic words that should never become context
        "there", "here", "these", "those", "them", "they", "its", "all",
        "any", "some", "other", "related", "regarding", "about", "top",
        "with", "from", "between", "into", "out", "up", "down", "get",
        "can", "do", "does", "did", "has", "have", "had", "will", "would",
    }
    words = [w for w in re.findall(r"\w+", q.lower())
             if w not in analytics_stop and len(w) > 2]
    return " ".join(words)


# ---------------------------------------------------------------------------
# Handler functions
# ---------------------------------------------------------------------------

def lookup_cve(cve_id: str) -> str:
    """O(1) direct CVE lookup."""
    _init_kb_if_needed()
    cve_id = cve_id.upper().strip()
    m = re.search(r"CVE-(\d{4})-", cve_id)
    if m:
        yr = int(m.group(1))
        if yr not in _LOADED_YEARS:
            _init_kb_if_needed([yr])
    rec = _CVE_ID_INDEX.get(cve_id)
    if not rec:
        return f"No local records found for **{cve_id}**."
    ctx = (
        f"**CVE ID**: {rec.get('cve_id')}\n"
        f"**Severity**: {rec.get('severity')} (CVSS Base Score: {rec.get('base_score')})\n"
        f"**CWE ID**: {rec.get('cwe_id')}\n"
        f"**Published**: {rec.get('published_date')}\n"
        f"**Description**: {rec.get('description')}\n"
    )
    platforms = rec.get("platforms", [])
    if platforms:
        ctx += f"**Affected Platforms**: {', '.join(platforms[:5])}\n"
    return ctx


def _get_cwe_profile(clean_id: str) -> dict:
    """Try multiple key formats to find a CWE profile."""
    for key in (clean_id, f"CWE-{clean_id}", clean_id.lower()):
        if key in _CWE_PROFILES:
            return _CWE_PROFILES[key]
    return {}


def lookup_cwe(cwe_id: str) -> str:
    """Return CWE profile plus example CVEs."""
    _init_kb_if_needed()
    clean = str(cwe_id).upper().replace("CWE-", "").strip()
    profile = _get_cwe_profile(clean)
    if profile:
        ctx = (
            f"**CWE-{clean} Profile**\n"
            f"**Name**: {profile.get('name', 'Unknown')}\n"
            f"**Summary**: {profile.get('summary', 'N/A')}\n"
            f"**Description**: {profile.get('description', 'N/A')}\n\n"
        )
    else:
        ctx = f"**CWE-{clean} Profile**\nNo summary found in local profiles.\n\n"
    examples = _CWE_INDEX.get(f"CWE-{clean}", [])
    if examples:
        ctx += "**Example CVEs from Local KB:**\n"
        for rec in examples[:3]:
            ctx += (f"- **{rec.get('cve_id')}** ({rec.get('severity')}, "
                    f"Score: {rec.get('base_score')}): "
                    f"{rec.get('description', '')[:150]}…\n")
    else:
        ctx += "No locally indexed CVEs found for this weakness category.\n"
    return ctx


def analyze_cve_database(
    is_recent: bool   = False,
    is_oldest: bool   = False,
    is_critical: bool = False,
    is_count: bool    = False,
    context: str      = "",
    top_k: int        = 5,
) -> str:
    """
    General analytical engine.
    - Filters by severity if is_critical.
    - Filters by keyword context if context is non-empty.
    - Sorts by published_date (desc for recent, asc for oldest).
    - Returns a count string if is_count, else a ranked list.
    """
    _init_kb_if_needed()
    pool = list(_CVE_ID_INDEX.values())

    # ── Filter: severity ────────────────────────────────────────────────
    if is_critical:
        pool = [r for r in pool if (r.get("severity") or "").upper() == "CRITICAL"]

    # ── Filter: context keywords ─────────────────────────────────────────
    if context.strip():
        ctx_words = [w.lower() for w in re.findall(r"\w+", context) if len(w) > 2]
        if ctx_words:
            matched_ids: set = set()
            for kw, ids in _KEYWORD_INDEX.items():
                if any(cw in kw or kw in cw for cw in ctx_words):
                    matched_ids.update(ids)
            if matched_ids:
                pool = [r for r in pool if r.get("cve_id") in matched_ids]

    if not pool:
        return "No CVE records matched the specified criteria in the local knowledge base."

    # ── Sorting ──────────────────────────────────────────────────────────
    def _parse_date(rec):
        try:
            return rec.get("published_date", "") or ""
        except Exception:
            return ""

    if is_recent:
        pool.sort(key=_parse_date, reverse=True)
    elif is_oldest:
        pool.sort(key=_parse_date, reverse=False)
    elif is_critical:
        # Sort by CVSS score descending within critical
        pool.sort(key=lambda r: float(r.get("base_score") or 0), reverse=True)

    # ── Count shortcut ────────────────────────────────────────────────────
    if is_count:
        qualifier = "critical " if is_critical else ""
        ctx_label = f" related to '{context}'" if context.strip() else ""
        return (f"**Local KB Count**: There are **{len(pool):,}** "
                f"{qualifier}CVE records{ctx_label} in the currently loaded "
                f"knowledge base ({', '.join(str(y) for y in sorted(_LOADED_YEARS))}).")

    # ── Render top-k ─────────────────────────────────────────────────────
    label_parts = []
    if is_recent:  label_parts.append("Most Recent")
    if is_oldest:  label_parts.append("Oldest")
    if is_critical: label_parts.append("Critical Severity")
    label = " · ".join(label_parts) if label_parts else "Matching"
    ctx_label = f" — context: *{context}*" if context.strip() else ""
    heading = f"**{label} CVEs{ctx_label} (Top {min(top_k, len(pool))} of {len(pool):,} records):**\n"

    rows = ""
    for rec in pool[:top_k]:
        score  = rec.get("base_score", "N/A")
        sev    = rec.get("severity", "UNKNOWN")
        date   = (rec.get("published_date") or "Unknown date")[:10]
        desc   = rec.get("description", "")[:200]
        cwe    = rec.get("cwe_id", "N/A")
        rows += (f"- **{rec.get('cve_id')}** | {sev} (CVSS {score}) | CWE: {cwe} "
                 f"| Published: {date}\n  {desc}…\n")

    return heading + rows


def get_top_cwes(top_n: int = 5) -> str:
    """Return the most frequently appearing CWE categories in the loaded CVE data."""
    _init_kb_if_needed()
    if not _CWE_INDEX:
        return "No CWE data currently indexed in the local knowledge base."

    # Filter out non-standard keys (N/A, NVD-CWE-noinfo, etc.)
    standard = [(k, v) for k, v in _CWE_INDEX.items() if re.match(r"CWE-\d+$", k)]
    ranked = sorted(standard, key=lambda kv: len(kv[1]), reverse=True)[:top_n]
    if not ranked:
        return "No standard CWE entries found in the local knowledge base."
    ctx = f"**Top {len(ranked)} Most Common Weaknesses (CWEs) in Local KB:**\n"
    for cwe_key, recs in ranked:
        clean = cwe_key.replace("CWE-", "")
        profile = _get_cwe_profile(clean)
        name = profile.get("name") or cwe_key
        # Truncate name if it looks like a description (>80 chars)
        if len(name) > 80:
            name = name[:77] + "…"
        summary = profile.get("summary") or "No summary available."
        if len(summary) > 200:
            summary = summary[:197] + "…"
        ctx += (f"\n### {cwe_key} — {name}\n"
                f"- **Occurrences in Local KB**: {len(recs):,} CVEs\n"
                f"- **Summary**: {summary}\n")
    return ctx


def search_cve_by_context(query: str, top_k: int = 5) -> str:
    """Inverted-index keyword scored CVE search."""
    _init_kb_if_needed()
    query_words = [w.lower() for w in re.findall(r"\w+", query)]
    scores: Dict[str, int] = {}
    for kw, cve_ids in _KEYWORD_INDEX.items():
        if any(qw in kw or kw in qw for qw in query_words):
            for cid in cve_ids:
                scores[cid] = scores.get(cid, 0) + 1
    if not scores:
        return "No local CVE records matched your search context."
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
    ctx = f"**Top {len(ranked)} Local CVE Records matched:**\n"
    for cid, _ in ranked:
        rec = _CVE_ID_INDEX.get(cid)
        if rec:
            ctx += (f"- **{cid}** (CVSS: {rec.get('base_score')}, "
                    f"CWE: {rec.get('cwe_id')}): "
                    f"{rec.get('description', '')[:200]}…\n")
    return ctx
