import re
from dataclasses import dataclass
from typing import List

CONTEXT_WINDOW = 300  # chars to extract around each org keyword match


@dataclass
class Finding:
    source: str         # which scanner found this (ahmia / torch / paste / ransomware)
    url: str
    category: str       # credentials / pii / infrastructure / documents / general
    severity: str       # critical / high / medium / low
    matched_keyword: str
    context: str        # text window around the match
    indicator: str      # human-readable label for what triggered severity


# Patterns checked inside the context window around an org keyword match.
# Format: (regex_template, severity, category, label)
# {email_domain} is replaced at runtime with the org's email domain.
_PATTERNS = [
    # ── CRITICAL ────────────────────────────────────────────────────────────
    (r'[a-zA-Z0-9._%+\-]+@{email_domain}:[^\s]{{4,}}',
     'critical', 'credentials', 'email:password combo'),
    (r'-----BEGIN[^\n]+PRIVATE KEY-----',
     'critical', 'credentials', 'private key'),
    (r'AKIA[0-9A-Z]{16}',
     'critical', 'credentials', 'AWS access key'),
    (r'(?i)ghp_[a-zA-Z0-9]{36}',
     'critical', 'credentials', 'GitHub token'),
    (r'(?i)xox[baprs]-[0-9A-Za-z\-]{10,}',
     'critical', 'credentials', 'Slack token'),
    (r'(?i)(sk|pk)-(live|test)-[a-zA-Z0-9]{20,}',
     'critical', 'credentials', 'Stripe key'),
    (r'\b\d{3}-\d{2}-\d{4}\b',
     'critical', 'pii', 'SSN pattern'),

    # ── HIGH ────────────────────────────────────────────────────────────────
    (r'(?i)password\s*[:=]\s*\S{4,}',
     'high', 'credentials', 'password field'),
    (r'(?i)passwd\s*[:=]\s*\S{4,}',
     'high', 'credentials', 'password field'),
    (r'(?i)secret\s*[:=]\s*\S{4,}',
     'high', 'credentials', 'secret field'),
    (r'(?i)api[_\s-]?key\s*[:=]\s*[A-Za-z0-9_\-\.]{16,}',
     'high', 'credentials', 'API key'),
    (r'(?i)token\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}',
     'high', 'credentials', 'auth token'),
    (r'(?i)(dump|breach|leaked?|compromise[d]?|exposed)\b',
     'high', 'documents', 'leak indicator'),
    (r'(?i)\bfor\s+sale\b|\bselling\b|\bpurchase\b',
     'high', 'documents', 'sale indicator'),
    (r'(?i)\b(source[_\s]?code|git[_\s]?repo|github|gitlab|bitbucket)\b',
     'high', 'documents', 'source code leak'),
    (r'(?i)\b(vpn|active[_\s]?directory|ldap|kerberos|okta|sso)\b',
     'high', 'infrastructure', 'auth infrastructure'),
    (r'(?i)\b(ssn|social[_\s]security|passport|national[_\s]id|driver[_\s]licen[cs]e)\b',
     'high', 'pii', 'government ID'),
    (r'(?i)\b(salary|payroll|compensation|w2|w-2)\b',
     'high', 'pii', 'financial PII'),

    # ── MEDIUM ──────────────────────────────────────────────────────────────
    (r'(?i)\b(database|db\b|\.sql\b|backup|\.csv\b|\.xlsx\b)\b',
     'medium', 'documents', 'data artifact'),
    (r'(?i)\b(internal|confidential|proprietary|classified|restricted)\b',
     'medium', 'documents', 'sensitivity label'),
    (r'(?i)\b(employee|staff|personnel|hr[_\s]data)\b',
     'medium', 'pii', 'employee data'),
    (r'(?i)\b(invoice|contract|nda|agreement|financial[_\s]report)\b',
     'medium', 'documents', 'business document'),
    (r'(?i)\b(admin[_\s]panel|control[_\s]panel|dashboard|management[_\s]console)\b',
     'medium', 'infrastructure', 'admin surface'),
]


def _severity_rank(s: str) -> int:
    return {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(s, 0)


def _extract_context(text: str, pos: int, window: int = CONTEXT_WINDOW) -> str:
    start = max(0, pos - window)
    end = min(len(text), pos + window)
    return text[start:end].strip()


def analyze_page(content: str, url: str, source: str, org_profile: dict) -> List[Finding]:
    """
    Scan a page's text content for org keyword occurrences.
    For each occurrence, extract a context window and look for
    credential/leak indicators within it.  Returns deduplicated Findings.
    """
    findings: dict = {}   # (url, indicator) → best Finding
    email_domain = re.escape(org_profile.get('email_domain', ''))

    compiled = [
        (re.compile(pat.replace('{email_domain}', email_domain), re.IGNORECASE),
         sev, cat, label)
        for pat, sev, cat, label in _PATTERNS
    ]

    for kw in org_profile.get('keywords', []):
        for m in re.finditer(re.escape(kw), content, re.IGNORECASE):
            ctx = _extract_context(content, m.start())
            best_sev = 'low'
            best_label = 'org keyword present on dark web'
            best_cat = 'general'

            for pattern, sev, cat, label in compiled:
                if pattern.search(ctx):
                    if _severity_rank(sev) > _severity_rank(best_sev):
                        best_sev = sev
                        best_label = label
                        best_cat = cat

            key = (url, best_label)
            existing = findings.get(key)
            if existing is None or _severity_rank(best_sev) > _severity_rank(existing.severity):
                findings[key] = Finding(
                    source=source,
                    url=url,
                    category=best_cat,
                    severity=best_sev,
                    matched_keyword=kw,
                    context=ctx,
                    indicator=best_label,
                )

    return list(findings.values())
