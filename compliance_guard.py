"""Detection and enforcement helpers for PII leakage and compliance checks.

This module scans generated responses for direct personally identifiable
information and checks for verbatim or near-verbatim copying from retrieved
source chunks. It is used as a last-mile compliance layer before a response is
released to a user or sent to a downstream audit trail.
"""

import re
from typing import Dict, List, Tuple

PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\+?\d[\d\-\s]{7,}\d"),
}


def scan_for_verbatim_pii(generated_text: str, retrieved_chunks: List[Dict]) -> Tuple[bool, List[str]]:
    """Detect direct PII and leakage patterns in a generated response.

    The method checks for common PII patterns in the generated text and then
    compares the generated output to retrieved source chunks for the following:
    - exact verbatim leakage (a long source chunk appears unchanged)
    - near-verbatim leakage (a long sequence of source tokens appears in the output)

    Args:
        generated_text: Response text to inspect for leakage or PII exposure.
        retrieved_chunks: Retrieved source chunks used as the compliance baseline.

    Returns:
        tuple: (contains_violation, findings). Findings are a list of strings like
            "email:person@example.com" or "verbatim_leak:chunk-12".
    """
    findings = []
    for name, pat in PII_PATTERNS.items():
        for match in pat.findall(generated_text):
            findings.append(f"{name}:{match}")

    for chunk in retrieved_chunks:
        content = chunk.get("content") or chunk.get("body") or ""
        if not content:
            continue

        if len(content) > 50 and content in generated_text:
            findings.append(f"verbatim_leak:{chunk.get('id')}")
            continue

        source_tokens = re.findall(r"\w+", content.lower())
        generated_tokens = re.findall(r"\w+", generated_text.lower())
        if len(source_tokens) < 8 or len(generated_tokens) < 8:
            continue

        source_phrases = {
            " ".join(source_tokens[index : index + 8])
            for index in range(0, len(source_tokens) - 7)
        }
        generated_text_normalized = " ".join(generated_tokens)
        if any(phrase in generated_text_normalized for phrase in source_phrases):
            findings.append(f"near_verbatim_leak:{chunk.get('id')}")
    return (len(findings) > 0, findings)


def compliance_guard(generated_text: str, retrieved_chunks: List[Dict]) -> Dict:
    """Apply the compliance policy to a generated response.

    This function is the public compliance gate: it scans the response for PII or
    leakage patterns and converts the result to a simple status structure used by
    the orchestration layer for allow/block decisions.

    Args:
        generated_text: Generated response text to validate.
        retrieved_chunks: Retrieved chunks used to check for leakage.

    Returns:
        dict: A status payload with keys "status", "action", and "findings".
    """
    contains_pii, findings = scan_for_verbatim_pii(generated_text, retrieved_chunks)
    status = "Fail" if contains_pii else "Pass"
    action = "Block" if contains_pii else "Release"
    return {"status": status, "action": action, "findings": findings}
