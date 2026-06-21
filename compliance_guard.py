import re
from typing import Tuple, List, Dict

PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\+?\d[\d\-\s]{7,}\d"),
}

def scan_for_verbatim_pii(generated_text: str, retrieved_chunks: List[Dict]) -> Tuple[bool, List[str]]:
    """Detect direct PII matches and verbatim leakage from retrieved chunks.

    Args:
        generated_text: The generated response text to inspect.
        retrieved_chunks: Retrieved chunks used as the source context.

    Returns:
        A tuple containing a boolean flag and a list of findings.
    """
    findings = []
    for name, pat in PII_PATTERNS.items():
        for m in pat.findall(generated_text):
            findings.append(f"{name}:{m}")

    for c in retrieved_chunks:
        content = c.get("content", "")
        if len(content) > 50 and content in generated_text:
            findings.append(f"verbatim_leak:{c.get('id')}")
    return (len(findings) > 0, findings)

def compliance_guard(generated_text: str, retrieved_chunks: List[Dict]) -> Dict:
    """Apply the compliance policy to the generated response.

    Args:
        generated_text: The response text to validate.
        retrieved_chunks: Retrieved chunks used to check for leakage.

    Returns:
        A status dictionary with the enforcement action and any findings.
    """
    contains_pii, findings = scan_for_verbatim_pii(generated_text, retrieved_chunks)
    status = "Fail" if contains_pii else "Pass"
    action = "Block" if contains_pii else "Release"
    return {"status": status, "action": action, "findings": findings}
