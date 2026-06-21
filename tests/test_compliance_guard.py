from compliance_guard import compliance_guard, scan_for_verbatim_pii


def test_scan_for_verbatim_pii_detects_email_and_verbatim_leak():
    chunks = [
        {"id": "chunk-1", "content": "This is a long retrieved chunk with enough length to trigger leakage detection."}
    ]
    text = "Contact person@example.com. This is a long retrieved chunk with enough length to trigger leakage detection."

    contains_pii, findings = scan_for_verbatim_pii(text, chunks)

    assert contains_pii is True
    assert any(finding.startswith("email:") for finding in findings)
    assert any(finding.startswith("verbatim_leak:") for finding in findings)


def test_compliance_guard_passes_without_pii():
    result = compliance_guard("No sensitive content here.", [{"id": "chunk-2", "content": "short text"}])

    assert result["status"] == "Pass"
    assert result["action"] == "Release"
    assert result["findings"] == []
