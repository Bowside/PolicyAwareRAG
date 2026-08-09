from compliance_guard import compliance_guard, scan_for_verbatim_pii


def test_scan_for_verbatim_pii_detects_email_and_verbatim_leak():
    """Verify the guard detects PII and verbatim leakage."""
    chunks = [
        {"id": "chunk-1", "content": "This is a long retrieved chunk with enough length to trigger leakage detection."}
    ]
    text = "Contact person@example.com. This is a long retrieved chunk with enough length to trigger leakage detection."

    contains_pii, findings = scan_for_verbatim_pii(text, chunks)

    assert contains_pii is True
    assert any(finding.startswith("email:") for finding in findings)
    assert any(finding.startswith("verbatim_leak:") for finding in findings)


def test_compliance_guard_passes_without_pii():
    """Verify the guard passes safe output unchanged."""
    result = compliance_guard("No sensitive content here.", [{"id": "chunk-2", "content": "short text"}])

    assert result["status"] == "Pass"
    assert result["action"] == "Release"
    assert result["findings"] == []


def test_compliance_guard_detects_body_field_and_near_verbatim_overlap():
    """Verify the guard inspects body text and catches near-verbatim reuse."""
    retrieved_chunks = [
        {
            "id": "chunk-3",
            "body": "The approved review includes a confidential project timeline and customer identifiers that should not be repeated verbatim.",
        }
    ]
    generated_text = "The approved review includes a confidential project timeline and customer identifiers in the response."

    result = compliance_guard(generated_text, retrieved_chunks)

    assert result["status"] == "Fail"
    assert any(
        finding.startswith("near_verbatim_leak:") or finding.startswith("verbatim_leak:")
        for finding in result["findings"]
    )
