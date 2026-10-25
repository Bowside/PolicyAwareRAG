"""Streamlit browser for inspecting saved performance-evaluation records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pandas as pd
import streamlit as st


RESULTS_PATH = Path(__file__).resolve().parent / "evaluation_results_2026-09-30T16-49-55Z.json"


@st.cache_data
def load_results() -> list[dict[str, Any]]:
    """Load valid evaluation records from the configured results file.

    Returns:
        Evaluation records whose values are dictionaries.
    """
    with RESULTS_PATH.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    results = payload.get("results", [])
    return [result for result in results if isinstance(result, dict)]


def first_value(value: Any, fallback: str = "-") -> str:
    """Convert a value to display text, using a fallback for empty values.

    Args:
        value: Value to convert.
        fallback: Text to use when ``value`` is empty or ``None``.

    Returns:
        Display-ready text.
    """
    if value is None or value == "":
        return fallback
    return str(value)


def result_label(result: dict[str, Any]) -> str:
    """Build the selector label for one evaluation record.

    Args:
        result: Evaluation record containing case and correlation metadata.

    Returns:
        A label combining the case type and correlation ID.
    """
    correlation_id = first_value(result.get("correlationId"))
    case_type = first_value(result.get("case_type"), "unknown case")
    return f"{case_type} | {correlation_id}"


def render_metric_summary(results: list[dict[str, Any]]) -> None:
    """Render aggregate counts and latency metrics for evaluation records.

    Args:
        results: Evaluation records to summarize.

    Returns:
        None.
    """
    passed = sum(bool(result.get("passed")) for result in results)
    allowed = sum(result.get("actual_outcome") == "allow" for result in results)
    average_latency = sum(float(result.get("http_latency_ms") or 0) for result in results) / len(results)
    unique_ids = len({result.get("correlationId") for result in results if result.get("correlationId")})

    columns = st.columns(4)
    columns[0].metric("Records", len(results))
    columns[1].metric("Unique correlation IDs", unique_ids)
    columns[2].metric("Passed", f"{passed} / {len(results)}")
    columns[3].metric("Average latency", f"{average_latency:,.0f} ms")
    st.caption(f"Allowed outcomes: {allowed} of {len(results)}")


def render_record(result: dict[str, Any]) -> None:
    """Render the detailed survey view for one evaluation record.

    Args:
        result: Evaluation record to display.

    Returns:
        None.
    """
    st.subheader(first_value(result.get("case_type"), "Evaluation record"))
    st.code(first_value(result.get("correlationId")), language=None)

    columns = st.columns(4)
    columns[0].metric("Outcome", first_value(result.get("actual_outcome")))
    columns[1].metric("Passed", "Yes" if result.get("passed") else "No")
    columns[2].metric("HTTP status", first_value(result.get("status_code")))
    columns[3].metric("Latency", f"{float(result.get('http_latency_ms') or 0):,.0f} ms")

    st.markdown("**Survey prompt**")
    st.write(first_value(result.get("question"), "No question recorded."))

    answer_columns = st.columns(2)
    with answer_columns[0]:
        st.markdown("**Response answer**")
        st.write(first_value(result.get("response", {}).get("answer"), "No answer recorded."))
    with answer_columns[1]:
        st.markdown("**Reference answer**")
        st.write(first_value(result.get("reference_answer"), "No reference answer recorded."))

    request = result.get("request_payload") or {}
    response = result.get("response") or {}
    with st.expander("Request and response details"):
        st.json({"request": request, "response": response})

    sources = result.get("evaluation_contexts") or []
    with st.expander(f"Evidence and sources ({len(sources)} context items)"):
        st.write("Source IDs:", ", ".join(str(source) for source in result.get("response", {}).get("sources", [])) or "None")
        if sources:
            for index, context in enumerate(sources, start=1):
                st.markdown(f"**Context {index}**")
                st.write(context)
        else:
            st.info("No retrieved evaluation context was recorded.")

    steps = result.get("step_metrics") or []
    with st.expander(f"Pipeline steps ({len(steps)})"):
        if steps:
            step_rows = [
                {
                    "Step": step.get("stepName"),
                    "Status": step.get("executionStatus"),
                    "Latency (ms)": step.get("latency_ms"),
                    "Documents": step.get("document_count"),
                    "Reason": step.get("reason"),
                }
                for step in steps
            ]
            st.dataframe(pd.DataFrame(step_rows), width="stretch", hide_index=True)
        else:
            st.info("No pipeline step metrics were recorded.")


st.set_page_config(page_title="Evaluation survey", page_icon=":mag:", layout="wide")
st.title("Evaluation survey")
st.caption("Browse one evaluation record at a time and share a stable correlation-ID link.")

try:
    all_results: list[dict[str, Any]] = load_results()
except (OSError, json.JSONDecodeError, KeyError) as error:
    st.error(f"Could not load {RESULTS_PATH.name}: {error}")
    st.stop()

if not all_results:
    st.warning("The results file contains no evaluation records.")
    st.stop()

render_metric_summary(all_results)

correlation_ids = sorted({str(result.get("correlationId")) for result in all_results if result.get("correlationId")})
query_value = st.query_params.get("correlationId", "")
if isinstance(query_value, list):
    query_value = query_value[0] if query_value else ""
query_value = str(query_value)

with st.sidebar:
    st.header("Survey filter")
    selected_id = st.selectbox(
        "Correlation ID",
        options=["All records", *correlation_ids],
        index=(correlation_ids.index(query_value) + 1 if query_value in correlation_ids else 0),
    )
    if selected_id != "All records":
        share_url = f"?correlationId={quote(selected_id)}"
        st.markdown("**Shareable survey URL**")
        st.code(share_url, language=None)
        st.link_button("Open filtered record", share_url)
    st.divider()
    st.caption(f"Data file: {RESULTS_PATH.name}")

filtered_results = (
    all_results
    if selected_id == "All records"
    else [result for result in all_results if str(result.get("correlationId")) == selected_id]
)

st.write(f"Showing **{len(filtered_results)}** record(s)")
if len(filtered_results) > 1:
    selected_label = st.selectbox("Choose a record", options=filtered_results, format_func=result_label)
else:
    selected_label = filtered_results[0]

st.divider()
render_record(selected_label)