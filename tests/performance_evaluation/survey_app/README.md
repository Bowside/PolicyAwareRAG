# Evaluation survey app

This is a read-only Streamlit browser for the checked-in evaluation result file
`evaluation_results_2026-09-30T16-49-55Z.json`. It displays aggregate pass and
latency metrics, one selected record, the request and response, reference and
retrieved context, and recorded pipeline-step metrics.

Run it from the repository root:

```powershell
python -m pip install -r tests/performance_evaluation/survey_app/requirements.txt
streamlit run tests/performance_evaluation/survey_app/app.py
```

The selected record is encoded in the URL query string as
`?correlationId=<id>`, making links suitable for sharing from a survey form.
Without that parameter, the app shows all records and allows a record to be
selected from the sidebar or record selector. The result JSON must remain next
to `app.py`; changing the dataset requires updating the `RESULTS_PATH` constant
in the app.