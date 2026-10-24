# Evaluation survey app

Run this read-only Streamlit browser from the repository root:

```powershell
python -m pip install -r tests/performance_evaluation/survey_app/requirements.txt
streamlit run tests/performance_evaluation/survey_app/app.py
```

The selected record is encoded in the URL query string as
`?correlationId=<id>`, making links suitable for sharing from a survey form.