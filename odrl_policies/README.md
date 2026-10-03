# ODRL policies

This folder contains the JSON policy files loaded automatically by
`app/policy_guard.py`. There is no standalone command to run from this folder.

To use the policies locally, start the application from the repository root:

```powershell
func start
```

To exercise policy loading and authorization, run the policy tests from the
repository root:

```powershell
python -m pytest -q tests/unit_tests/test_policy_guard_odrl.py
```

Keep policy filenames in this folder with the `.json` extension. The loader
reads all such files in sorted filename order.