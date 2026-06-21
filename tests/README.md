# Tests

This folder contains unit tests for the policy validator, compliance guard, graph logic, and the Azure Functions HTTP starter.

Run the tests from the repository root after installing the dependencies:

```powershell
pytest
```

The `test_function_app.py` module uses lightweight local stubs so it can validate the starter route without connecting to Azure.