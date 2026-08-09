# Unit Tests

This folder contains unit tests for the policy validator, compliance guard, graph logic, and the Azure Functions HTTP starter.

Run the tests from the repository root after installing the dependencies:

```powershell
pytest
```

The test modules use lightweight local stubs so they can validate behaviour without connecting to Azure.
