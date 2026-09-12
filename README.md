# PolicyAwareRAG

A Python Azure Functions app for Enron email retrieval using LangChain, LangGraph, Cosmos DB vector search, and Microsoft Foundry models.

## Features

- Azure Functions Python programming model
- LangChain + LangGraph orchestration
- Microsoft Foundry OpenAI-compatible chat and embeddings
- GPT-4o-mini as the default reasoning model
- Cosmos DB vector search against the Enron email corpus
- HTTP endpoint for Q&A over the Enron dataset
- Evidence-grounded answers with source-labeled context and policy guardrails
- Evaluation tooling for latency, token usage, retrieval context, and RAGAS quality metrics

## Project structure

- `function_app.py` - Azure Function entry point
- `app/rag_chain.py` - LangGraph retrieval, reranking, evidence formatting, and answer generation
- `tests/performance_evaluation/` - Evaluation harness, analysis notebook, and publication-ready figures
- `host.json` - Azure Functions host configuration
- `requirements.txt` - Python dependencies
- `local.settings.sample.json` - local settings template

## Local setup

1. Create and activate a virtual environment.
2. Install dependencies:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Copy `local.settings.sample.json` to `local.settings.json` and fill in your Microsoft Foundry values.
4. Start the function app:

   ```bash
   func start
   ```

5. Send a request to the HTTP route:

   ```bash
   curl -X POST http://localhost:7071/api/rag \
     -H "Content-Type: application/json" \
     -d '{"question":"Who was involved in the California energy trading discussions?"}'
   ```

## Environment variables

- `FOUNDRY_API_KEY`
- `FOUNDRY_ENDPOINT` (for example: `https://<resource>.services.ai.azure.com/models` or the compatible OpenAI-style Foundry endpoint for your project)
- `FOUNDRY_CHAT_MODEL` (set to `gpt-4o-mini`)
- `FOUNDRY_EMBEDDING_MODEL` (for example: `text-embedding-3-small`)
- `COSMOSDB_ENDPOINT`
- `COSMOSDB_KEY`
- `COSMOSDB_DATABASE`
- `COSMOSDB_COLLECTION` (set to `EnronEmailVectorStore`)
- `EMBEDDING_MODEL` (set to `all-MiniLM-L6-v2`)
- `ENABLE_EVALUATION_DETAILS` (set to `true` only for controlled evaluation runs that need the pre-guardrail answer)

## Notes

The retrieval logic is designed to query the live Enron email vector store in Cosmos DB using the configured embedding model and the Foundry GPT-4o-mini chat model.

Retrieved candidates are policy-filtered, reranked using query-term overlap, and bounded before answer generation. The answer prompt requires claims to be supported by source-labeled evidence and to cite source IDs. Normal API responses expose the final guarded answer only; pre-guardrail answers are returned only when `ENABLE_EVALUATION_DETAILS=true` and the request explicitly asks for evaluation details.

For evaluation setup, result interpretation, RAGAS metrics, token-stage reporting, and chart exports, see [tests/performance_evaluation/README.md](tests/performance_evaluation/README.md).
