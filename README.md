# PolicyAwareRAG

A Python Azure Functions app for Enron email retrieval using LangChain, LangGraph, Cosmos DB vector search, and Microsoft Foundry models.

## Features

- Azure Functions Python programming model
- LangChain + LangGraph orchestration
- Microsoft Foundry OpenAI-compatible chat and embeddings
- GPT-4o-mini as the default reasoning model
- Cosmos DB vector search against the Enron email corpus
- HTTP endpoint for Q&A over the Enron dataset

## Project structure

- `function_app.py` - Azure Function entry point
- `app/rag_chain.py` - LangGraph RAG graph and document ingestion logic
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

## Notes

The retrieval logic is designed to query the live Enron email vector store in Cosmos DB using the configured embedding model and the Foundry GPT-4o-mini chat model.
