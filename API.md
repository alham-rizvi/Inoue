# Inoue API

The optional API surface is available when the FastAPI dependencies are installed.

## Health check

```bash
curl http://localhost:8000/health
```

## List signature names

```bash
curl http://localhost:8000/signatures
```

## Single scan

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://example.com","modules":["headers","tech"]}'
```

## Batch scan

```bash
curl -X POST http://localhost:8000/scan/batch \
  -H 'Content-Type: application/json' \
  -d '{"targets":["https://example.com","https://example.org"],"workers":2}'
```

Set `INOUE_API_KEY` and send the `X-API-Key` header when the API is configured to require authentication.
