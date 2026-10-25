# Usage report

## Runtime configuration

- Python: 3.13.1 (`c:/python313/python.exe`)
- Provider: local Ollama HTTP API (`http://localhost:11434`)
- Model: `llama3.2:3b`
- Generation endpoint: `/api/generate`, JSON response mode, temperature 0, bounded output (`num_predict=96`)
- Final run: two workers, maximum two generations per reviewed case, 45-second request timeout, zero automatic retries
- Configuration variables: `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `OLLAMA_WORKERS`, `OLLAMA_MAX_ITERATIONS`, `OLLAMA_TIMEOUT`, and `OLLAMA_RETRIES`

## Final full-dataset usage

Command: `c:/python313/python.exe -u code/main.py`

- 518 requests processed in 817.2 seconds.
- 117 Ollama generations: one startup diagnostic and 116 case generations. The one extra generation was used only when a first response requested a follow-up or required bounded recovery.
- 1,255 registered tool actions executed against local participant data.
- Input/output token counts: unavailable. The standard-library client records prompt and response characters, but Ollama did not return token counts in the configured response payload; no token values are fabricated here.
- Estimated cost: `$0.00` because the model and data stayed local and no paid API was used.
- No external investigation service, API key, or participant-data upload was used.

## How to run

```powershell
ollama serve
ollama pull llama3.2:3b
c:/python313/python.exe -u code/main.py
c:/python313/python.exe -m unittest discover -s code -p 'test_*.py' -v
c:/python313/python.exe -u code/main.py --offline
```

The live command checks `/api/tags` and performs a timed diagnostic before processing cases. It prints startup settings, case progress, throughput, estimated remaining time, and failures. A failed model, tool, or investigation leaves the existing root `output.csv` unchanged. `--offline` is an explicit deterministic validation mode and is not selected automatically after a live failure.

## Agent responsibilities

The model selects or confirms investigation actions and proposes a structured conclusion. Python owns CSV/schema validation, registered-tool argument validation, evidence retrieval, audit cutoffs, policy rules, evidence provenance, step ordering, status safeguards, and atomic output writing. The model never receives unrestricted filesystem or code execution access.
