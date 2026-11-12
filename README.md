# AndroAI Dashboard

Real-time web dashboard for the AndroAI Android malware analysis pipeline.

## Setup

```bash
cd /path/to/host_androai_page
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
# Development (auto-reload)
python app.py

# Production
gunicorn -w 2 -b 0.0.0.0:8080 app:app
```

## Configuration

Set the path to the AndroAI databases via environment variables:

```bash
export ANDROAI_DIR=/home/user/workspace/androAiV2/llm_V1
# Or individually:
export LEDGER_DB=/path/to/androai_ledger.sqlite
export YARA_REG_DB=/path/to/yara_rule_registry.sqlite
```

Default: looks for `../old_llm_with_custom_agent_editor/llm_V1/generated_rules/`.

## Features

- **Live auto-refresh** every 30 seconds
- **Hero stats**: total samples, verdicts, signatures created
- **Timeline chart**: daily analysis volume by verdict
- **Pipeline breakdown**: which source produced what
- **Recent analyses table**: latest samples with verdict, risk, YARA info
- **Signature browser**: all YARA rules with state (draft/approved/rejected), filter by status
- **Rule viewer**: click any signature to see the full YARA rule text
- **Pipeline source tracking**: manual, vt_downloader, smba_runner, crawler, etc.

## Adding new pipelines

Any pipeline that calls AndroAI just needs to pass `--pipeline-source <name>`:

```bash
python modified_trial8_multiple_models.py /apks --pipeline-source vt_downloader
python modified_trial8_multiple_models.py /apks --pipeline-source smba_runner
python modified_trial8_multiple_models.py /apks --pipeline-source crawler
```

The dashboard automatically picks up the new source in the pipeline breakdown.
