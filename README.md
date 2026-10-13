# PhishBrief AI 🛡️

**Local-first phishing triage for small businesses.** Turn suspicious emails, SMS messages, chat messages, and payment requests into an evidence-led brief with a risk rating, plain-English explanations, and safe next steps.

> The screen gives you the warning signs. You make the security decision.

## Why this exists

Small teams often receive suspicious messages but do not have a dedicated security operations team to triage them. PhishBrief AI gives them a lightweight first-pass analysis without requiring a paid hosted AI API.

## What works in this MVP

- Paste a message and analyze it with a local model through [Ollama](https://ollama.com/).
- Risk level and 0–100 triage score.
- Evidence-led indicators, explanations, and safe next steps.
- JSON export of the analysis brief.
- Optional, explicitly labelled rule-based demo preview for UI walkthroughs.
- Input length limit and schema validation for model output.
- No account, cloud AI API, or default persistent message history.

## Run locally

### 1. Requirements

- Python 3.10+
- [Ollama](https://ollama.com/) installed and running
- A local chat-capable model available in Ollama

### 2. Install a model

The default model is `granite3.2-vision`, suitable if you already have it installed. Otherwise, choose any chat-capable model supported by your machine.

```bash
ollama pull granite3.2-vision
```

If Ollama is already running as a desktop service, you usually do not need to run `ollama serve` separately.

### 3. Install and launch

**Windows PowerShell** (use `python` or `py` depending on your installation):

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation, run the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

**macOS/Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit, usually `http://localhost:8501`.

### Optional configuration

```powershell
$env:OLLAMA_BASE_URL = "http://127.0.0.1:11434"
$env:OLLAMA_MODEL = "granite3.2-vision"
```

Set these before launching Streamlit. The model name must match a model installed in Ollama.

## Demo without AI

Open the sidebar and enable **Use demo preview (no AI)**. This mode uses simple keyword patterns for a UI walkthrough and is clearly labelled as non-AI. It is not the main analysis mode and must not be presented as an AI result.

## Tests

```bash
python -m pytest -q
```

## Privacy and security boundaries

- In AI mode, message text is sent to the configured **local Ollama endpoint**. This project does not call a hosted AI API by design.
- Do not configure the endpoint to a server you do not control if the message contains confidential information.
- The app does not fetch links, open attachments, inspect mail headers, query threat-intelligence feeds, or prove whether a message is malicious.
- Model outputs can be wrong. A low score does not prove safety; a high score is a triage signal, not a verdict.
- Avoid pasting sensitive customer data into public demos.
- Only analyze messages you are authorized to handle.

## Who might pay for this?

Small agencies, freelancers, and small businesses that need a simple first-pass message triage tool. Possible future paid offerings include managed private deployment, team policy packs, batch triage, and audit-friendly exports. These are roadmap ideas, not features currently delivered.

## Roadmap

- [x] Local model integration through Ollama
- [x] Evidence-led JSON result schema
- [x] Rule-based demo preview, clearly separated from AI analysis
- [x] JSON export
- [x] Unit tests for validation and demo behavior
- [ ] Sender/header analysis from uploaded `.eml` files
- [ ] Batch triage for small IT teams
- [ ] Optional redacted case history with explicit user consent
- [ ] User testing with a small business and feedback-driven iteration

## Open innovation

A local open-weight model gives teams control over model choice and helps keep message contents on their own machine. It avoids a per-message hosted AI bill and reduces dependency on a single closed AI provider. The trade-offs are local setup, hardware limits, and model quality differences.

## Prize categories

Do not list partner prize categories unless the submitted version genuinely uses that partner's technology. This MVP uses Ollama; it does not claim Gemma, Render, DigitalOcean, or other partner integrations by default.

## Disclaimer

PhishBrief AI is an assistive triage tool, not a malware scanner, URL reputation service, legal/compliance certification, or substitute for a qualified security review.

## License

MIT. See [LICENSE](LICENSE).
