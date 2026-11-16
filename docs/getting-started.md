# Getting started

[← Documentation index](README.md)

Requirements: Python 3.11 or newer, or Docker. JATMP needs no external database and loads nothing from a CDN, so it also runs on an isolated network (collection itself of course needs Internet access).

## Install from source

```bash
python -m venv .venv
```
```bash
.venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
```
```bash
pip install -r requirements.txt
```
```bash
python install.py             # interactive: single / multi user, API keys, LLM
```
```bash
python run.py                 # open http://127.0.0.1:8000
```

The installer can be skipped: on first launch the web UI shows the same setup wizard. For an unattended
install use `python install.py --mode multi --admin admin --password 'StrongPassw0rd'`.

> The web wizard requires no login because no users exist yet. Run the first install on `127.0.0.1` (the
> default) before exposing the port to a network.

## Docker

```bash
cp .env.example .env
```
```bash
docker compose up -d --build
```

The container exposes `/healthz` and ships a `HEALTHCHECK`. To run a local LLM alongside it, start
`docker compose --profile llm up -d`, pull a model with `docker compose exec ollama ollama pull llama3.1` and
set the base URL to `http://ollama:11434` under Settings → AI → Advanced.

Next: [Configuration](configuration.md) for API keys and options, [Sources](sources.md) for what is collected.
