# Getting started

[← Documentation index](README.md)

You can run JATMP from source with Python 3.11 or newer, or with Docker. It doesn't need an external database
and loads nothing from a CDN, so it also runs on an isolated network. (Collecting sources does, of course, need
Internet access.)

## Install from source

Create a virtual environment and activate it:

```bash
python -m venv .venv
```
```bash
.venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

Run the installer. It asks whether you want single-user or multi-user mode, and for any API keys and AI settings:

```bash
python install.py
```

Then start JATMP and open http://127.0.0.1:8000:

```bash
python run.py
```

You can also skip the installer: on first launch, the web interface shows the same setup wizard. For an
unattended install, pass everything on the command line, for example
`python install.py --mode multi --admin admin --password 'StrongPassw0rd'`.

> The web wizard doesn't ask for a login, because no users exist yet. Run the first install on `127.0.0.1` (the
> default) before you expose the port to a network. If you open the wizard from another machine, it asks for a
> one-time setup token, which you will find in the log and in `data/setup-token`.

## Docker

Copy the example environment file and start the containers:

```bash
cp .env.example .env
```
```bash
docker compose up -d --build
```

The container exposes `/healthz` and has a built-in `HEALTHCHECK`.

To run a local AI model next to it, start the `llm` profile and pull a model:

```bash
docker compose --profile llm up -d
```
```bash
docker compose exec ollama ollama pull llama3.1
```

Then set the base URL to `http://ollama:11434` under Settings → AI → Advanced.

## Next steps

- [Configuration](configuration.md) explains API keys, options and the daily schedule.
- [Sources](sources.md) lists what JATMP collects out of the box.
- [How JATMP works](how-it-works/index.md) explains what happens to the data once it arrives.
