# Reporting and AI

[← Documentation index](README.md)

The *Threat Intel Findings* report builder and the optional LLM features.

## Reporting

The report builder produces a **Threat Intel Findings** document for any period, as PDF, Word, Markdown or CSV.
It opens with a summary of the period, writes up the top findings (published time, severity, description,
related malware, actors and CVEs, and a link to the original), lists the leading malware families with their
type, the sources that covered them and an example hash, and closes with the top indicators of compromise and
their verdicts. Collection statistics, actors, CVEs, newly seen families and the latest AI digest can be
appended. The number of findings, families and indicators is adjustable.

## AI (optional)

With an LLM configured, JATMP can summarise and analyse individual items, write a threat brief per family or
actor, produce a daily digest at 06:00 UTC and answer questions over the collected data. Set-up is a three-way
choice between **Off**, **Local** and **Cloud**, followed by a vendor and a model picked from the live list the
server or provider reports. Local runtimes: Ollama, LM Studio, llama.cpp, vLLM, Jan or any OpenAI-compatible
server. Cloud providers: Anthropic, OpenAI, OpenRouter, Groq, Gemini, Mistral, DeepSeek, xAI, Together or any
OpenAI-compatible API. The output language is configurable.

The model names offered in the AI presets were current when this version was written. Use **Load models**
to see what your server or provider actually offers.
