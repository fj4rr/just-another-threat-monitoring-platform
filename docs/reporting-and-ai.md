# Reporting and AI

[← Documentation index](README.md)

The *Threat Intel Findings* report builder and the optional LLM features.

## Reporting

The report builder produces a **Threat Intel Findings** document for any period, as PDF, Word, Markdown or CSV.
It opens with a summary of the period, writes up the top findings (published time, severity, description,
related malware, actors and CVEs, and a link to the original), lists the leading malware families with their
type, the sources that covered them and an example hash, and closes with the top indicators of compromise and
their verdicts. Collection statistics, actors, CVEs, newly seen families and the latest AI executive summary can be
appended. The number of findings, families and indicators is adjustable.

## AI (optional)

With an LLM configured, JATMP can summarise and analyse individual items, write a threat brief per family or
actor, write a daily executive summary (06:00 UTC by default; time and time zone under Settings → General) and answer questions over the collected data.

The **executive summary** (dashboard card, *AI summary* button, history under AI insights) is short on purpose: a
one-sentence headline, an overall threat level (low, elevated, high, critical), three or four key points and up to
three actions for today, over the last 24 hours of items plus the week's trending malware, actors, CVEs, scam types
and sectors. The model answers in JSON; JATMP checks it, strips any markdown or math notation, and renders it with
the same components as the rest of the interface. If the model returns something unusable, the text is shown as
it came. Set-up is a three-way
choice between **Off**, **Local** and **Cloud**, followed by a vendor and a model picked from the live list the
server or provider reports. Local runtimes: Ollama, LM Studio, llama.cpp, vLLM, Jan or any OpenAI-compatible
server. Cloud providers: Anthropic, OpenAI, OpenRouter, Groq, Gemini, Mistral, DeepSeek, xAI, Together or any
OpenAI-compatible API. The output language is configurable.

The model names offered in the AI presets were current when this version was written. Use **Load models**
to see what your server or provider actually offers.
