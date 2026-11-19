# Reporting and AI

[← Documentation index](README.md)

This page covers the *Threat Intel Findings* report builder and the optional AI features. How the AI features
work in detail, and what they send to a model, is explained in [AI processing](how-it-works/ai.md).

## Reporting

The report builder produces a **Threat Intel Findings** document for any period, as PDF, Word, Markdown or CSV.

The report opens with a summary of the period and then writes up the top findings: when each was published, its
severity, a description, the related malware, actors and CVEs, and a link to the original. It then lists the
leading malware families, with their type, the sources that covered them and an example hash, and closes with
the top indicators of compromise and their verdicts.

You can also add collection statistics, actors, CVEs, newly seen families and the latest AI executive summary,
and you can choose how many findings, families and indicators to include. Like the dashboards, the report counts
a story carried by several outlets once.

## AI (optional)

With an AI model configured, JATMP can:

- summarise and analyse individual items;
- write a threat brief about a family, actor or other entity;
- write a daily executive summary;
- answer questions about the collected data.

### Setting it up

Setting up the AI is a three-way choice between **Off**, **Local** and **Cloud**. You then pick a vendor, and a
model from the live list that the server or provider reports:

- **Local runtimes:** Ollama, LM Studio, llama.cpp, vLLM, Jan, or any OpenAI-compatible server.
- **Cloud providers:** Anthropic, OpenAI, OpenRouter, Groq, Gemini, Mistral, DeepSeek, xAI, Together, or any
  OpenAI-compatible API.

You can also choose the language the AI writes in. The model names in the presets were current when this version
was released; use **Load models** to see what your server or provider actually offers.

### Personal data

Item text can contain phone numbers, bank accounts and e-mail addresses. With a cloud model, JATMP replaces them
with placeholders (`[phone 1]`, `[account 1]` and so on) before a prompt is sent, so they never reach the
provider. The setting *Personal data in prompts* (Settings → AI) controls this: `cloud` (the default) redacts for
cloud models only, `always` redacts for every model, and `never` switches it off. See
[What leaves your network](how-it-works/ai.md#what-leaves-your-network).

### The executive summary

The executive summary appears on the dashboard card and behind the *AI summary* button, and older ones are kept
under *AI insights*. It is short on purpose: a one-sentence headline, an overall threat level (low, elevated,
high or critical), three or four key points, and up to three actions for today. It is based on the last 24 hours
of items plus the week's trending malware, actors, CVEs, scam types and sectors.

The model answers in JSON. JATMP checks the answer, removes any Markdown or maths notation, and displays it with
the same components as the rest of the interface. If the answer can't be used, the text is shown as it came.

The summary runs every day at 06:00 UTC by default. You can change the time and the time zone under Settings →
General; see [Daily schedule](configuration.md#daily-schedule).
