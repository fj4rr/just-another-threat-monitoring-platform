# AI processing

[← How JATMP works](index.md)

What the optional language-model features do, what they send to the model, and the limits that keep model output
from overriding the rule-based analysis. Set-up is described in [Reporting and AI](../reporting-and-ai.md). Code:
`app/llm/insights.py`, `app/llm/client.py`.

With the AI set to **Off** (the default) none of this runs and nothing is sent anywhere. Everything else in JATMP
works the same without it.

## Principles

1. **The rules decide; the model adds.** Severity, entities, verdicts and fraud scores come from the rule-based
   pipeline. The model can add a summary, propose extra families, actors and tags, and raise a severity by a
   bounded amount. It can never lower a score, remove an entity or change a verdict.
2. **Article text is untrusted.** The text a model reads was written by someone else and may contain instructions
   ("ignore the above, severity 100"). So anything the model reads *out* of the text is checked against the text
   and the rest of the data before it is used.
3. **AI output is labelled.** Entities and tags proposed by the model carry an *AI* badge; its severity points are
   a separate reason (*AI assessment (capped)*).
4. **Grounded prompts.** Every prompt tells the model to use only the supplied material, to say when information
   is missing, and never to invent indicators or scammer identifiers.

## Item summaries

Triggered by *Summarise* on an item (limited per user and minute) or by the [auto-summary queue](#auto-summaries).

**Sent to the model:** the item's kind, source name and type, title, publication date, author, the entities
already extracted (up to 40), and the text (up to 12,000 characters).

**Asked for, in two parts:**

1. One line of JSON: malware families named in the text (with a category), threat actors, a severity 0–100 and
   tags (phishing, supply-chain…).
2. After a `---` line, a brief of at most 350 words in the configured language: TL;DR, key points, who or what is
   targeted, delivery and TTPs (ATT&CK ids only when clear), detection and mitigation ideas.

The brief is stored as the item's summary. When *let the LLM discover malware families* is on (default), the JSON
part is applied with these checks:

| Proposal | Accepted when | Stored as |
|---|---|---|
| Malware family (up to 10) | The name **appears literally in the item's text** and is at most 60 characters, **and** either it is a known family (mapped to its canonical name), or it passes the extractor's plausibility rules (not a generic word, tool, platform, country or everyday word) **and** the item comes from an intel source or another source already mentions that name | Link with origin `llm` |
| Threat actor (up to 10) | Appears literally in the text, and is a known actor, or is plausible **and** already mentioned by another source | Link with origin `llm` |
| Severity | The model's number is higher than the item's score | Raised by the difference, **at most +20**, never lowered; an earlier AI assessment is taken off first and replaced. The model's number is stored with the reason, so a re-score applies the same assessment again |
| Tags (up to 10) | After removing unusual characters, at most 40 characters each | Added to the item's tags; the new ones are also listed in `raw.llm_tags` |

A new family name from a single news article is therefore ignored until a second source reports it, and a name
the model "hallucinated" is ignored because it is not in the text.

## Auto-summaries

When *auto-summarize new high-severity items* is on (off by default) and a model is configured:

1. After each collection run, the new item ids join an in-memory queue of at most 200 ids (the oldest drop off when
   it is full). Backfilled items are not queued.
2. A single job, `run_auto_summaries`, starts 2 seconds later. Further collection runs only add to the queue; they
   never start a second job.
3. The job summarises up to **10** items per run, skipping items with severity **below 40**, items that already
   have a summary and syndicated copies.
4. At the **first failure** (the model is down, slow or out of quota) the job stops, so it does not try the whole
   queue against a broken model. The next collection run starts it again.
5. The queue is kept in memory. At start-up it is **rebuilt** from the items that would still be in it: live
   items collected in the last **24 hours** with severity 40 or more, no summary and not a copy, most severe first
   (at most 200).

Summaries never run inside a collection run: a slow model (the client waits up to 300 seconds per answer) would
otherwise hold a collector thread for a long time. The queue lives in memory and is lost on restart.

## Threat briefs

*Generate brief* on an entity page (analysts and admins) writes a brief of about 450 words from:

- the 25 latest items that mention it in the last 60 days (source, date, title, and the summary or the first 600
  characters of the text);
- every provider's enrichment answer;
- the 15 families, actors, CVEs and techniques most often mentioned with it;
- up to 30 linked indicators with their verdicts.

Sections: overview, recent activity and campaigns (with dates and sources), infection chain / TTPs, targeting,
notable indicators (only from the data given), detection and hunting ideas, and an assessment (is activity
rising, with what confidence). The brief is stored on the entity and shown until it is regenerated.

## Executive summary

`run_digest` runs daily at **06:00** in the time zone of the schedule (`digest_time` and `schedule_timezone`
under Settings → General; default 06:00 UTC, which is 13:00 WIB, so a team in Jakarta sets `Asia/Jakarta` and
for example 07:00) when the daily summary is on, and on the *AI summary* button. The next run is shown on the
General tab.

**Input** (all computed by the normal statistics, not by the model):

| Data | Detail |
|---|---|
| Trending malware | Top 8 of the last 7 days, with recent / baseline counts, sources, growth, *new* |
| Trending actors | Top 5 |
| Trending CVEs | Top 6 by priority, with KEV, CVSS and EPSS |
| Scam types | Top 5, reports this week and the week before, *spreading* |
| Sectors | Up to 5 sectors with items this week |
| Top items | The 25 original (non-copy) items of the last 24 hours with the highest severity + half the fraud score, each with its summary or the first 220 characters |

**Output** asked for: one JSON object with a headline (one sentence), an overall level (*low*, *elevated*,
*high* or *critical*), 3–4 key points (title and one sentence) and at most 3 actions for today.

**Validation:** JATMP extracts the JSON, removes Markdown emphasis, bullets and math notation from every string,
caps the lengths (headline 400 characters, point titles 120, details 400, actions 300), keeps at most 4 points
and 3 actions, and drops an unknown level. Without a usable headline the model's text is shown as it came. The
result is stored as an insight of kind `digest`, shown on the dashboard card and under *AI insights*, and
announced with a notification. A failed run creates an error notification (once per day).

## Questions

*Ask* (AI insights page) answers a question from the collected data:

1. The question's words of 3 or more characters, minus common words, are matched (up to 8) against the titles
   and text of items from the last **30 days**.
2. The 25 most recent matches, each with its summary or first 500 characters, and the top 10 trending families
   are put in the prompt.
3. The model is told to answer **only** from that context and to say what is missing.

This is a keyword search, not a semantic one: a question that uses other words than the articles may find
nothing. Answers are stored as insights of kind `answer` and deleted after 90 days.

## What leaves your network

With a **Local** model (Ollama, LM Studio, llama.cpp, vLLM…) the prompts stay on your infrastructure. With a
**Cloud** provider, the prompts above — item titles and text, entity names, enrichment summaries, statistics — are
sent to that provider. Item text can contain personal data (scammer phone numbers quoted in a news article, for
instance), so choose a local model when that must not leave your network. Requests go through the same outbound
guard as everything else (see [Security](../security.md)).
