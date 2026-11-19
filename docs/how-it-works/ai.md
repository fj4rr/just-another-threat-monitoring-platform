# AI processing

[← How JATMP works](index.md)

This page explains what the optional AI features do, what they send to the model, and the safeguards that stop a
model's output from overriding the rule-based analysis. Setting up a model is covered in
[Reporting and AI](../reporting-and-ai.md). The code is in `app/llm/insights.py`, `app/llm/client.py` and
`app/llm/redact.py`.

When the AI is set to **Off** (the default), none of this runs and nothing is sent anywhere. The rest of JATMP
works exactly the same without it.

## Principles

1. **The rules decide; the model adds.** Severity, entities, verdicts and fraud scores come from the rule-based
   pipeline. A model can write a summary, suggest extra families, actors and tags, and raise a severity by a
   limited amount. It can't push a score below what the rules gave it, remove an entity or change a verdict.
2. **Article text is untrusted.** Whatever a model reads was written by someone else, and it may contain
   instructions aimed at the model ("ignore the above, severity 100"). So everything the model extracts from the
   text is checked against the text and the rest of the data before JATMP uses it.
3. **AI output is labelled.** Entities and tags suggested by the model carry an *AI* badge, and its severity
   points appear as a separate reason (*AI assessment (capped)*).
4. **Prompts stick to the data.** Every prompt tells the model to use only the material it is given, to say when
   information is missing, and never to invent indicators or scammer identifiers.
5. **Personal data stays out of cloud prompts.** Phone numbers, bank accounts and similar details are replaced
   with placeholders before a prompt goes to a cloud model (see [What leaves your network](#what-leaves-your-network)).

## Item summaries

A summary is written when someone clicks *Summarise* on an item (limited per user and per minute), or by the
[auto-summary queue](#auto-summaries).

**What the model receives:** the item's kind, the source's name and type, the title, publication date and author,
the entities already extracted (up to 40), and the text (up to 12,000 characters).

**What it is asked for**, in two parts:

1. One line of JSON listing the malware families named in the text (with a category), the threat actors, a
   severity from 0 to 100, and tags such as phishing or supply-chain.
2. After a `---` line, a brief of no more than 350 words in the configured language: a TL;DR, key points, who or
   what is targeted, delivery and TTPs (with ATT&CK ids only where they are clear), and ideas for detection and
   mitigation.

The brief is saved as the item's summary. When *let the LLM discover malware families* is on (the default), the
JSON part is applied as well, after these checks:

| Suggestion | Accepted when | Stored as |
|---|---|---|
| Malware family (up to 10) | The name **appears word for word in the item's text** and is no longer than 60 characters, **and** either it is a known family (mapped to its official name), or it passes the extractor's plausibility checks (not a generic word, tool, platform, country or everyday word) **and** the item comes from an intel source or another source already mentions that name | A link with origin `llm` |
| Threat actor (up to 10) | It appears word for word in the text, and it is either a known actor, or plausible **and** already mentioned by another source | A link with origin `llm` |
| Severity | The model's number is higher than the rule-based score | Raised by the difference, **at most +20**. The model's number is stored with the reason, so a later re-score can apply the same assessment again |
| Tags (up to 10) | After unusual characters are removed, each is at most 40 characters | Added to the item's tags; new ones are also noted as AI tags |

When an item is analysed again, the previous AI assessment is taken off first and the new one replaces it. A
lower new assessment can therefore remove points, but the score never drops below what the rules gave it.

The result is that a new family name from a single news article is ignored until a second source reports it,
and a name the model made up is ignored because it isn't in the text.

## Auto-summaries

When *auto-summarize new high-severity items* is on (it is off by default) and a model is configured:

1. After each collection run, the new items join an in-memory queue of at most 200 ids (when it is full, the
   oldest drop off). Backfilled items are not queued.
2. A single job, `run_auto_summaries`, starts 2 seconds later. Further collection runs only add to the queue;
   they never start a second job.
3. The job summarises up to **10** items per run, skipping items with severity **below 40**, items that already
   have a summary, and syndicated copies.
4. As soon as one summary **fails** (the model is down, slow or out of quota), the job stops, so it doesn't run
   the whole queue against a broken model. The next collection run starts it again.
5. Because the queue lives in memory, it is **rebuilt at start-up** from the items that would still be in it:
   live items collected in the last **24 hours** with a severity of 40 or more, no summary yet, and not a copy,
   most severe first (up to 200).

Summaries never run inside a collection run. A slow model (JATMP waits up to 300 seconds for an answer) would
otherwise tie up a collector thread for a long time.

## Threat briefs

*Generate brief* on an entity's page (for analysts and admins) writes a brief of about 450 words, based on:

- the 25 most recent items that mention the entity in the last 60 days (source, date, title, and the summary or
  the first 600 characters of the text);
- every provider's enrichment answer;
- the 15 families, actors, CVEs and techniques most often mentioned with it;
- up to 30 linked indicators, with their verdicts.

The brief has these sections: overview, recent activity and campaigns (with dates and sources), infection chain
and TTPs, targeting, notable indicators (only from the data provided), ideas for detection and hunting, and an
assessment of whether activity is rising and how confident that assessment is. The brief is saved on the entity
and shown until someone generates a new one.

## Executive summary

`run_digest` runs daily at **06:00** by default, when the daily summary is switched on, and also whenever
someone clicks *AI summary*. You can change the time and the time zone under Settings → General (`digest_time`
and `schedule_timezone`). The default is UTC, which is 13:00 in Jakarta, so a team there would typically choose
`Asia/Jakarta` and a time such as 07:00. The next scheduled run is shown on the same tab.

**The input** is calculated by JATMP's normal statistics, not by the model:

| Data | Details |
|---|---|
| Trending malware | The top 8 of the last 7 days, with recent and baseline counts, sources, growth and the *new* flag |
| Trending actors | The top 5 |
| Trending CVEs | The top 6 by priority, with KEV, CVSS and EPSS |
| Scam types | The top 5, with reports this week and the week before, and whether they are *spreading* |
| Sectors | Up to 5 sectors with items this week |
| Top items | The 25 original (non-copy) items of the last 24 hours with the highest severity plus half their fraud score, each with its summary or the first 220 characters of its text |

**The output** the model is asked for is a single JSON object: a one-sentence headline, an overall threat level
(*low*, *elevated*, *high* or *critical*), 3 or 4 key points (each a title and one sentence), and no more than 3
actions for today.

**Before it is shown,** JATMP checks the answer. It extracts the JSON, removes Markdown formatting, bullets and
maths notation from every text, limits the lengths (headline 400 characters, point titles 120, details 400,
actions 300), keeps at most 4 points and 3 actions, and drops a threat level it doesn't recognise. If there is no
usable headline, the model's text is shown as it came. The result is saved under *AI insights*, shown on the
dashboard card, and announced with a notification. If the run fails, an error notification is sent (at most once
a day).

## Questions

*Ask* (on the AI insights page) answers a question using the collected data:

1. **Which items.** `llm/retrieval.py` scores the items of the period the question names ("today", "minggu ini",
   "this month"; otherwise the last **30 days**), copies of a syndicated story left out:

    | Signal | How it is found | Weight |
    |---|---|---|
    | Entities the question names | Families, actors, CVEs and indicators by the extractor (aliases included: "Fancy Bear" is APT28), scam types and brands by the fraud rules | 4 |
    | Concepts | A malware type ("ransomware", "stealer", "pencuri data"), a critical infrastructure sector ("hospital", "rumah sakit", "bank"), or a question about scams | 2 |
    | Words | Each word of 3 or more letters (common English and Indonesian words left out, up to 8) through the full-text index; an item doesn't need every word | 1, plus 0.5 when it is in the title |

    "Ransomware attacks on hospitals" therefore finds "LockBit hits a healthcare provider" although they share no
    word. When nothing matches, the most severe recent items are used so the model can say what there is.
2. The 25 best items, numbered [1]…[25], each with its summary or first 500 characters, and the top 10 trending
   families are added to the prompt.
3. The model is told to answer **only** from that material, to **cite** the items it uses as [n], and to say what
   is missing.
4. Each citation becomes a link to the item, and under the answer *Based on N item(s)* lists the items with what
   the question matched (entities, concepts, period); items the model did not cite are greyed.

It is still not a search by meaning (embeddings would be the next step), but synonyms that JATMP already knows
(aliases, sectors, malware types) now carry the question. Answers are saved under *AI insights* and deleted after
90 days.

## What leaves your network

With a **local** model (Ollama, LM Studio, llama.cpp, vLLM and similar), prompts stay on your own
infrastructure. With a **cloud** provider, the prompts described above are sent to that provider: item titles and
text, entity names, enrichment summaries and statistics. These requests go through the same outbound guard as
everything else (see [Security](../security.md)).

**Personal data is replaced before a prompt leaves.** Item text can quote the phone numbers, bank accounts and
e-mail addresses of scammers and victims. Before a prompt goes to a cloud model, JATMP replaces:

- every phone and e-wallet number;
- every account number written as such ("rekening BCA …");
- every run of 10 to 18 digits (national ID numbers, card numbers, account numbers);
- every e-mail address.

Each one becomes a placeholder that stays the same for the same value within a prompt, such as `[phone 1]`,
`[account 1]`, `[number 1]` or `[email 1]`, so the model can still tell them apart. Amounts written with
separators ("Rp 1.500.000"), IPs, domains, hashes, CVE ids and crypto wallets are left alone, because they are
what the analysis is about. Summaries of redacted items therefore mention the placeholders, not the numbers.

The setting *Personal data in prompts* (`llm_redact`, Settings → AI) controls this:

| Value | Behaviour |
|---|---|
| `cloud` (default) | Redacts when the model runs outside your network: Anthropic, or an OpenAI-compatible or Ollama server on a public host name. Localhost, private addresses, and single-label or `.local` / `.internal` names count as local |
| `always` | Always redacts, even for a local model |
| `never` | Never redacts |
