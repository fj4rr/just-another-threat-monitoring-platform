# JATMP — Just Another Threat Monitoring Platform

Platform self-hosted untuk memantau kampanye malware baru / yang sedang ramai dibicarakan komunitas,
dengan menggabungkan **berita keamanan siber**, **media sosial** (X, Bluesky) dan **platform threat intel**
(VirusTotal, AlienVault OTX, urlscan.io, ANY.RUN, ThreatFox), lalu saling memperkaya datanya dan
menampilkannya dalam dashboard tren. Opsional: LLM lokal atau API untuk insight tambahan.

## Fitur

| Area | Isi |
|---|---|
| **Sumber berita** | The Hacker News, Cyber Security News, BleepingComputer, SecurityWeek, The Record, Dark Reading, The DFIR Report, Unit 42, Malwarebytes Labs, SANS ISC, Krebs on Security, Cisco Talos, Securelist, Microsoft Security — tambah RSS lain lewat UI |
| **Bluesky** (API publik, tanpa key) | vx-underground, Marcus Hutchins, MalwareHunterTeam, Kevin Beaumont, Catalin Cimpanu, Will Thomas (BushidoToken), Zack Whittaker, Lorenzo Franceschi-Bicchierai, Dan Goodin, Karsten Hahn, hasherezade, Silas Cutler, Shadowserver, The DFIR Report, ESET Research, Cisco Talos, SentinelLABS, GreyNoise, Huntress, Ransomware.live |
| **Mastodon** (API publik, tanpa key) | Marcus Hutchins, Brian Krebs, Brad Duncan (malware-traffic), SANS ISC, Proofpoint Threat Insight, Thomas Roccia, ffforward, Matt Taggart, Kevin Beaumont |
| **X / Twitter** (API v2 bearer token **atau** RSS bridge) | Aktif: vxunderground, MalwareTechBlog, malwrhunterteam. Tersedia tapi **nonaktif** secara default (aktifkan di Settings agar kuota API tidak boros): GossiTheDog, cyb3rops, 1ZRR4H, BushidoToken, TheDFIRReport, Unit42_Intel, abuse_ch, malware_traffic, ESETresearch, MsftSecIntel, executemalware, pr0xylife, g0njxa, Max_Mal_, RedDrip7, fr0gger_, StopMalvertisin, ViriBack, Fox_threatintel, FalconFeedsio, H4ckManac, anyrun_app, ffforward |
| **Threat intel (collector)** | OTX subscribed pulses / search, urlscan.io search, ANY.RUN TI Lookup query, ThreatFox IOC terbaru |
| **Ekstraksi entitas** | Malware family (±150 family + alias), threat actor (±45), CVE, teknik ATT&CK, IOC (IP, domain, URL, MD5/SHA1/SHA256 — termasuk yang di-*defang* `hxxp`, `[.]`). Deteksi family **baru** yang belum ada di knowledge base (pola “`PipeMagic backdoor`”, “`WhiteArmor ransomware`”) |
| **Enrichment lintas sumber** | IOC dari berita/sosmed otomatis dicek ke VirusTotal, OTX, urlscan, ANY.RUN → verdict + family yang diatribusikan (mis. hash dari post Bluesky → “Lumma Stealer” dari VT) sehingga tersambung ke artikel lain tentang family itu. Family yang sedang trending ditarik IOC-nya dari OTX & ANY.RUN |
| **Korelasi** | Halaman item menampilkan item dari sumber lain yang berbagi entitas; halaman entitas menampilkan coverage per sumber, co-occurrence, IOC terkait, dan hasil enrichment |
| **Dashboard** | Animasi: *threat radar* (family trending sebagai blip yang menyala saat disapu radar, makin dekat pusat makin panas), KPI count-up + sparkline, ticker headline, kartu muncul bertahap, chart beranimasi, auto-refresh 60 detik (menghormati *prefers-reduced-motion*). Isi: KPI, volume per jenis sumber, family trending (skor = laju 7 hari vs baseline 30 hari × sebaran sumber), timeline top-5 family, family terbanyak, malware per tipe, verdict IOC, item per sumber, actor & CVE terhangat |
| **AI (opsional)** | Ringkasan + ekstraksi per item, *threat brief* per family/actor, *daily digest* otomatis 06:00 UTC, tanya-jawab atas data yang terkumpul. Provider: **Ollama** (lokal), **OpenAI-compatible** (LM Studio, vLLM, llama.cpp, OpenRouter, OpenAI, Groq…), **Anthropic Claude** (SDK resmi, default `claude-opus-5-5`). Bahasa output bisa diatur (mis. *Bahasa Indonesia*) |
| **Mode instalasi** | **Single-user** (tanpa login) atau **multi-user** (login, role admin/analyst/viewer, dashboard admin: manajemen user, status job, audit log, statistik sistem) |
| **Lainnya** | Watchlist per user, tema gelap/terang, CSRF protection, proteksi brute-force login, retensi data, Docker |

## Instalasi cepat (lokal)

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
python install.py             # interaktif: pilih single / multi user, API key, LLM
```
```bash
python run.py                 # buka http://127.0.0.1:8000
```

Atau lewati `install.py`: saat pertama kali dibuka, web UI menampilkan **setup wizard** yang sama.
Non-interaktif: `python install.py --mode multi --admin admin --password 'PasswordKuat123'`.

> Wizard web tidak memerlukan login (belum ada user). Jalankan instalasi pertama di `127.0.0.1`
> (default) sebelum mengekspos port ke jaringan.

### Docker

```bash
cp .env.example .env
```
```bash
docker compose up -d --build
```

LLM lokal di container: `docker compose --profile llm up -d`, lalu `docker compose exec ollama ollama pull llama3.1`
dan set base URL `http://ollama:11434`.

## Konfigurasi

Semua API key dan opsi bisa diatur di **Settings** (role admin). Variabel environment (lihat `.env.example`)
meng-override UI dan tampil terkunci.

| Layanan | Key | Catatan |
|---|---|---|
| VirusTotal | `VT_API_KEY` | Free tier 4 req/menit, 500/hari — sudah di-throttle (`vt_min_interval`, `vt_daily_budget`) |
| AlienVault OTX | `OTX_API_KEY` | Gratis. Subscribe ke pulse/user di OTX supaya feed “subscribed” terisi |
| urlscan.io | `URLSCAN_API_KEY` | Search API sekarang butuh key |
| ANY.RUN | `ANYRUN_API_KEY` | Butuh paket dengan **TI Lookup**. Base URL bisa diubah di Settings |
| abuse.ch ThreatFox | `ABUSECH_AUTH_KEY` | Gratis (Auth-Key dari auth.abuse.ch) |
| X / Twitter | `X_BEARER_TOKEN` | API v2 berbayar; alternatif isi `rss_bridge` per sumber X |

### Menambah malware family / actor tanpa ubah kode

Buat `data/knowledge_extra.json`:

```json
{
  "malware": {"WhiteArmor": {"category": "ransomware", "aliases": ["white armor"]}},
  "actors":  {"UNC9999": {"aliases": ["some alias"]}}
}
```

Restart, lalu jalankan `python manage.py reextract` untuk memproses ulang item lama.

## Perintah maintenance

```bash
python manage.py collect          # jalankan semua collector sekarang (atau: collect 1 5 7)
python manage.py enrich           # satu batch enrichment
python manage.py digest           # buat AI digest sekarang
python manage.py reextract        # ekstraksi ulang entitas di semua item
python manage.py seed-sources     # tambahkan sumber bawaan baru ke instalasi lama (juga ada tombolnya di Settings)
python manage.py create-user budi analyst
```

## Arsitektur

```
app/
  collectors/   rss, bluesky, mastodon, x_twitter, intel (OTX, urlscan, ANY.RUN, ThreatFox)  → RawItem
  processing/   pipeline (dedupe, simpan, link entitas) · extractor (IOC/CVE/family/actor)
                enrichment (lintas sumber) · trends (agregasi dashboard)
  intel/        client API: VirusTotal, OTX, urlscan, ANY.RUN, ThreatFox (+ rate limit/budget)
  llm/          client (Ollama / OpenAI-compatible / Anthropic) · insights (summary, brief, digest, Q&A)
  routers/      pages, api (JSON + aksi), settings, admin, auth/setup
  jobs.py       APScheduler: collector per sumber, enrichment tiap N menit, digest harian, housekeeping
data/           config.json (mode instalasi, secret), jatmp.db (SQLite)
```

Database default SQLite (WAL). Untuk deployment besar set `JATMP_DATABASE_URL` ke PostgreSQL
(install driver `psycopg[binary]`).

## Catatan

- Semua akun Bluesky & Mastodon di atas sudah dicek aktif pada 12 Nov 2026. Pengecualian: `vxunderground.bsky.social`
  belum punya post, dan Marcus Hutchins / MalwareHunterTeam jarang posting di Bluesky — aktivitas utama mereka di X
  (dan Marcus juga di Mastodon). Handle X tidak bisa diverifikasi tanpa token API.
- Endpoint ANY.RUN TI Lookup (`/v1/intelligence/api/search`) ditulis berdasarkan dokumentasi publik dan belum diuji
  dengan key asli; parser-nya defensif dan base URL bisa diubah.
- Skor severity adalah heuristik (kata kunci + jenis entitas); LLM bisa menaikkannya saat analisis.
