# Third-party notices

JATMP itself is released under the [MIT License](LICENSE). It ships or downloads the following third-party
material, each under its own terms.

## Bundled in this repository

| Component | Where | Licence |
|---|---|---|
| [Chart.js](https://www.chartjs.org/) 4.4.1 | `app/static/js/vendor/chart.umd.min.js` | MIT, Copyright (c) 2014-2024 Chart.js Contributors |
| Map outlines from [Natural Earth](https://www.naturalearthdata.com/) | `app/static/geo/world.json`, `app/static/geo/indonesia.json` (built by `scripts/build_geo.py`) | Public domain |

Chart.js licence text:

```text
The MIT License (MIT)

Copyright (c) 2014-2024 Chart.js Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
```

## Downloaded on request

| Data | When | Licence |
|---|---|---|
| [IP Geolocation by DB-IP](https://db-ip.com) (Lite) | `manage.py geoip-update` or the monthly refresh | CC BY 4.0; attribution is required where the data is shown |
| MaxMind GeoLite2 | Same, with a MaxMind license key | MaxMind GeoLite2 End User License Agreement |

## Data from sources and providers

Feeds, social posts and threat-intelligence answers stay under the terms of whoever publishes them. Several
providers limit what may be redistributed (for example ransomware.live's keyless API is for personal use only;
organisations need its free PRO key). JATMP's sharing rules (TLP, per-source redistribution, *Include
third-party provider verdicts*) help you respect them, but checking each provider's terms is up to the operator.
See [Sharing and integrations](docs/integrations.md#sharing-rules).

Python dependencies are installed from PyPI under their own licences (`requirements.txt`).
