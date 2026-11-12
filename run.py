#!/usr/bin/env python
import argparse
import os

import uvicorn

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.getenv("JATMP_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.getenv("JATMP_PORT", "8000")))
    ap.add_argument("--reload", action="store_true")
    a = ap.parse_args()
    # One worker on purpose: the APScheduler instance lives in-process. Scale collectors by
    # interval, not by web workers.
    uvicorn.run("app.main:app", host=a.host, port=a.port, reload=a.reload, proxy_headers=True,
                forwarded_allow_ips=os.getenv("JATMP_FORWARDED_ALLOW_IPS", "127.0.0.1"))
