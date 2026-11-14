"""Test bootstrap: every test runs against a throw-away data dir / SQLite DB.

The environment must be set before `app.*` is imported (config paths are resolved at import).
"""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="jatmp-test-")
os.environ["JATMP_DATA_DIR"] = _TMP
os.environ.pop("JATMP_DATABASE_URL", None)
# make sure a developer's .env / shell cannot leak real providers into the test run
for var in ("LLM_PROVIDER", "VT_API_KEY", "OTX_API_KEY", "URLSCAN_API_KEY", "ANYRUN_API_KEY",
            "ABUSECH_AUTH_KEY", "NVD_API_KEY", "X_BEARER_TOKEN", "LLM_API_KEY", "ANTHROPIC_API_KEY", "JATMP_SECURE_COOKIES"):
    os.environ.pop(var, None)

import pytest
from fastapi.testclient import TestClient

from app.config import load_config, save_config
from app.setup_service import perform_install


@pytest.fixture(scope="session")
def installed():
    """Single-user install with the default sources, once per test session."""
    perform_install(mode="single", seed_sources=True)
    return True


@pytest.fixture()
def client(installed):
    # No `with` block on purpose: the lifespan would start the scheduler and real collectors.
    from app.main import app

    return TestClient(app)


@pytest.fixture()
def multi_user_mode(installed):
    """Temporarily switch the install to multi-user mode and create an admin."""
    from sqlalchemy import select

    from app.auth import hash_password
    from app.db import session_scope
    from app.models import User

    cfg = load_config()
    before = cfg["mode"]
    save_config({**cfg, "mode": "multi"})
    with session_scope() as db:
        if not db.execute(select(User).where(User.username == "admin")).scalar_one_or_none():
            db.add(User(username="admin", display_name="Admin", role="admin",
                        password_hash=hash_password("CorrectHorse9")))
    yield {"username": "admin", "password": "CorrectHorse9"}
    save_config({**load_config(), "mode": before})
