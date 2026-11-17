from app.main import app


def test_health():
    assert app.test_client().get("/health").json == {"ok": True}
