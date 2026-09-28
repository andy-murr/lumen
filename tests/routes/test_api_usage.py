"""API key usage is visible only to the key that recorded it."""

from datetime import datetime
from decimal import Decimal
from http import HTTPStatus

from lumen.extensions import db
from lumen.models.api_key import APIKey
from lumen.services.crypto import hash_api_key


def test_usage_returns_only_authenticated_keys_cumulative_counters(app, client, test_user):
    with app.app_context():
        first = APIKey(
            entity_id=test_user["id"], name="first", key_hash=hash_api_key("first-token"),
            requests=3, input_tokens=100, output_tokens=25, audio_seconds=42,
            cost=Decimal("1.234567"), last_used_at=datetime(2026, 9, 28, 14, 0),
        )
        second = APIKey(
            entity_id=test_user["id"], name="second", key_hash=hash_api_key("second-token"),
            requests=8, input_tokens=800, output_tokens=200, cost=Decimal("9.000000"),
        )
        db.session.add_all([first, second])
        db.session.commit()

    response = client.get("/v1/usage", headers={"Authorization": "Bearer first-token"})

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {
        "requests": 3,
        "input_tokens": 100,
        "output_tokens": 25,
        "total_tokens": 125,
        "audio_seconds": 42,
        "cost": 1.234567,
        "last_used_at": "2026-09-28T14:00:00Z",
    }
    assert client.get("/v1/usage", headers={"Authorization": "Bearer first-token"}).get_json() == response.get_json()
    assert client.get("/v1/usage", headers={"Authorization": "Bearer second-token"}).get_json()["requests"] == 8


def test_usage_requires_active_api_key(app, client, test_user):
    with app.app_context():
        db.session.add(APIKey(
            entity_id=test_user["id"], name="inactive", key_hash=hash_api_key("inactive-token"),
            active=False,
        ))
        db.session.commit()

    assert client.get("/v1/usage").status_code == HTTPStatus.BAD_REQUEST
    assert client.get("/v1/usage", headers={"Authorization": "Bearer invalid"}).status_code == HTTPStatus.UNAUTHORIZED
    assert client.get("/v1/usage", headers={"Authorization": "Bearer inactive-token"}).status_code == HTTPStatus.UNAUTHORIZED


def test_usage_for_unused_key_has_zero_counters_and_no_last_use(app, client, test_user):
    with app.app_context():
        db.session.add(APIKey(
            entity_id=test_user["id"], name="unused", key_hash=hash_api_key("unused-token"),
        ))
        db.session.commit()

    response = client.get("/v1/usage", headers={"Authorization": "Bearer unused-token"})

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == {
        "requests": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "audio_seconds": 0,
        "cost": 0.0,
        "last_used_at": None,
    }


def test_usage_rejects_monitor_token(app, client):
    app.config["YAML_DATA"] = {
        **app.config.get("YAML_DATA", {}),
        "api": {"monitoring": {"token": "monitor-token"}},
    }

    response = client.get("/v1/usage", headers={"Authorization": "Bearer monitor-token"})

    assert response.status_code == HTTPStatus.FORBIDDEN
