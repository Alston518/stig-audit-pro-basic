from __future__ import annotations

import logging
from types import SimpleNamespace

from stig_audit_pro.basic_app import BasicApp


class Variable:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


def _app(decision):
    app = BasicApp.__new__(BasicApp)
    app.verify_host_keys = Variable(False)
    app.host_key_banner = SimpleNamespace(configure=lambda **kwargs: setattr(app, "banner", kwargs["text"]))
    app.messagebox = SimpleNamespace(askyesno=lambda *_args, **_kwargs: decision)
    app.root = object()
    app.update_mode_badge = lambda: None
    return app


def test_disabling_host_keys_requires_confirmation_and_shows_banner(caplog):
    app = _app(True)
    with caplog.at_level(logging.WARNING, logger="stig_audit_pro.activity"):
        app._on_host_key_toggle()
    assert app.verify_host_keys.get() is False
    assert "OFF" in app.banner
    assert "HOST_KEY_VERIFICATION_DISABLED" in caplog.text


def test_declined_host_key_change_restores_verification(caplog):
    app = _app(False)
    with caplog.at_level(logging.WARNING, logger="stig_audit_pro.activity"):
        app._on_host_key_toggle()
    assert app.verify_host_keys.get() is True
    assert not app.banner
    assert "HOST_KEY_VERIFICATION_DISABLED" not in caplog.text
