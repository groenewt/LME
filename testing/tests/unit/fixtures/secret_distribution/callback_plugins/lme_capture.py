"""Test callback that records the exact result objects Ansible exposes to callbacks."""

import json
import os

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "lme_capture"
    CALLBACK_NEEDS_ENABLED = True

    def _record(self, event, result):
        path = os.environ.get("LME_CALLBACK_LOG")
        if not path:
            return
        record = {
            "event": event,
            "host": result._host.get_name(),
            "result": result._result,
        }
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, default=str, sort_keys=True) + "\n")

    def v2_runner_on_ok(self, result, **kwargs):
        self._record("ok", result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record("failed", result)

    def v2_runner_on_skipped(self, result):
        self._record("skipped", result)

