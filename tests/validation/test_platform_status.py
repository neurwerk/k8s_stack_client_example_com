"""Tests for the dedicated platform compatibility status publisher."""

from __future__ import annotations

import io
import json
import unittest
from urllib.request import Request

from scripts.publish_platform_status import StatusError, publish_status


class PlatformStatusTests(unittest.TestCase):
    def test_status_targets_the_exact_sha_and_fixed_context(self) -> None:
        requests: list[Request] = []
        responses = [io.BytesIO(b"{}")]

        def opener(request: Request, *, timeout: int):
            self.assertEqual(timeout, 20)
            requests.append(request)
            return responses.pop(0)

        published = publish_status(
            repository="neurwerk/example",
            sha="a" * 40,
            state="success",
            run_id="12",
            run_attempt="1",
            token="installation-token",
            opener=opener,
        )

        self.assertTrue(published)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].get_method(), "POST")
        self.assertTrue(requests[0].full_url.endswith(f"/statuses/{'a' * 40}"))
        body = json.loads(requests[0].data or b"")
        self.assertEqual(body["context"], "Platform Compatibility")
        self.assertEqual(body["state"], "success")
        self.assertEqual(
            body["target_url"],
            "https://github.com/neurwerk/example/actions/runs/12/attempts/1",
        )

    def test_status_publisher_rejects_untrusted_endpoints_and_inputs(self) -> None:
        with self.assertRaisesRegex(StatusError, "must use github.com"):
            publish_status(
                repository="neurwerk/example",
                sha="a" * 40,
                state="success",
                run_id="12",
                run_attempt="1",
                token="installation-token",
                api_url="https://example.test",
            )
        with self.assertRaisesRegex(StatusError, "token is missing"):
            publish_status(
                repository="neurwerk/example",
                sha="a" * 40,
                state="success",
                run_id="12",
                run_attempt="1",
                token="",
            )


if __name__ == "__main__":
    unittest.main()
