import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from osint_framework.api.redis_ws_bridge import RedisWebSocketBridge


class RedisWebSocketBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_handle_event_forwards_redis_metadata(self):
        bridge = RedisWebSocketBridge(
            event_bus=SimpleNamespace(channel="osint.events", instance_id="api-instance-1")
        )
        event = {"type": "job_update", "job_id": "job-123", "status": "running"}
        envelope = {"source": "worker-instance-7", "sent_at_ms": 1000, "event": event}

        with patch(
            "osint_framework.api.redis_ws_bridge.ws_manager.broadcast",
            new=AsyncMock(),
        ) as mock_broadcast:
            await bridge._handle_event(event, envelope)

        mock_broadcast.assert_awaited_once()
        forwarded = mock_broadcast.await_args.args[0]
        self.assertEqual(forwarded["type"], "job_update")
        self.assertEqual(forwarded["job_id"], "job-123")
        self.assertEqual(forwarded["status"], "running")

        meta = forwarded.get("_event_meta")
        self.assertIsInstance(meta, dict)
        self.assertEqual(meta.get("transport"), "redis_pubsub")
        self.assertEqual(meta.get("source"), "worker-instance-7")
        self.assertEqual(meta.get("channel"), "osint.events")
        self.assertEqual(meta.get("bridge_instance"), "api-instance-1")
        self.assertEqual(meta.get("sent_at_ms"), 1000)
        self.assertIn("bridge_received_at_ms", meta)
        self.assertIn("bridge_delay_ms", meta)
        self.assertGreaterEqual(meta["bridge_delay_ms"], 0)


if __name__ == "__main__":
    unittest.main()
