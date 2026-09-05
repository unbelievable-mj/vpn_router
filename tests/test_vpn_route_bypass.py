#!/usr/bin/env python3
"""VPN Route Bypass 引擎单元测试。

覆盖新增能力：
- fake-ip 网段检测
- DoH 兜底解析（模拟系统解析被 fake-ip 劫持）
- /etc/hosts 标记段管理（写入 / 清理 / 幂等 / 不破坏其他行）
- sync_once 在 dry-run 模式下的完整流程

运行：
    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vpn_route_bypass as vrb  # noqa: E402


class FakeIpDetectionTest(unittest.TestCase):
    def test_fake_ip_range_hit(self):
        self.assertTrue(vrb.is_suspicious_ip("198.18.1.121", vrb.DEFAULT_FAKE_IP_RANGES))
        self.assertTrue(vrb.is_suspicious_ip("100.64.0.5", vrb.DEFAULT_FAKE_IP_RANGES))

    def test_public_ip_not_suspicious(self):
        self.assertFalse(vrb.is_suspicious_ip("203.0.113.50", vrb.DEFAULT_FAKE_IP_RANGES))
        self.assertFalse(vrb.is_suspicious_ip("8.8.8.8", vrb.DEFAULT_FAKE_IP_RANGES))

    def test_invalid_ip(self):
        self.assertFalse(vrb.is_suspicious_ip("not-an-ip", vrb.DEFAULT_FAKE_IP_RANGES))

    def test_ipv6_ignored(self):
        self.assertFalse(vrb.is_suspicious_ip("2001:db8::1", vrb.DEFAULT_FAKE_IP_RANGES))


class HostsMarkedBlockTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8")
        self.tmp.close()
        self.tmp_path = Path(self.tmp.name)
        self.hosts_patcher = mock.patch.object(vrb, "hosts_path", return_value=str(self.tmp_path))
        self.hosts_patcher.start()

    def tearDown(self):
        self.hosts_patcher.stop()
        if self.tmp_path.exists():
            self.tmp_path.unlink()

    def test_strip_marked_block(self):
        text = (
            "# system line\n"
            "127.0.0.1 localhost\n"
            "# === VPN-ROUTE-BYPASS-BEGIN ===\n"
            "198.18.1.120 bad.example\n"
            "# === VPN-ROUTE-BYPASS-END ===\n"
            "255.255.255.255 broadcasthost\n"
        )
        stripped = vrb._strip_marked_block(text)
        self.assertNotIn("VPN-ROUTE-BYPASS", stripped)
        self.assertNotIn("bad.example", stripped)
        self.assertIn("127.0.0.1 localhost", stripped)
        self.assertIn("255.255.255.255 broadcasthost", stripped)

    def test_update_then_clear_roundtrip(self):
        # 预置用户原始内容
        self.tmp_path.write_text("# user line\n127.0.0.1 localhost\n", encoding="utf-8")

        ok = vrb.update_hosts_marked({"www.example.edu.cn": "203.0.113.50"})
        self.assertTrue(ok)
        content = self.tmp_path.read_text(encoding="utf-8")
        self.assertIn("203.0.113.50\twww.example.edu.cn", content)
        self.assertIn("# user line", content)
        self.assertIn("127.0.0.1 localhost", content)

        # 幂等：再次写入不产生重复条目
        vrb.update_hosts_marked({"www.example.edu.cn": "203.0.113.50"})
        content2 = self.tmp_path.read_text(encoding="utf-8")
        self.assertEqual(content2.count("203.0.113.50"), 1)

        # 清理：只删托管块，保留用户行
        vrb.clear_hosts_marked()
        content3 = self.tmp_path.read_text(encoding="utf-8")
        self.assertNotIn("VPN-ROUTE-BYPASS", content3)
        self.assertIn("# user line", content3)
        self.assertIn("127.0.0.1 localhost", content3)


class DoHFallbackTest(unittest.TestCase):
    def test_resolve_real_addresses_falls_back_when_fake_ip(self):
        cfg = {
            "fake_ip_ranges": vrb.DEFAULT_FAKE_IP_RANGES,
            "doh_enabled": True,
            "doh_urls": ["https://example.invalid/resolve?name={host}&type=A"],
        }
        # 系统解析返回 fake-ip，DoH 返回真实 IP
        with mock.patch.object(
            vrb, "resolve_ipv4_addresses", return_value={"198.18.1.121"}
        ), mock.patch.object(vrb, "resolve_via_doh", return_value=["203.0.113.50"]):
            result = vrb.resolve_real_addresses("www.example.edu.cn", cfg)
        self.assertEqual(result, {"203.0.113.50"})

    def test_resolve_real_addresses_uses_system_when_real(self):
        cfg = {"fake_ip_ranges": vrb.DEFAULT_FAKE_IP_RANGES, "doh_enabled": True}
        with mock.patch.object(
            vrb, "resolve_ipv4_addresses", return_value={"203.0.113.50"}
        ), mock.patch.object(vrb, "resolve_via_doh", return_value=["8.8.8.8"]) as doh:
            result = vrb.resolve_real_addresses("www.example.edu.cn", cfg)
        self.assertEqual(result, {"203.0.113.50"})
        doh.assert_not_called()

    def test_resolve_real_addresses_mixed_keeps_real(self):
        cfg = {"fake_ip_ranges": vrb.DEFAULT_FAKE_IP_RANGES, "doh_enabled": True}
        with mock.patch.object(
            vrb, "resolve_ipv4_addresses", return_value={"198.18.1.121", "203.0.113.50"}
        ), mock.patch.object(vrb, "resolve_via_doh", return_value=[]) as doh:
            result = vrb.resolve_real_addresses("www.example.edu.cn", cfg)
        self.assertEqual(result, {"203.0.113.50"})
        doh.assert_not_called()


class HostIpOverridesTest(unittest.TestCase):
    """host_ip_overrides：为白名单域名手动指定直连 IP（内网地址）的通用能力。"""

    def _cfg(self, overrides=None, prefixes=None):
        cfg = {
            "prefixes": prefixes if prefixes is not None else ["https://intra.example.edu.cn"],
            "fake_ip_ranges": vrb.DEFAULT_FAKE_IP_RANGES,
            "doh_enabled": True,
        }
        if overrides is not None:
            cfg["host_ip_overrides"] = overrides
        return cfg

    def test_override_used_without_resolving(self):
        cfg = self._cfg(overrides={"https://intra.example.edu.cn": "10.10.0.155"})
        with mock.patch.object(vrb, "resolve_real_addresses") as resolver:
            result = vrb.build_target_host_map(cfg)
        self.assertEqual(result, {"intra.example.edu.cn": {"10.10.0.155"}})
        resolver.assert_not_called()

    def test_override_key_with_and_without_scheme(self):
        cfg = self._cfg(overrides={"intra.example.edu.cn": "10.10.0.155"})
        result = vrb.build_target_host_map(cfg)
        self.assertEqual(result, {"intra.example.edu.cn": {"10.10.0.155"}})

    def test_invalid_override_ip_ignored(self):
        cfg = self._cfg(
            overrides={"intra.example.edu.cn": "999.1.1.1", "mail.example.edu.cn": "not-an-ip"}
        )
        with mock.patch.object(vrb, "resolve_real_addresses", return_value={"203.0.113.2"}):
            result = vrb.build_target_host_map(cfg)
        # 无效 override 被忽略，退回自动解析
        self.assertEqual(result, {"intra.example.edu.cn": {"203.0.113.2"}})

    def test_override_does_not_affect_other_hosts(self):
        cfg = self._cfg(
            prefixes=["https://intra.example.edu.cn", "portal.example.edu.cn"],
            overrides={"https://intra.example.edu.cn": "10.10.0.155"},
        )
        with mock.patch.object(vrb, "resolve_real_addresses", return_value={"203.0.113.50"}):
            result = vrb.build_target_host_map(cfg)
        self.assertEqual(
            result,
            {
                "intra.example.edu.cn": {"10.10.0.155"},
                "portal.example.edu.cn": {"203.0.113.50"},
            },
        )

    def test_parse_ip_overrides_ignores_ipv6_and_non_string(self):
        raw = {
            "https://a.example.edu.cn": "10.0.0.1",
            "https://b.example.edu.cn": "2001:db8::1",
            "https://c.example.edu.cn": 123,
            42: "1.2.3.4",
        }
        parsed = vrb.parse_ip_overrides(raw)
        self.assertEqual(parsed, {"a.example.edu.cn": "10.0.0.1"})


class SyncOnceDryRunTest(unittest.TestCase):
    def test_sync_once_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            cfg = {
                "prefixes": ["www.example.edu.cn", "https://mail.example.edu.cn"],
                "manage_hosts": True,
                "fake_ip_ranges": vrb.DEFAULT_FAKE_IP_RANGES,
                "doh_enabled": True,
                "doh_urls": ["https://example.invalid/resolve?name={host}&type=A"],
            }
            manager = mock.Mock(spec=vrb.RouteManager)
            manager.dry_run = True
            manager.add_route.return_value = True
            manager.remove_route.return_value = True

            host_map = {
                "www.example.edu.cn": {"203.0.113.50"},
                "mail.example.edu.cn": {"203.0.113.2"},
            }
            with mock.patch.object(vrb, "build_target_host_map", return_value=host_map), \
                 mock.patch.object(vrb, "update_hosts_marked", return_value=True) as upd:
                vrb.sync_once(manager, Path("config.json"), cfg, state_path)

            # dry-run 不真正写 hosts
            upd.assert_not_called()
            # 对全部目标 IP 幂等重加
            self.assertEqual(manager.add_route.call_count, 2)
            manager.remove_route.assert_not_called()
            # 关键回归：dry-run 绝不落盘状态文件（防止污染后续真实运行）
            self.assertFalse(state_path.exists())

    def test_dry_run_does_not_overwrite_existing_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            state_path.write_text(json.dumps({"ips": ["203.0.113.50"]}), encoding="utf-8")
            cfg = {
                "prefixes": ["www.example.edu.cn"],
                "manage_hosts": True,
                "fake_ip_ranges": vrb.DEFAULT_FAKE_IP_RANGES,
                "doh_enabled": True,
                "doh_urls": ["https://example.invalid/resolve?name={host}&type=A"],
            }
            manager = mock.Mock(spec=vrb.RouteManager)
            manager.dry_run = True
            manager.add_route.return_value = True
            manager.remove_route.return_value = True

            host_map = {"www.example.edu.cn": {"203.0.113.50"}}
            with mock.patch.object(vrb, "build_target_host_map", return_value=host_map):
                vrb.sync_once(manager, Path("config.json"), cfg, state_path)
            # 既有状态文件内容保持不变
            self.assertEqual(
                json.loads(state_path.read_text(encoding="utf-8")),
                {"ips": ["203.0.113.50"]},
            )

    def test_sync_once_re_adds_route_even_if_in_state(self):
        """回归：状态文件已含目标 IP（如被 dry-run 污染），真实运行时仍必须幂等重加路由。"""
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            state_path.write_text(
                json.dumps({"ips": ["203.0.113.50"]}), encoding="utf-8"
            )
            cfg = {
                "prefixes": ["www.example.edu.cn"],
                "manage_hosts": True,
                "fake_ip_ranges": vrb.DEFAULT_FAKE_IP_RANGES,
                "doh_enabled": True,
                "doh_urls": ["https://example.invalid/resolve?name={host}&type=A"],
            }
            manager = mock.Mock(spec=vrb.RouteManager)
            manager.dry_run = False
            manager.add_route.return_value = True
            manager.remove_route.return_value = True

            host_map = {"www.example.edu.cn": {"203.0.113.50"}}
            with mock.patch.object(vrb, "build_target_host_map", return_value=host_map), \
                 mock.patch.object(vrb, "update_hosts_marked", return_value=True):
                vrb.sync_once(manager, Path("config.json"), cfg, state_path)
            # 尽管状态文件已有该 IP，仍会调用 add_route 确保路由真实存在
            manager.add_route.assert_called_once_with("203.0.113.50")

    def test_sync_once_removes_stale_fake_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            state_path.write_text(
                json.dumps({"ips": ["198.18.1.120", "198.18.1.121"]}), encoding="utf-8"
            )
            cfg = {
                "prefixes": ["www.example.edu.cn"],
                "manage_hosts": True,
                "fake_ip_ranges": vrb.DEFAULT_FAKE_IP_RANGES,
                "doh_enabled": True,
                "doh_urls": ["https://example.invalid/resolve?name={host}&type=A"],
            }
            manager = mock.Mock(spec=vrb.RouteManager)
            manager.dry_run = False
            manager.add_route.return_value = True
            manager.remove_route.return_value = True

            host_map = {"www.example.edu.cn": {"203.0.113.50"}}
            with mock.patch.object(vrb, "build_target_host_map", return_value=host_map), \
                 mock.patch.object(vrb, "update_hosts_marked", return_value=True):
                vrb.sync_once(manager, Path("config.json"), cfg, state_path)

            saved = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["ips"], ["203.0.113.50"])
            # 旧 fake-ip 路由被移除，真实 IP 被添加
            removed = {c.args[0] for c in manager.remove_route.call_args_list}
            self.assertEqual(removed, {"198.18.1.120", "198.18.1.121"})


if __name__ == "__main__":
    unittest.main()
