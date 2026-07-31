"""
Testsuite für src/whitelist.py
Pytest-kompatibel; auch direkt ausführbar: python tests/test_whitelist.py
"""

import os
import sys
import asyncio
import signal
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def reload_whitelist_module(env: dict):
    """Modul + config mit frischer Env-Var-Umgebung neu laden."""
    for key in ("WHITELIST_IPS", "WHITELIST_IP_MASK", "WHITELIST_FILE", "WHITELIST_RELOAD_INTERVAL"):
        os.environ.pop(key, None)
    os.environ.update(env)
    for mod in ("src.config", "src.whitelist"):
        if mod in sys.modules:
            del sys.modules[mod]
    import src.whitelist as wl
    return wl


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_01_empty_whitelist():
    wl = reload_whitelist_module({"WHITELIST_IPS": "", "WHITELIST_FILE": "/nonexistent"})
    wl.load_whitelist()
    assert not wl.is_whitelisted("1.2.3.4")
    assert not wl.is_whitelisted("")


def test_02_env_whitelist_ips():
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "10.0.0.1, 192.168.1.0/24",
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert wl.is_whitelisted("10.0.0.1")
    assert wl.is_whitelisted("192.168.1.50")
    assert not wl.is_whitelisted("10.0.0.2")
    assert not wl.is_whitelisted("8.8.8.8")


def test_03_file_overrides_env():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("172.16.0.1\n")
        fname = f.name
    try:
        wl = reload_whitelist_module({"WHITELIST_IPS": "10.0.0.1", "WHITELIST_FILE": fname})
        wl.load_whitelist()
        assert wl.is_whitelisted("172.16.0.1")
        assert not wl.is_whitelisted("10.0.0.1")
    finally:
        os.unlink(fname)


def test_04_comments_and_blank_lines():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("# Kommentar\n\n10.10.10.1\n  # eingerückt\n")
        f.write("10.10.10.2   # inline\n10.10.10.3, 10.10.10.4\n")
        fname = f.name
    try:
        wl = reload_whitelist_module({"WHITELIST_IPS": "", "WHITELIST_FILE": fname})
        wl.load_whitelist()
        assert wl.is_whitelisted("10.10.10.1")
        assert wl.is_whitelisted("10.10.10.2")
        assert wl.is_whitelisted("10.10.10.3")
        assert wl.is_whitelisted("10.10.10.4")
        assert len(wl._WHITELIST_NETWORKS) == 4
    finally:
        os.unlink(fname)


def test_05_invalid_entries_ignored():
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "not-an-ip, 10.0.0.1, 999.999.999.999",
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert wl.is_whitelisted("10.0.0.1")
    assert len(wl._WHITELIST_NETWORKS) == 1


def test_06_invalid_ip_in_is_whitelisted():
    wl = reload_whitelist_module({"WHITELIST_IPS": "10.0.0.1", "WHITELIST_FILE": "/nonexistent"})
    wl.load_whitelist()
    assert not wl.is_whitelisted("garbage")
    assert not wl.is_whitelisted("")


def test_07_ipv6():
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "::1, 2001:db8::/32",
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert wl.is_whitelisted("::1")
    assert wl.is_whitelisted("2001:db8::1")
    assert not wl.is_whitelisted("2001:db9::1")


def test_08_sighup_signal_handler():
    wl = reload_whitelist_module({"WHITELIST_IPS": "10.0.0.1", "WHITELIST_FILE": "/nonexistent"})
    signal.signal(signal.SIGHUP, lambda *_: wl.load_whitelist())


def test_09_watch_detects_change():
    async def _run():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("10.1.1.1\n")
            fname = f.name
        try:
            wl = reload_whitelist_module({
                "WHITELIST_IPS": "",
                "WHITELIST_FILE": fname,
                "WHITELIST_RELOAD_INTERVAL": "1",
            })
            wl.load_whitelist()
            assert wl.is_whitelisted("10.1.1.1")
            assert not wl.is_whitelisted("10.2.2.2")

            task = asyncio.create_task(wl.watch_whitelist())
            await asyncio.sleep(0.1)
            with open(fname, "w") as fh:
                fh.write("10.2.2.2\n")
            os.utime(fname, (time.time() + 2, time.time() + 2))
            await asyncio.sleep(1.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            assert wl.is_whitelisted("10.2.2.2")
            assert not wl.is_whitelisted("10.1.1.1")
        finally:
            if os.path.exists(fname):
                os.unlink(fname)

    asyncio.run(_run())


def test_10_watch_stable_on_missing_file():
    async def _run():
        wl = reload_whitelist_module({
            "WHITELIST_IPS": "",
            "WHITELIST_FILE": "/tmp/does_not_exist_resin.txt",
            "WHITELIST_RELOAD_INTERVAL": "1",
        })
        wl.load_whitelist()
        task = asyncio.create_task(wl.watch_whitelist())
        await asyncio.sleep(1.5)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())


def test_11_watch_detects_deletion():
    async def _run():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("10.3.3.3\n")
            fname = f.name
        deleted = False
        try:
            wl = reload_whitelist_module({
                "WHITELIST_IPS": "10.0.0.1",
                "WHITELIST_FILE": fname,
                "WHITELIST_RELOAD_INTERVAL": "1",
            })
            wl.load_whitelist()
            assert wl.is_whitelisted("10.3.3.3")
            assert not wl.is_whitelisted("10.0.0.1")

            task = asyncio.create_task(wl.watch_whitelist())
            os.unlink(fname)
            deleted = True
            await asyncio.sleep(1.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            assert not wl.is_whitelisted("10.3.3.3")
            assert wl.is_whitelisted("10.0.0.1")
        finally:
            if not deleted and os.path.exists(fname):
                os.unlink(fname)

    asyncio.run(_run())


def test_12_watch_detects_creation():
    async def _run():
        fname = f"/tmp/resin_test_create_{os.getpid()}.txt"
        if os.path.exists(fname):
            os.unlink(fname)
        try:
            wl = reload_whitelist_module({
                "WHITELIST_IPS": "10.0.0.1",
                "WHITELIST_FILE": fname,
                "WHITELIST_RELOAD_INTERVAL": "1",
            })
            wl.load_whitelist()
            assert wl.is_whitelisted("10.0.0.1")
            assert not wl.is_whitelisted("10.4.4.4")

            task = asyncio.create_task(wl.watch_whitelist())
            await asyncio.sleep(0.1)
            with open(fname, "w") as fh:
                fh.write("10.4.4.4\n")
            os.utime(fname, (time.time() + 2, time.time() + 2))
            await asyncio.sleep(1.5)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            assert wl.is_whitelisted("10.4.4.4")
            assert not wl.is_whitelisted("10.0.0.1")
        finally:
            if os.path.exists(fname):
                os.unlink(fname)

    asyncio.run(_run())


def test_13_asyncio_sighup_handler():
    async def _run():
        wl = reload_whitelist_module({"WHITELIST_IPS": "10.0.0.1", "WHITELIST_FILE": "/nonexistent"})
        wl.load_whitelist()
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, wl.load_whitelist)
        loop.remove_signal_handler(signal.SIGHUP)

    asyncio.run(_run())


def test_14_mask_matches_suffix():
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "",
        "WHITELIST_IP_MASK": r"\.7$",
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert wl.is_whitelisted("192.168.1.7")
    assert wl.is_whitelisted("10.0.0.7")
    assert not wl.is_whitelisted("192.168.1.70")
    assert not wl.is_whitelisted("192.168.1.8")


def test_15_multiple_masks_newline_separated():
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "",
        "WHITELIST_IP_MASK": "\n".join([r"^10\.", r"\.255$"]),
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert len(wl._WHITELIST_MASKS) == 2
    assert wl.is_whitelisted("10.1.2.3")
    assert wl.is_whitelisted("192.168.0.255")
    assert not wl.is_whitelisted("192.168.0.1")


def test_16_mask_with_comma_quantifier():
    # A comma inside a regex quantifier must be preserved (not split on).
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "",
        "WHITELIST_IP_MASK": r"^172\.16\.\d{1,3}\.\d{1,3}$",
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert len(wl._WHITELIST_MASKS) == 1
    assert wl.is_whitelisted("172.16.5.9")
    assert not wl.is_whitelisted("172.17.5.9")


def test_17_mask_and_ip_combined():
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "10.0.0.1",
        "WHITELIST_IP_MASK": r"\.7$",
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert wl.is_whitelisted("10.0.0.1")     # IP whitelist
    assert wl.is_whitelisted("8.8.8.7")      # mask
    assert not wl.is_whitelisted("8.8.8.8")


def test_18_invalid_mask_ignored():
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "",
        "WHITELIST_IP_MASK": "\n".join([r"[", r"\.7$", "# a comment"]),
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert len(wl._WHITELIST_MASKS) == 1
    assert wl.is_whitelisted("1.2.3.7")


def test_19_ipv6_mask():
    wl = reload_whitelist_module({
        "WHITELIST_IPS": "",
        "WHITELIST_IP_MASK": r"^2001:db8:",
        "WHITELIST_FILE": "/nonexistent",
    })
    wl.load_whitelist()
    assert wl.is_whitelisted("2001:db8::1")
    assert not wl.is_whitelisted("2001:db9::1")


# ── Standalone runner ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
