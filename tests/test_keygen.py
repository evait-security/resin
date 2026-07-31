import os
import ssl

import pytest

from src.services.ssh import generate_host_key
from src.services.http import generate_self_signed_cert


class TestSSHHostKeyGeneration:
    def test_generates_key_at_preferred_path(self, tmp_path):
        target = tmp_path / "data" / "ssh_host_key"
        path = generate_host_key(str(target))
        assert path == str(target)
        assert os.path.exists(path)
        assert os.path.getsize(path) > 0

    def test_reuses_existing_key(self, tmp_path):
        target = tmp_path / "ssh_host_key"
        first = generate_host_key(str(target))
        with open(first, "rb") as f:
            original = f.read()
        second = generate_host_key(str(target))
        assert second == first
        with open(second, "rb") as f:
            assert f.read() == original

    def test_falls_back_when_preferred_path_not_writable(self, tmp_path, monkeypatch):
        fallback = tmp_path / "fallback"
        monkeypatch.setattr("src.services.ssh.KEY_FALLBACK_DIR", str(fallback))

        readonly = tmp_path / "readonly"
        readonly.mkdir()
        os.chmod(readonly, 0o500)
        target = readonly / "ssh_host_key"
        try:
            path = generate_host_key(str(target))
        finally:
            os.chmod(readonly, 0o700)

        assert path == str(fallback / "ssh_host_key")
        assert os.path.exists(path)
        assert not os.path.exists(str(target))


class TestTLSCertGeneration:
    def test_generates_cert_at_preferred_path(self, tmp_path):
        cert = tmp_path / "data" / "tls_cert.pem"
        key = tmp_path / "data" / "tls_key.pem"
        cert_path, key_path = generate_self_signed_cert(str(cert), str(key))
        assert cert_path == str(cert)
        assert key_path == str(key)
        assert os.path.exists(cert_path) and os.path.getsize(cert_path) > 0
        assert os.path.exists(key_path) and os.path.getsize(key_path) > 0
        # Cert/key must load into an SSL context together.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)

    def test_falls_back_when_preferred_path_not_writable(self, tmp_path, monkeypatch):
        fallback = tmp_path / "fallback"
        monkeypatch.setattr("src.services.http.KEY_FALLBACK_DIR", str(fallback))

        readonly = tmp_path / "readonly"
        readonly.mkdir()
        os.chmod(readonly, 0o500)
        cert = readonly / "tls_cert.pem"
        key = readonly / "tls_key.pem"
        try:
            cert_path, key_path = generate_self_signed_cert(str(cert), str(key))
        finally:
            os.chmod(readonly, 0o700)

        assert cert_path == str(fallback / "tls_cert.pem")
        assert key_path == str(fallback / "tls_key.pem")
        assert os.path.exists(cert_path) and os.path.exists(key_path)
        assert not os.path.exists(str(cert))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
