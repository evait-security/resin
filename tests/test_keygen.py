import os
import ssl

from src.services.ssh import generate_host_key
from src.services.http import generate_self_signed_cert


class TestSSHHostKeyGeneration:
    def test_generates_key_in_container(self, tmp_path):
        target = tmp_path / "run" / "ssh_host_key"
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


class TestTLSCertGeneration:
    def test_generates_cert_in_container(self, tmp_path):
        cert = tmp_path / "run" / "tls_cert.pem"
        key = tmp_path / "run" / "tls_key.pem"
        cert_path, key_path = generate_self_signed_cert(str(cert), str(key))
        assert cert_path == str(cert)
        assert key_path == str(key)
        assert os.path.exists(cert_path) and os.path.getsize(cert_path) > 0
        assert os.path.exists(key_path) and os.path.getsize(key_path) > 0
        # Cert/key must load into an SSL context together.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)

    def test_reuses_existing_cert(self, tmp_path):
        cert = tmp_path / "tls_cert.pem"
        key = tmp_path / "tls_key.pem"
        generate_self_signed_cert(str(cert), str(key))
        with open(cert, "rb") as f:
            original = f.read()
        cert_path, key_path = generate_self_signed_cert(str(cert), str(key))
        assert cert_path == str(cert) and key_path == str(key)
        with open(cert_path, "rb") as f:
            assert f.read() == original
