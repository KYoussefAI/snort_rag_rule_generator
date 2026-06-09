import subprocess
import sys


def test_pcap_generation_creates_manifest(tmp_path):
    out_dir = tmp_path / "pcaps"
    subprocess.run([sys.executable, "scripts/generate_lab_pcaps.py", "--out", str(out_dir)], check=True)

    assert (out_dir / "manifest.json").exists()
    assert list(out_dir.glob("*.pcap"))
