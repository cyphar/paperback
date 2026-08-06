import random
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target" / "release" / "paperback"


class QrCodes:
    def __init__(self, pdf: Path):
        result = subprocess.run(
            ["zbarimg", "--quiet", str(pdf)],
            capture_output=True,
            text=True,
            check=True,
        )
        payloads = [
            line.removeprefix("QR-Code:")
            for line in result.stdout.splitlines()
            if line.startswith("QR-Code:")
        ]
        assert len(payloads) == 2, f"expected 2 QR codes in {pdf.name}, got {len(payloads)}"
        self.checksum, self.data = sorted(payloads, key=len)


def test_backup(tmp_path):
    secret = str(random.randint(0, 2**64))
    (tmp_path / "backup.txt").write_text(secret)

    subprocess.run(
        [str(BINARY), "backup", "--quorum-size", "1", "--shards", "1", "backup.txt"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )

    main_documents = list(tmp_path.glob("main_document-*.pdf"))
    assert len(main_documents) == 1
    main_id = re.fullmatch(r"main_document-(\w+)\.pdf", main_documents[0].name).group(1)

    key_shards = list(tmp_path.glob(f"key_shard-{main_id}-*.pdf"))
    assert len(key_shards) == 1
    assert re.fullmatch(rf"key_shard-{main_id}-\w+\.pdf", key_shards[0].name)

    main_qr = QrCodes(main_documents[0])
    shard_qr = QrCodes(key_shards[0])
    print(f"main document checksum: {main_qr.checksum}")
    print(f"main document data: {main_qr.data}")
    print(f"key shard checksum: {shard_qr.checksum}")
    print(f"key shard data: {shard_qr.data}")

    codewords = subprocess.run(
        ["pdftotext", "-x", "140", "-y", "495", "-W", "270", "-H", "90", str(key_shards[0]), "-"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    print(f"key shard codewords: {codewords}")

    recover = subprocess.Popen(
        [str(BINARY), "recover", "--interactive", "restore.txt"],
        cwd=tmp_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    for answer in (main_qr.data, shard_qr.data, codewords):
        recover.stdin.write(answer + "\n\n")
        recover.stdin.flush()
        time.sleep(2)
    output, _ = recover.communicate(timeout=30)
    print(output)
    assert recover.returncode == 0, f"recover failed: {output}"
    assert (tmp_path / "restore.txt").read_text() == secret
