"""Screenshot capture handler — mss → PIL → GDI fallback chain."""
from __future__ import annotations
import io
import sys


class ScreenshotHandler:
    """Capture the primary display as PNG bytes."""

    def capture(self) -> bytes:
        """Return raw PNG bytes of the current screen, or raise RuntimeError."""
        errors = []

        # Try mss first (fastest, cross-platform)
        try:
            return self._capture_mss()
        except Exception as exc:
            errors.append(f"mss: {exc}")

        # PIL / Pillow fallback
        try:
            return self._capture_pil()
        except Exception as exc:
            errors.append(f"PIL: {exc}")

        # Windows GDI via ctypes (no extra deps)
        if sys.platform == "win32":
            try:
                return self._capture_gdi()
            except Exception as exc:
                errors.append(f"GDI: {exc}")

        raise RuntimeError(f"No screenshot backend available. Tried: {'; '.join(errors)}")

    def _capture_mss(self) -> bytes:
        import mss
        import mss.tools
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            sshot   = sct.grab(monitor)
            buf     = mss.tools.to_png(sshot.rgb, sshot.size)
            if isinstance(buf, (bytes, bytearray)):
                return bytes(buf)
            # older mss versions write to file — use PNG encoder directly
            from PIL import Image
            img = Image.frombytes("RGB", sshot.size, sshot.rgb)
            out = io.BytesIO()
            img.save(out, format="PNG")
            return out.getvalue()

    def _capture_pil(self) -> bytes:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        out = io.BytesIO()
        img.save(out, format="PNG")
        return out.getvalue()

    def _capture_gdi(self) -> bytes:
        import ctypes
        import ctypes.wintypes as wt
        import struct

        gdi   = ctypes.windll.gdi32
        user  = ctypes.windll.user32

        hwnd   = user.GetDesktopWindow()
        hdc    = user.GetDC(hwnd)
        mdc    = gdi.CreateCompatibleDC(hdc)
        width  = user.GetSystemMetrics(0)
        height = user.GetSystemMetrics(1)
        hbmp   = gdi.CreateCompatibleBitmap(hdc, width, height)
        gdi.SelectObject(mdc, hbmp)
        gdi.BitBlt(mdc, 0, 0, width, height, hdc, 0, 0, 0x00CC0020)  # SRCCOPY

        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [
                ("biSize",          ctypes.c_uint32),
                ("biWidth",         ctypes.c_int32),
                ("biHeight",        ctypes.c_int32),
                ("biPlanes",        ctypes.c_uint16),
                ("biBitCount",      ctypes.c_uint16),
                ("biCompression",   ctypes.c_uint32),
                ("biSizeImage",     ctypes.c_uint32),
                ("biXPelsPerMeter", ctypes.c_int32),
                ("biYPelsPerMeter", ctypes.c_int32),
                ("biClrUsed",       ctypes.c_uint32),
                ("biClrImportant",  ctypes.c_uint32),
            ]

        bih             = BITMAPINFOHEADER()
        bih.biSize      = ctypes.sizeof(BITMAPINFOHEADER)
        bih.biWidth     = width
        bih.biHeight    = -height   # top-down
        bih.biPlanes    = 1
        bih.biBitCount  = 24
        bih.biCompression = 0

        row_bytes = ((width * 3 + 3) & ~3)
        buf_size  = row_bytes * height
        buf       = (ctypes.c_byte * buf_size)()
        gdi.GetDIBits(mdc, hbmp, 0, height, buf, ctypes.byref(bih), 0)

        gdi.DeleteObject(hbmp)
        gdi.DeleteDC(mdc)
        user.ReleaseDC(hwnd, hdc)

        # Encode raw BGR bytes as BMP then convert to PNG via PIL
        pixel_data = bytes(buf)
        bmp_header = struct.pack(
            "<2sIHHI",
            b"BM",
            54 + buf_size,
            0, 0,
            54,
        )
        dib_header = struct.pack(
            "<IiiHHIIiiII",
            40, width, -height, 1, 24, 0, buf_size, 0, 0, 0, 0,
        )
        bmp_bytes = bmp_header + dib_header + pixel_data

        try:
            from PIL import Image
            img = Image.open(io.BytesIO(bmp_bytes))
            out = io.BytesIO()
            img.save(out, format="PNG")
            return out.getvalue()
        except ImportError:
            # Return BMP if PIL not available
            return bmp_bytes
