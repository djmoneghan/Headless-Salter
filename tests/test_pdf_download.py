"""
Tests for the download_pdf pipeline (web_sterilizer v0.2).

Coverage per PDF_DOWNLOAD_PLAN.md test requirements:
- allow_pdf_download=false → immediate rejection, no file written
- Unlisted domain → rejected
- SSRF address → rejected
- Non-PDF Content-Type → aborted, no file written
- Valid PDF response → file written, path returned, file_size_bytes correct
- Response exceeds max_response_bytes → aborted, no file written
- pdf_download_dir does not exist → creates it; non-writable → fails closed
- Generated filenames are unique across consecutive calls
- Agent cannot influence filename (URL path not used)
- purpose appears in audit_log
- Exception in pipeline → success=False, file_path=""
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import web_sterilizer as ws

# Minimal valid PDF bytes (PDF 1.0 header — enough to be a real file)
_FAKE_PDF = b"%PDF-1.4 fake pdf content for testing purposes"


def _pdf_config(
    allowed_domains=None,
    allow_pdf_download=True,
    pdf_download_dir=None,
    max_response_bytes=2097152,
    max_redirects=3,
    timeout_seconds=10,
    tmp_dir=None,
):
    download_dir = pdf_download_dir or tmp_dir or tempfile.mkdtemp()
    return {
        "allowed_domains": allowed_domains if allowed_domains is not None else ["example.com"],
        "max_redirects": max_redirects,
        "timeout_seconds": timeout_seconds,
        "max_response_bytes": max_response_bytes,
        "max_output_chars": 8000,
        "pattern_file": "patterns.json",
        "verbose_logging": False,
        "allow_pdf_download": allow_pdf_download,
        "pdf_download_dir": download_dir,
    }


def _make_pdf_response(content: bytes, url: str, content_type: str = "application/pdf"):
    mock_resp = MagicMock()
    mock_resp.url = url
    mock_resp.headers = {"Content-Type": content_type}
    mock_resp.raw.read = MagicMock(return_value=content)
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


def _run_pipeline(url, response_bytes=None, content_type="application/pdf",
                  config_kwargs=None, tmp_dir=None):
    config_kwargs = config_kwargs or {}
    cfg = _pdf_config(tmp_dir=tmp_dir, **config_kwargs)

    mock_resp = _make_pdf_response(
        response_bytes if response_bytes is not None else _FAKE_PDF,
        url,
        content_type,
    )

    with patch("web_sterilizer.socket.getaddrinfo") as mock_dns, \
         patch("web_sterilizer.requests.Session") as mock_session_cls:
        mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session
        mock_session.get.return_value = mock_resp
        result = ws.run_pdf_download_pipeline(url, "test", cfg)

    return result


# ---------------------------------------------------------------------------
# Feature Flag
# ---------------------------------------------------------------------------

class TestPdfFeatureFlag(unittest.TestCase):

    def test_disabled_by_default_rejects_immediately(self):
        cfg = _pdf_config(allow_pdf_download=False)
        with patch("web_sterilizer.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
            result = ws.run_pdf_download_pipeline("https://example.com/file.pdf", "test", cfg)
        self.assertFalse(result["success"])
        self.assertIn("disabled", result["error"].lower())
        self.assertEqual(result["file_path"], "")

    def test_disabled_does_not_write_any_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _pdf_config(allow_pdf_download=False, pdf_download_dir=tmp)
            with patch("web_sterilizer.socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
                ws.run_pdf_download_pipeline("https://example.com/file.pdf", "test", cfg)
            self.assertEqual(os.listdir(tmp), [])


# ---------------------------------------------------------------------------
# URL Validation (reused stages)
# ---------------------------------------------------------------------------

class TestPdfUrlValidation(unittest.TestCase):

    def test_unlisted_domain_rejected(self):
        cfg = _pdf_config(allowed_domains=["safe.com"])
        with patch("web_sterilizer.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("1.2.3.4", 0))]
            result = ws.run_pdf_download_pipeline("https://blocked.com/file.pdf", "test", cfg)
        self.assertFalse(result["success"])
        self.assertIn("allowlist", result["error"].lower())
        self.assertEqual(result["file_path"], "")

    def test_empty_allowlist_rejects_all(self):
        cfg = _pdf_config(allowed_domains=[])
        with patch("web_sterilizer.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
            result = ws.run_pdf_download_pipeline("https://example.com/file.pdf", "test", cfg)
        self.assertFalse(result["success"])
        self.assertEqual(result["file_path"], "")

    def test_ssrf_private_ip_rejected(self):
        cfg = _pdf_config(allowed_domains=["internal.example.com"])
        with patch("web_sterilizer.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("192.168.1.1", 0))]
            result = ws.run_pdf_download_pipeline(
                "https://internal.example.com/file.pdf", "test", cfg
            )
        self.assertFalse(result["success"])
        self.assertIn("SSRF", result["error"])
        self.assertEqual(result["file_path"], "")

    def test_ssrf_loopback_rejected(self):
        cfg = _pdf_config(allowed_domains=["example.com"])
        with patch("web_sterilizer.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("127.0.0.1", 0))]
            result = ws.run_pdf_download_pipeline("https://example.com/file.pdf", "test", cfg)
        self.assertFalse(result["success"])
        self.assertEqual(result["file_path"], "")

    def test_file_scheme_rejected(self):
        cfg = _pdf_config()
        with patch("web_sterilizer.socket.getaddrinfo"):
            result = ws.run_pdf_download_pipeline("file:///etc/passwd", "test", cfg)
        self.assertFalse(result["success"])
        self.assertEqual(result["file_path"], "")


# ---------------------------------------------------------------------------
# Content-Type Verification
# ---------------------------------------------------------------------------

class TestPdfContentTypeVerification(unittest.TestCase):

    def test_html_response_rejected_no_file_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/file.pdf",
                content_type="text/html; charset=utf-8",
                config_kwargs={"pdf_download_dir": tmp},
                tmp_dir=tmp,
            )
            self.assertFalse(result["success"])
            self.assertIn("Content-Type", result["error"])
            self.assertEqual(result["file_path"], "")
            self.assertEqual(os.listdir(tmp), [])  # no file written

    def test_json_response_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/file.pdf",
                content_type="application/json",
                config_kwargs={"pdf_download_dir": tmp},
                tmp_dir=tmp,
            )
            self.assertFalse(result["success"])
            self.assertEqual(os.listdir(tmp), [])

    def test_application_pdf_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/file.pdf",
                content_type="application/pdf",
                tmp_dir=tmp,
            )
            self.assertTrue(result["success"])

    def test_octet_stream_with_pdf_extension_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/report.pdf",
                content_type="application/octet-stream",
                tmp_dir=tmp,
            )
            self.assertTrue(result["success"])

    def test_octet_stream_without_pdf_extension_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/report",
                content_type="application/octet-stream",
                config_kwargs={"pdf_download_dir": tmp},
                tmp_dir=tmp,
            )
            self.assertFalse(result["success"])
            self.assertEqual(os.listdir(tmp), [])

    def test_content_type_with_charset_param_accepted(self):
        """Content-Type parameters (charset) must be stripped before comparison."""
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/file.pdf",
                content_type="application/pdf; charset=binary",
                tmp_dir=tmp,
            )
            self.assertTrue(result["success"])


# ---------------------------------------------------------------------------
# Successful Download
# ---------------------------------------------------------------------------

class TestPdfSuccessfulDownload(unittest.TestCase):

    def test_file_written_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            self.assertTrue(result["success"])
            self.assertTrue(os.path.isfile(result["file_path"]))

    def test_file_size_bytes_correct(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            self.assertTrue(result["success"])
            self.assertEqual(result["file_size_bytes"], len(_FAKE_PDF))
            self.assertEqual(os.path.getsize(result["file_path"]), len(_FAKE_PDF))

    def test_file_contents_match_response(self):
        pdf_data = b"%PDF-1.4 specific test content 12345"
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf",
                                   response_bytes=pdf_data, tmp_dir=tmp)
            self.assertTrue(result["success"])
            with open(result["file_path"], "rb") as f:
                self.assertEqual(f.read(), pdf_data)

    def test_response_dict_has_all_required_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            required = {"success", "file_path", "source_url", "fetch_timestamp",
                        "file_size_bytes", "audit_log", "error"}
            self.assertTrue(required.issubset(result.keys()))

    def test_file_path_is_absolute(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            self.assertTrue(result["success"])
            self.assertTrue(os.path.isabs(result["file_path"]))

    def test_file_has_pdf_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            self.assertTrue(result["success"])
            self.assertTrue(result["file_path"].endswith(".pdf"))

    def test_error_is_none_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            self.assertTrue(result["success"])
            self.assertIsNone(result["error"])


# ---------------------------------------------------------------------------
# Filename Generation
# ---------------------------------------------------------------------------

class TestPdfFilenameGeneration(unittest.TestCase):

    def test_filename_not_derived_from_url_path(self):
        """Agent-controlled URL path components must not appear in the filename."""
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/secret/path/report.pdf", tmp_dir=tmp)
            self.assertTrue(result["success"])
            filename = os.path.basename(result["file_path"])
            self.assertNotIn("secret", filename)
            self.assertNotIn("path", filename)
            self.assertNotIn("report", filename)

    def test_filename_not_derived_from_url_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/dl?name=../../etc/cron&token=abc", tmp_dir=tmp
            )
            self.assertTrue(result["success"])
            filename = os.path.basename(result["file_path"])
            self.assertNotIn("..", filename)
            self.assertNotIn("etc", filename)
            self.assertNotIn("cron", filename)

    def test_filenames_unique_across_consecutive_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            filenames = set()
            for _ in range(20):
                result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
                self.assertTrue(result["success"])
                filenames.add(os.path.basename(result["file_path"]))
            self.assertEqual(len(filenames), 20, "Duplicate filenames detected")

    def test_file_saved_inside_download_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            self.assertTrue(result["success"])
            self.assertTrue(result["file_path"].startswith(os.path.abspath(tmp)))


# ---------------------------------------------------------------------------
# Size Cap
# ---------------------------------------------------------------------------

class TestPdfSizeCap(unittest.TestCase):

    def test_oversized_response_aborted_no_file_written(self):
        max_bytes = 100
        big_pdf = b"%PDF " + b"A" * 500

        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/file.pdf",
                response_bytes=big_pdf,
                config_kwargs={"max_response_bytes": max_bytes, "pdf_download_dir": tmp},
                tmp_dir=tmp,
            )
            self.assertFalse(result["success"])
            self.assertIn("size", result["error"].lower())
            self.assertEqual(result["file_path"], "")
            self.assertEqual(os.listdir(tmp), [])  # no partial file

    def test_exactly_at_limit_accepted(self):
        """A response exactly at the byte cap must succeed."""
        max_bytes = len(_FAKE_PDF)
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/file.pdf",
                response_bytes=_FAKE_PDF,
                config_kwargs={"max_response_bytes": max_bytes, "pdf_download_dir": tmp},
                tmp_dir=tmp,
            )
            self.assertTrue(result["success"])


# ---------------------------------------------------------------------------
# Download Directory Handling
# ---------------------------------------------------------------------------

class TestPdfDownloadDir(unittest.TestCase):

    def test_nonexistent_dir_is_created(self):
        with tempfile.TemporaryDirectory() as base:
            new_dir = os.path.join(base, "new_subdir")
            self.assertFalse(os.path.exists(new_dir))
            result = _run_pipeline(
                "https://example.com/file.pdf",
                config_kwargs={"pdf_download_dir": new_dir},
                tmp_dir=new_dir,
            )
            self.assertTrue(result["success"])
            self.assertTrue(os.path.isdir(new_dir))


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------

class TestPdfAuditLog(unittest.TestCase):

    def test_audit_log_contains_required_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            log = result["audit_log"]
            for field in ("requested_url", "final_url", "fetch_timestamp",
                          "purpose", "file_size_bytes", "content_type", "generated_filename"):
                self.assertIn(field, log, f"Missing audit_log field: {field}")

    def test_purpose_logged_in_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _pdf_config(tmp_dir=tmp)
            mock_resp = _make_pdf_response(_FAKE_PDF, "https://example.com/file.pdf")
            with patch("web_sterilizer.socket.getaddrinfo") as mock_dns, \
                 patch("web_sterilizer.requests.Session") as mock_session_cls:
                mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
                mock_session = MagicMock()
                mock_session_cls.return_value = mock_session
                mock_session.get.return_value = mock_resp
                result = ws.run_pdf_download_pipeline(
                    "https://example.com/file.pdf", "downloading annual report", cfg
                )
            self.assertEqual(result["audit_log"]["purpose"], "downloading annual report")

    def test_audit_log_has_error_on_failure(self):
        cfg = _pdf_config(allowed_domains=[])
        with patch("web_sterilizer.socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
            result = ws.run_pdf_download_pipeline("https://example.com/file.pdf", "test", cfg)
        self.assertFalse(result["success"])
        self.assertIn("error", result["audit_log"])

    def test_generated_filename_in_audit_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline("https://example.com/file.pdf", tmp_dir=tmp)
            self.assertTrue(result["success"])
            filename_in_log = result["audit_log"]["generated_filename"]
            self.assertEqual(filename_in_log, os.path.basename(result["file_path"]))


# ---------------------------------------------------------------------------
# Fail-Closed
# ---------------------------------------------------------------------------

class TestPdfFailClosed(unittest.TestCase):

    def test_exception_in_pipeline_returns_fail_closed(self):
        cfg = _pdf_config()
        with patch("web_sterilizer.stage_validate_url", side_effect=RuntimeError("boom")):
            result = ws.run_pdf_download_pipeline("https://example.com/file.pdf", "test", cfg)
        self.assertFalse(result["success"])
        self.assertEqual(result["file_path"], "")
        self.assertIn("boom", result["error"])
        self.assertEqual(result["file_size_bytes"], 0)

    def test_no_file_written_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = _run_pipeline(
                "https://example.com/file.pdf",
                content_type="text/html",
                config_kwargs={"pdf_download_dir": tmp},
                tmp_dir=tmp,
            )
            self.assertFalse(result["success"])
            self.assertEqual(os.listdir(tmp), [])

    def test_too_many_redirects_fails_closed(self):
        import requests as req_lib
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _pdf_config(tmp_dir=tmp, max_redirects=2)
            with patch("web_sterilizer.socket.getaddrinfo") as mock_dns, \
                 patch("web_sterilizer.requests.Session") as mock_session_cls:
                mock_dns.return_value = [(None, None, None, None, ("93.184.216.34", 0))]
                mock_session = MagicMock()
                mock_session_cls.return_value = mock_session
                mock_session.get.side_effect = req_lib.TooManyRedirects()
                result = ws.run_pdf_download_pipeline("https://example.com/file.pdf", "test", cfg)
            self.assertFalse(result["success"])
            self.assertEqual(result["file_path"], "")
            self.assertEqual(os.listdir(tmp), [])


# ---------------------------------------------------------------------------
# stage_verify_pdf_content_type unit tests
# ---------------------------------------------------------------------------

class TestStageVerifyPdfContentType(unittest.TestCase):

    def test_application_pdf_accepted(self):
        ok, err = ws.stage_verify_pdf_content_type({"Content-Type": "application/pdf"}, "https://x.com/f.pdf")
        self.assertTrue(ok)

    def test_application_pdf_with_params_accepted(self):
        ok, err = ws.stage_verify_pdf_content_type(
            {"Content-Type": "application/pdf; charset=binary"}, "https://x.com/f.pdf"
        )
        self.assertTrue(ok)

    def test_octet_stream_pdf_url_accepted(self):
        ok, err = ws.stage_verify_pdf_content_type(
            {"Content-Type": "application/octet-stream"}, "https://x.com/doc.pdf"
        )
        self.assertTrue(ok)

    def test_octet_stream_non_pdf_url_rejected(self):
        ok, err = ws.stage_verify_pdf_content_type(
            {"Content-Type": "application/octet-stream"}, "https://x.com/doc"
        )
        self.assertFalse(ok)

    def test_text_html_rejected(self):
        ok, err = ws.stage_verify_pdf_content_type(
            {"Content-Type": "text/html"}, "https://x.com/f.pdf"
        )
        self.assertFalse(ok)

    def test_missing_content_type_rejected(self):
        ok, err = ws.stage_verify_pdf_content_type({}, "https://x.com/f.pdf")
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# stage_write_pdf unit tests
# ---------------------------------------------------------------------------

class TestStageWritePdf(unittest.TestCase):

    def test_writes_bytes_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, err = ws.stage_write_pdf(_FAKE_PDF, tmp, "2026-01-01T00:00:00+00:00")
            self.assertTrue(path)
            self.assertEqual(err, "")
            with open(path, "rb") as f:
                self.assertEqual(f.read(), _FAKE_PDF)

    def test_creates_directory_if_missing(self):
        with tempfile.TemporaryDirectory() as base:
            new_dir = os.path.join(base, "subdir")
            path, err = ws.stage_write_pdf(_FAKE_PDF, new_dir, "2026-01-01T00:00:00+00:00")
            self.assertTrue(path)
            self.assertTrue(os.path.isdir(new_dir))

    def test_filename_ends_with_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, err = ws.stage_write_pdf(_FAKE_PDF, tmp, "2026-01-01T00:00:00+00:00")
            self.assertTrue(path.endswith(".pdf"))

    def test_path_stays_inside_download_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, err = ws.stage_write_pdf(_FAKE_PDF, tmp, "2026-01-01T00:00:00+00:00")
            self.assertTrue(path.startswith(os.path.abspath(tmp)))


if __name__ == "__main__":
    unittest.main()
