"""Regression coverage for the browser inspector redaction policy."""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def inspector_probe() -> dict[str, str]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for inspector JavaScript regression coverage")

    script = textwrap.dedent(
        r"""
        const fs = require("fs");
        const vm = require("vm");

        const bootstrapSource = fs.readFileSync("xferry/data/static/ui/bootstrap.js", "utf8");
        const source = fs.readFileSync("xferry/data/static/ui/inspector.js", "utf8");
        const filesSummaryElements = {
          title: { textContent: "" },
          body: { textContent: "" },
          badge: { textContent: "", hidden: false, dataset: {} },
          meta: { innerHTML: "", hidden: false },
        };
        const filesSummaryRoot = {
          dataset: {
            toolSummaryIdleTitleKey: "filesResultIdleTitle",
            toolSummaryIdleBodyKey: "filesResultIdleBody",
          },
          querySelector: (selector) => ({
            "[data-tool-summary-title]": filesSummaryElements.title,
            "[data-tool-summary-body]": filesSummaryElements.body,
            "[data-tool-summary-badge]": filesSummaryElements.badge,
            "[data-tool-summary-meta]": filesSummaryElements.meta,
          })[selector] || null,
        };
        const context = {
          console,
          filesSummaryElements,
          localStorage: { getItem: () => "raw" },
          document: {
            addEventListener: () => {},
            getElementById: () => null,
            querySelector: (selector) => (
              selector === '[data-tool-summary-scope="files"]' ? filesSummaryRoot : null
            ),
            querySelectorAll: () => [],
          },
          t: (key) => ({
            exchangeRedacted: "REDACTED",
            exchangeRequestEmpty: "request empty",
            exchangeResponseEmpty: "response empty",
            requestPreviewNoBody: "no body",
            headersNA: "n/a",
            exchangeBodyKind: "Body kind",
            responseSummaryFieldContentType: "Content-Type",
            requestPreviewFieldBodySize: "Body size",
            exchangeBinaryBodyPreview: "Body preview",
            exchangeBinaryBodyPreviewPending: "Body preview pending",
            exchangeTruncated: "truncated",
            toolPhaseSuccess: "Done",
            requestPreviewFieldMethod: "Method",
            requestPreviewFieldPath: "Path",
            responseSummaryFieldStatus: "Status",
          })[key] || key,
          formatSize: (value) => `${value} B`,
          parseJsonSafe: (text) => {
            try {
              return JSON.parse(text);
            } catch (_error) {
              return null;
            }
          },
          esc: (value) => String(value),
          formatHttpStatusLabel: (status, text) => `${status} ${text || ""}`.trim(),
        };

        context.window = context;
        vm.createContext(context);
        vm.runInContext(bootstrapSource, context);
        vm.runInContext(`
          XferryApp.registerService("core", {
            t,
            escapeHtml: esc,
            formatSize,
            parseJsonSafe,
            formatHttpStatusLabel,
            formatActionErrorMessage: (base, error) => (
              error && error.message ? base + ": " + error.message : base
            ),
            writeTextToClipboard: async () => {},
            announceLiveRegion: () => {},
          });
        `, context);
        vm.runInContext(source, context);
        const result = vm.runInContext(`
          (() => {
            const inspector = XferryApp.service("inspector");
            const {
              buildRawMessage: buildExchangeRawMessage,
              buildRawMessageForExport: buildExchangeRawMessageForExport,
              createBinaryBody: createExchangeBinaryBody,
              createJsonBody: createExchangeJsonBody,
              createPreviewBody: createExchangePreviewBody,
              createTextBody: createExchangeTextBody,
              getAreaRawText: getExchangeAreaRawText,
              getInspectorState,
              renderPane: renderExchangePane,
              setInspector: setExchangeInspector,
            } = inspector;
            const advancedArea = {
              id: "opsecExchangeRequest",
              dataset: {},
              textContent: "",
              innerHTML: "",
            };
            const pathArea = {
              id: "pathExchangeRequest",
              dataset: {},
              textContent: "",
              innerHTML: "",
            };
            const advancedMessage = {
              transport: "http",
              method: "XUPLOAD",
              path: "/advanced/upload?data=url-payload&key=test-password" +
                "&key_is_base64=true&hmac=url-hmac&name=visible.txt",
              headers: {
                "X-XFerry-Advanced-Session": "session-bearer",
                "X-XFerry-Data": "header-payload",
                "X-XFerry-Data-0": "chunk-payload",
                "X-XFerry-Key": "test-password",
                "X-XFerry-Key-Is-Base64": "true",
                "X-XFerry-HMAC": "header-hmac",
                "X-XFerry-Name": "visible.txt",
              },
              body: createExchangeTextBody(
                JSON.stringify({
                  data: "body-payload",
                  key: "test-password",
                  key_is_base64: true,
                  hmac: "body-hmac",
                  name: "visible.txt",
                }),
                { contentType: "application/json" },
              ),
            };
            renderExchangePane(advancedArea, advancedMessage, "request");
            setExchangeInspector("opsec", {
              phase: "complete",
              request: advancedMessage,
              response: {
                transport: "http",
                method: "XUPLOAD",
                path: "/upload",
                body: createExchangeTextBody("ok"),
              },
            });

            const previewRaw = buildExchangeRawMessage({
              transport: "http",
              method: "XUPLOAD",
              path: "/headers",
              body: createExchangePreviewBody({
                label: "headers",
                text: "X-XFerry-Data-0: preview-payload" +
                  "\\nX-XFerry-Key: preview-password" +
                  "\\nX-XFerry-Name: preview.txt",
              }),
            }, "request");
            const advancedExportRaw = buildExchangeRawMessageForExport(advancedMessage, "request");
            const pathMessage = {
              transport: "http",
              method: "XUPLOAD",
              path: "/advanced/_payload/visible-path.txt/" +
                "c2VjcmV0LXByb2plY3QtcGF0aC1wYXlsb2Fk?encryption=none",
              headers: {},
            };
            renderExchangePane(pathArea, pathMessage, "request");
            setExchangeInspector("path", {
              phase: "ready",
              request: pathMessage,
              response: { phase: "empty" },
            });

            const transcriptRaw = buildExchangeRawMessage({
              rawText: [
                "XUPLOAD /advanced/raw?data=transcript-url-payload" +
                  "&key=transcript-password HTTP/1.1",
                "X-XFerry-Data-255: transcript-header-payload",
                "X-XFerry-Key: transcript-password",
                "",
                JSON.stringify({
                  data: "transcript-body-payload",
                  key: "transcript-password",
                  name: "transcript.txt",
                }),
              ].join("\\n"),
            }, "request");

            const notepadMessage = {
              transport: "ws",
              type: "save",
              path: "/notes/ws",
              body: createExchangeJsonBody(
                {
                  type: "save",
                  sessionId: "session-secret",
                  data: "ciphertext-secret",
                  clientPublicKey: "client-key-secret",
                  serverPublicKey: "server-key-secret",
                  title: "Visible title",
                },
                {
                  rawText: JSON.stringify({
                    type: "save",
                    sessionId: "session-secret",
                    data: "ciphertext-secret",
                    clientPublicKey: "client-key-secret",
                    serverPublicKey: "server-key-secret",
                    title: "Visible title",
                  }),
                },
              ),
            };
            const notepadRaw = buildExchangeRawMessage(notepadMessage, "request");
            const ordinaryUploadRaw = buildExchangeRawMessage({
              transport: "http",
              method: "POST",
              path: "/sample.txt",
              headers: {
                "Content-Type": "text/plain",
                "Content-Length": "650",
              },
              body: createExchangeBinaryBody({
                filename: "sample.txt",
                contentType: "text/plain",
                size: 650,
                bytes: Uint8Array.from(
                  ("payload-line\\n" + "A".repeat(638)).split("").map(char => char.charCodeAt(0)),
                ),
              }),
            }, "request");
            setExchangeInspector("notepad", {
              phase: "complete",
              request: notepadMessage,
              response: {
                transport: "ws",
                type: "saved",
                path: "/notes/ws",
                body: createExchangeJsonBody({ success: true }),
              },
            });
            setExchangeInspector("files", {
              phase: "complete",
              request: {
                transport: "http",
                method: "INFO",
                path: "/uploads",
              },
              response: {
                transport: "http",
                method: "INFO",
                path: "/uploads",
                phase: "complete",
                summaryText: "Listed /uploads",
                status: 200,
                statusText: "OK",
              },
            });

            return {
              advancedRaw: advancedArea.textContent,
              advancedCopyText: getExchangeAreaRawText("opsecExchangeRequest"),
              advancedDatasetPath: advancedArea.dataset.exchangePath,
              advancedStoredState: JSON.stringify(getInspectorState("opsec")),
              previewRaw,
              advancedExportRaw,
              pathRaw: pathArea.textContent,
              pathCopyText: getExchangeAreaRawText("pathExchangeRequest"),
              pathDatasetPath: pathArea.dataset.exchangePath,
              pathStoredState: JSON.stringify(getInspectorState("path")),
              pathExportRaw: buildExchangeRawMessageForExport(pathMessage, "request"),
              transcriptRaw,
              notepadRaw,
              notepadStoredState: JSON.stringify(getInspectorState("notepad")),
              ordinaryUploadRaw,
              filesSummaryTitle: filesSummaryElements.title.textContent,
              filesSummaryBody: filesSummaryElements.body.textContent,
              filesSummaryBadge: filesSummaryElements.badge.textContent,
              filesSummaryMeta: filesSummaryElements.meta.innerHTML,
            };
          })()
        `, context);

        console.log(JSON.stringify(result));
        """
    )
    result = subprocess.run(
        [node, "-e", script],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(
            f"inspector JS probe failed\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    return json.loads(result.stdout)


def test_inspector_redacts_advanced_upload_raw_and_copy_output(
    inspector_probe: dict[str, str],
) -> None:
    combined = "\n".join(
        [
            inspector_probe["advancedRaw"],
            inspector_probe["advancedCopyText"],
            inspector_probe["advancedDatasetPath"],
            inspector_probe["advancedStoredState"],
            inspector_probe["previewRaw"],
            inspector_probe["transcriptRaw"],
        ]
    )

    for secret in (
        "test-password",
        "url-payload",
        "header-payload",
        "chunk-payload",
        "named-chunk-payload",
        "body-payload",
        "preview-payload",
        "preview-password",
        "transcript-password",
        "transcript-url-payload",
        "transcript-header-payload",
        "transcript-body-payload",
        "session-bearer",
        "url-hmac",
        "header-hmac",
        "body-hmac",
    ):
        assert secret not in combined

    assert inspector_probe["advancedRaw"] == inspector_probe["advancedCopyText"]
    assert "[REDACTED]" in combined
    assert "visible.txt" in combined
    assert "preview.txt" in combined


def test_inspector_export_builder_redacts_advanced_request_values(
    inspector_probe: dict[str, str],
) -> None:
    export_raw = inspector_probe["advancedExportRaw"]

    for secret in (
        "url-payload",
        "header-payload",
        "chunk-payload",
        "body-payload",
        "test-password",
        "session-bearer",
        "url-hmac",
        "header-hmac",
        "body-hmac",
    ):
        assert secret not in export_raw

    assert "[REDACTED]" in export_raw
    assert "visible.txt" in export_raw


def test_inspector_redacts_canonical_path_payload_in_every_output(
    inspector_probe: dict[str, str],
) -> None:
    """Catches leaving the reserved path carrier data segment unredacted."""
    sentinel = "c2VjcmV0LXByb2plY3QtcGF0aC1wYXlsb2Fk"
    combined = "\n".join(
        [
            inspector_probe["pathRaw"],
            inspector_probe["pathCopyText"],
            inspector_probe["pathDatasetPath"],
            inspector_probe["pathStoredState"],
            inspector_probe["pathExportRaw"],
        ]
    )

    assert sentinel not in combined
    assert "visible-path.txt" in combined
    assert "[REDACTED]" in combined


def test_inspector_redacts_notepad_session_key_and_data_fields_but_keeps_title_visible(
    inspector_probe: dict[str, str],
) -> None:
    notepad_raw = inspector_probe["notepadRaw"]
    notepad_state = inspector_probe["notepadStoredState"]

    for secret in (
        "session-secret",
        "ciphertext-secret",
        "client-key-secret",
        "server-key-secret",
    ):
        assert secret not in notepad_raw
        assert secret not in notepad_state

    assert "[REDACTED]" in notepad_raw
    assert "[REDACTED]" in notepad_state
    assert "Visible title" in notepad_raw
    assert "Visible title" in notepad_state


def test_ordinary_upload_raw_request_keeps_truncated_body_preview(
    inspector_probe: dict[str, str],
) -> None:
    upload_raw = inspector_probe["ordinaryUploadRaw"]

    assert "POST /sample.txt HTTP/1.1" in upload_raw
    assert "Content-Length: 650" in upload_raw
    assert "payload-line" in upload_raw
    assert "AAAA" in upload_raw
    assert "... truncated" in upload_raw


def test_tool_summary_updates_without_exchange_inspector_root(
    inspector_probe: dict[str, str],
) -> None:
    assert inspector_probe["filesSummaryTitle"] == "Done"
    assert inspector_probe["filesSummaryBody"] == "Listed /uploads"
    assert inspector_probe["filesSummaryBadge"] == "Done"
    assert "INFO" in inspector_probe["filesSummaryMeta"]
    assert "/uploads" in inspector_probe["filesSummaryMeta"]
    assert "200 OK" in inspector_probe["filesSummaryMeta"]
