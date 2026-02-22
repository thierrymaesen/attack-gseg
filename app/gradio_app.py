"""Gradio frontend for the ATT&CK Ground Segment Threat Graph API.

This application provides a web interface for mapping security events
and log lines to MITRE ATT&CK techniques.  All processing is delegated
to the FastAPI backend (Sprint 5); this module only handles presentation.

Usage:
    poetry run python app/gradio_app.py
    """
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import gradio as gr
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_URL: str = "http://localhost:8000"
REQUEST_TIMEOUT: int = 30

logging.basicConfig(
      level=logging.INFO,
      format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
      datefmt="%H:%M:%S",
)
logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# API communication
# ---------------------------------------------------------------------------


def check_api_health() -> bool:
    """Check whether the FastAPI backend is reachable.

        Returns:
            True if the ``/health`` endpoint responds with a 200 status.
    """
    try:
        resp: requests.Response = requests.get(
            f"{API_URL}/health", timeout=5
        )
        return resp.status_code == 200
    except requests.ConnectionError:
        return False
    except Exception:
        return False


def query_api(
    text: str, top_k: int, show_mitigations: bool
) -> Tuple[List[Dict[str, Any]], float]:
    """Send a search request to the FastAPI backend.

        Args:
            text: Security event description or log line.
            top_k: Number of top techniques to retrieve.
            show_mitigations: Whether to include mitigations in the response.

        Returns:
            Tuple of ``(results_list, latency_ms)``.  On error the results
            list contains a single dict with an ``"error"`` key.
    """
    payload: Dict[str, Any] = {
        "text": text,
        "top_k": top_k,
        "include_mitigations": show_mitigations,
    }

    try:
        resp: requests.Response = requests.post(
            f"{API_URL}/map_event",
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data: Dict[str, Any] = resp.json()
        logger.info(
            "API returned %d results in %.1f ms",
            len(data.get("results", [])),
            data.get("latency_ms", 0.0),
        )
        return data.get("results", []), data.get("latency_ms", 0.0)

    except requests.ConnectionError:
        logger.error("API is unreachable at %s", API_URL)
        return [{"error": f"API is unreachable at {API_URL}. Is the server running?"}], 0.0

    except requests.HTTPError as exc:
        logger.error("API returned HTTP error: %s", exc)
        return [{"error": f"API error: {exc}"}], 0.0

    except requests.Timeout:
        logger.error("API request timed out after %d s", REQUEST_TIMEOUT)
        return [{"error": "Request timed out. The server may be overloaded."}], 0.0

    except Exception as exc:
        logger.exception("Unexpected error calling API: %s", exc)
        return [{"error": f"Unexpected error: {exc}"}], 0.0


# ---------------------------------------------------------------------------
# Result formatting
# ---------------------------------------------------------------------------


def format_results(
    results: List[Dict[str, Any]], latency_ms: float
) -> str:
    """Convert API results into formatted Markdown for display.

        Args:
            results: List of technique dicts from the API response.
            latency_ms: Pipeline latency reported by the API.

        Returns:
            Markdown-formatted string ready for a ``gr.Markdown`` component.
    """
    if not results:
        return "*No matching techniques found.*"

    # --- handle error dicts ---
    if len(results) == 1 and "error" in results[0]:
        return f"**Error:** {results[0]['error']}"

    lines: List[str] = []
    lines.append(f"**Found {len(results)} technique(s)** — pipeline latency: {latency_ms:.0f} ms\n")

    for i, tech in enumerate(results, start=1):
        rerank: float = tech.get("rerank_score", 0.0)
        bm25: float = tech.get("bm25_score", 0.0)
        tid: str = tech.get("technique_id", "?")
        name: str = tech.get("name", "Unknown")
        url: Optional[str] = tech.get("url")
        tactics: List[str] = tech.get("tactics", [])

        # --- header ---
        title: str = f"[{tid}]({url})" if url else tid
        lines.append(f"### {i}. {title} — {name}")
        lines.append(f"**Rerank score:** {rerank:.4f} | **BM25 score:** {bm25:.2f}\n")

        # --- tactics ---
        if tactics:
            formatted_tactics: str = ", ".join(
                t.replace("-", " ").title() for t in tactics
            )
            lines.append(f"**Tactics:** {formatted_tactics}\n")

        # --- mitigations ---
        mitigations: Optional[List[Dict[str, Any]]] = tech.get("mitigations")
        if mitigations:
            lines.append("**Recommended mitigations:**\n")
            for m in mitigations:
                mid: str = m.get("mitigation_id", "?")
                mname: str = m.get("name", "Unknown")
                murl: Optional[str] = m.get("url")
                if murl:
                    lines.append(f"- [{mid}]({murl}) — {mname}")
                else:
                    lines.append(f"- **{mid}** — {mname}")
            lines.append("")

        lines.append("---\n")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Gradio callback
# ---------------------------------------------------------------------------


def analyze_threat(
    text: str, top_k: int, show_mitigations: bool
) -> Tuple[str, str]:
    """Main callback wired to the Analyze button.

        Args:
            text: User-provided event description.
            top_k: Number of results requested.
            show_mitigations: Whether to include mitigations.

        Returns:
            Tuple of ``(markdown_output, raw_json_output)``.
    """
    if not text or len(text.strip()) < 3:
        return "*Please enter at least 3 characters.*", "{}"

    results, latency_ms = query_api(text.strip(), int(top_k), show_mitigations)
    markdown: str = format_results(results, latency_ms)
    raw_json: str = json.dumps(results, indent=2, default=str)
    return markdown, raw_json


# ---------------------------------------------------------------------------
# Gradio interface
# ---------------------------------------------------------------------------

HEADER_MD: str = """
# ATT&CK Ground Segment Threat Graph

Map security events and log lines from space ground segment operations
to **MITRE ATT&CK techniques** using BM25 retrieval and semantic reranking.

Enter a security event description below and click **Analyze Threat**.
"""

FOOTER_MD: str = """
---
*Powered by [MITRE ATT&CK](https://attack.mitre.org/) — BM25 + Semantic Search
— [GitHub](https://github.com/thierrymaesen/attack-gseg)*
"""

with gr.Blocks(
    theme=gr.themes.Soft(),
    title="ATT&CK Ground Segment Threat Graph",
) as demo:

    gr.Markdown(HEADER_MD)

    with gr.Row():
        with gr.Column(scale=3):
            txt_input = gr.Textbox(
                label="Security Event Description",
                placeholder=(
                    "Describe the security event or paste a log line...\n"
                    "e.g. 'Unauthorized SSH access from unknown IP "
                    "attempting lateral movement to ground station controller'"
                ),
                lines=4,
            )
        with gr.Column(scale=1):
            slider_top_k = gr.Slider(
                label="Top K Results",
                minimum=1,
                maximum=10,
                value=3,
                step=1,
            )
            chk_mitigations = gr.Checkbox(
                label="Show Mitigations",
                value=True,
            )
            btn_analyze = gr.Button(
                value="Analyze Threat",
                variant="primary",
            )

    with gr.Row():
        md_output = gr.Markdown(
            label="Analysis Results",
            value="*Results will appear here after analysis.*",
        )

    with gr.Accordion("Raw API Response (debug)", open=False):
        json_output = gr.Code(
            label="Raw JSON",
            language="json",
            value="{}",
        )

    gr.Markdown(FOOTER_MD)

    # --- event wiring ---
    btn_analyze.click(
        fn=analyze_threat,
        inputs=[txt_input, slider_top_k, chk_mitigations],
        outputs=[md_output, json_output],
    )
    txt_input.submit(
        fn=analyze_threat,
        inputs=[txt_input, slider_top_k, chk_mitigations],
        outputs=[md_output, json_output],
    )


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------


def main() -> None:
    """Launch the Gradio application."""
    logger.info("Starting Gradio frontend on http://0.0.0.0:7860")
    demo.launch(server_name="0.0.0.0", server_port=7860)


if __name__ == "__main__":
    main()
