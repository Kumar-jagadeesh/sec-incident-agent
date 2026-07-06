# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os


def setup_telemetry() -> str | None:
    """Configure GenAI prompt/response logging via OpenTelemetry."""

    # Keep full prompts/responses out of trace span attributes.
    os.environ.setdefault("ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS", "false")

    # Enable telemetry by default.
    os.environ.setdefault("GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY", "true")

    bucket = os.environ.get("LOGS_BUCKET_NAME")
    capture_content = os.environ.get(
        "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT",
        "false",
    )

    if bucket and capture_content != "false":
        logging.info(
            "Prompt-response logging enabled - metadata only."
        )

        os.environ["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"] = "NO_CONTENT"
        os.environ.setdefault("OTEL_INSTRUMENTATION_GENAI_UPLOAD_FORMAT", "jsonl")
        os.environ.setdefault("OTEL_INSTRUMENTATION_GENAI_COMPLETION_HOOK", "upload")
        os.environ.setdefault(
            "OTEL_SEMCONV_STABILITY_OPT_IN",
            "gen_ai_latest_experimental",
        )

        commit_sha = os.environ.get("COMMIT_SHA", "dev")

        os.environ.setdefault(
            "OTEL_RESOURCE_ATTRIBUTES",
            f"service.namespace=sec-incident-agent,service.version={commit_sha}",
        )

        path = os.environ.get("GENAI_TELEMETRY_PATH", "completions")

        os.environ.setdefault(
            "OTEL_INSTRUMENTATION_GENAI_UPLOAD_BASE_PATH",
            f"gs://{bucket}/{path}",
        )

    else:
        logging.info(
            "Prompt-response logging disabled."
        )

    return bucket


def setup_agent_engine_telemetry() -> None:
    """
    Install Agent Engine telemetry.

    On Render or other non-Google environments there are no
    Application Default Credentials (ADC), so telemetry is skipped
    instead of crashing the application.
    """

    telemetry_enabled = os.environ.get(
        "GOOGLE_CLOUD_AGENT_ENGINE_ENABLE_TELEMETRY",
        "",
    ).lower() in ("true", "1")

    integration_test = (
        os.environ.get("INTEGRATION_TEST", "").lower() == "true"
    )

    if not telemetry_enabled or integration_test:
        logging.info("Telemetry disabled.")
        return

    try:
        import google.auth
        from google.auth.exceptions import DefaultCredentialsError
        from vertexai.agent_engines.templates.adk import (
            _default_instrumentor_builder,
        )

        try:
            _, project_id = google.auth.default()

            _default_instrumentor_builder(
                project_id,
                enable_tracing=True,
                enable_logging=True,
            )

            logging.info(
                "Agent Engine telemetry initialized successfully."
            )

        except DefaultCredentialsError:
            logging.warning(
                "Google Cloud ADC credentials not found. "
                "Skipping Agent Engine telemetry."
            )

    except Exception as exc:
        logging.warning(
            "Telemetry initialization skipped: %s",
            exc,
        )