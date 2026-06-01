"""
DEPRECATED — Cloud Workflow HTTP stubs (implementation module).

Terraform may still reference workflow/*.py entry points; each delegates to handle_event().
"""

from __future__ import annotations

import json
import logging

import functions_framework

from ..handlers import handle_event

logger = logging.getLogger("gcp-soar.workflow.deprecated")


def _delegate(request):
    body = request.get_json(silent=True) or {}
    logger.warning("Legacy workflow HTTP endpoint invoked — delegating to unified pipeline")
    result = handle_event(body)
    status = result.get("statusCode", 200)
    return json.dumps(result.get("body", result)), status


@functions_framework.http
def isolate_instance(request):
    return _delegate(request)


@functions_framework.http
def create_snapshot(request):
    return _delegate(request)


@functions_framework.http
def terminate_instance(request):
    return _delegate(request)


@functions_framework.http
def detect_severity(request):
    return _delegate(request)
