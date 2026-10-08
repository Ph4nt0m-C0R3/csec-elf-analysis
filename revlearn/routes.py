"""Web routes, request controls, and safe error presentation."""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    g,
    jsonify,
    render_template,
    request,
    Response,
)
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, TooManyRequests

from .database import (
    get_analysis_record,
    get_completed_topics,
    get_learning_content,
    get_learning_map,
    save_analysis_record,
)
from .errors import AnalysisError, AnalysisTimeout, ValidationError
from .security import csrf_is_valid, csrf_token
from .services.controller import analyze
from .services.pdf_report import build_pdf_report
from .services.validation import store_and_validate

bp = Blueprint("main", __name__)
_REPORT_CACHE: dict[str, tuple[float, dict, int | None]] = {}
_REPORT_CACHE_LOCK = threading.Lock()
_REPORT_CACHE_TTL = 60 * 30
_REPORT_CACHE_LIMIT = 12


class MemoryRateLimiter:
    """Small single-process limiter suitable for the local classroom app."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        cutoff = now - window
        with self._lock:
            events = self._events[key]
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            return True


limiter = MemoryRateLimiter()


def _csrf_token() -> str:
    return csrf_token()


def _check_csrf() -> None:
    if not csrf_is_valid():
        raise ValidationError(
            "The form expired or failed its security check. Refresh and try again."
        )


@bp.get("/")
def index():
    return render_template(
        "index.html",
        csrf_token=_csrf_token(),
        max_upload_mb=current_app.config["MAX_CONTENT_LENGTH"]
        // (1024 * 1024),
    )


@bp.post("/analyze")
def analyze_upload():
    _check_csrf()
    _check_rate_limit()

    stored = None
    try:
        stored = store_and_validate(
            request.files.get("binary"),
            current_app.config["UPLOAD_DIR"],
            current_app.config["MAX_CONTENT_LENGTH"],
        )
        result = analyze(
            stored.path,
            stored.display_name,
            stored.size,
            current_app.config["ANALYSIS_TIMEOUT"],
            current_app.config["MAX_STRINGS"],
            get_learning_map(),
            max_instructions=current_app.config["MAX_INSTRUCTIONS"],
        )
        _remember_report(result)
        saved_to_history = _save_student_report(result)
        return render_template(
            "result.html", result=result, saved_to_history=saved_to_history
        )
    finally:
        if stored is not None:
            Path(stored.path).unlink(missing_ok=True)


@bp.get("/compare")
def compare_form():
    return render_template(
        "compare.html",
        csrf_token=_csrf_token(),
        max_upload_mb=current_app.config["MAX_CONTENT_LENGTH"]
        // (1024 * 1024),
    )


@bp.post("/compare")
def compare_uploads():
    _check_csrf()
    _check_rate_limit()

    stored_files = []
    try:
        for field in ("binary_left", "binary_right"):
            stored_files.append(
                store_and_validate(
                    request.files.get(field),
                    current_app.config["UPLOAD_DIR"],
                    current_app.config["MAX_CONTENT_LENGTH"],
                )
            )
        learning = get_learning_map()
        left = analyze(
            stored_files[0].path,
            stored_files[0].display_name,
            stored_files[0].size,
            current_app.config["ANALYSIS_TIMEOUT"],
            current_app.config["MAX_STRINGS"],
            learning,
            max_instructions=current_app.config["MAX_INSTRUCTIONS"],
        )
        right = analyze(
            stored_files[1].path,
            stored_files[1].display_name,
            stored_files[1].size,
            current_app.config["ANALYSIS_TIMEOUT"],
            current_app.config["MAX_STRINGS"],
            learning,
            max_instructions=current_app.config["MAX_INSTRUCTIONS"],
        )
        for result in (left, right):
            _remember_report(result)
            _save_student_report(result)
        comparison = _compare_results(left, right)
        return render_template(
            "compare_result.html",
            left=left,
            right=right,
            comparison=comparison,
        )
    finally:
        for stored in stored_files:
            Path(stored.path).unlink(missing_ok=True)


@bp.get("/reports/<analysis_id>.pdf")
def report_pdf(analysis_id: str):
    result = _recall_report(analysis_id)
    if result is None:
        raise ValidationError(
            "The report is no longer available for PDF export. Analyze the file again."
        )
    pdf = build_pdf_report(result)
    filename = _safe_download_name(result["filename"])
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.pdf"',
            "Cache-Control": "no-store",
        },
    )


@bp.get("/learning")
def learning():
    return render_template(
        "learning.html", topics=get_learning_content()
    )


@bp.get("/learning/<topic>")
def learning_detail(topic: str):
    topics = get_learning_content()
    topic_index = next(
        (index for index, item in enumerate(topics) if item["topic"] == topic),
        None,
    )
    if topic_index is None:
        return not_found(None)
    user = g.get("user")
    completed = bool(
        user is not None
        and user["role"] == "student"
        and topic in get_completed_topics(user["user_id"])
    )
    return render_template(
        "learning_detail.html",
        topic=topics[topic_index],
        previous_topic=topics[topic_index - 1] if topic_index > 0 else None,
        next_topic=(
            topics[topic_index + 1]
            if topic_index + 1 < len(topics)
            else None
        ),
        completed=completed,
        topic_position=topic_index + 1,
        topic_total=len(topics),
    )


@bp.get("/healthz")
def health():
    return jsonify({"status": "ok"})


def _check_rate_limit() -> None:
    client = request.remote_addr or "local"
    if not limiter.allow(
        client,
        current_app.config["RATE_LIMIT"],
        current_app.config["RATE_WINDOW"],
    ):
        raise TooManyRequests(
            "Too many upload attempts. Wait briefly before trying again."
        )


def _remember_report(result: dict) -> None:
    now = time.monotonic()
    user = g.get("user")
    owner_user_id = user["user_id"] if user is not None else None
    with _REPORT_CACHE_LOCK:
        _REPORT_CACHE[result["analysis_id"]] = (
            now, result, owner_user_id
        )
        _prune_report_cache(now)


def forget_report(analysis_id: str) -> None:
    """Remove a deleted persistent report from the short-lived PDF cache."""
    with _REPORT_CACHE_LOCK:
        _REPORT_CACHE.pop(analysis_id, None)


def _save_student_report(result: dict) -> bool:
    user = g.get("user")
    if user is None or user["role"] != "student":
        return False
    save_analysis_record(user["user_id"], result)
    return True


def _recall_report(analysis_id: str) -> dict | None:
    now = time.monotonic()
    with _REPORT_CACHE_LOCK:
        _prune_report_cache(now)
        item = _REPORT_CACHE.get(analysis_id)
    user = g.get("user")
    if item is not None:
        owner_user_id = item[2]
        if owner_user_id is None or (
            user is not None and user["user_id"] == owner_user_id
        ):
            return item[1]
    if user is not None and user["role"] == "student":
        record = get_analysis_record(user["user_id"], analysis_id)
        return record["result"] if record else None
    return None


def _prune_report_cache(now: float) -> None:
    expired = [
        key
        for key, (created, _result, _owner_user_id) in _REPORT_CACHE.items()
        if now - created > _REPORT_CACHE_TTL
    ]
    for key in expired:
        _REPORT_CACHE.pop(key, None)
    while len(_REPORT_CACHE) > _REPORT_CACHE_LIMIT:
        oldest = min(_REPORT_CACHE, key=lambda key: _REPORT_CACHE[key][0])
        _REPORT_CACHE.pop(oldest, None)


def _safe_download_name(filename: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", filename).strip("._")
    return (stem or "analysis-report")[:80]


def _compare_results(left: dict, right: dict) -> dict:
    protection_rows = []
    for key in left["protections"]:
        protection_rows.append(
            {
                "key": key,
                "label": "RPATH / RUNPATH" if key == "rpath" else key.upper(),
                "left": left["protections"][key],
                "right": right["protections"][key],
                "changed": (
                    left["protections"][key]["status"]
                    != right["protections"][key]["status"]
                ),
            }
        )
    left_imports = set(left["functions"]["imports"])
    right_imports = set(right["functions"]["imports"])
    return {
        "protection_rows": protection_rows,
        "security_delta": (
            right["risk_summary"]["score"] - left["risk_summary"]["score"]
        ),
        "shared_imports": sorted(left_imports & right_imports)[:80],
        "left_only_imports": sorted(left_imports - right_imports)[:80],
        "right_only_imports": sorted(right_imports - left_imports)[:80],
        "left_warning_count": len(left["functions"]["warnings"]),
        "right_warning_count": len(right["functions"]["warnings"]),
    }


@bp.app_errorhandler(ValidationError)
def handle_validation(error):
    return (
        render_template(
            "error.html",
            title="File not accepted",
            message=str(error),
            guidance="Return to the upload page and choose a valid ELF executable.",
        ),
        400,
    )


@bp.app_errorhandler(AnalysisTimeout)
def handle_timeout(error):
    return (
        render_template(
            "error.html",
            title="Analysis timed out",
            message=str(error),
            guidance="Try a smaller, normal classroom ELF sample.",
        ),
        408,
    )


@bp.app_errorhandler(AnalysisError)
def handle_analysis(error):
    current_app.logger.warning("Analysis failed: %s", error)
    return (
        render_template(
            "error.html",
            title="Analysis could not be completed",
            message=str(error),
            guidance="Confirm the ELF file is complete and try another sample.",
        ),
        422,
    )


@bp.app_errorhandler(RequestEntityTooLarge)
def handle_large(_error):
    maximum = current_app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
    return (
        render_template(
            "error.html",
            title="File is too large",
            message=f"The upload limit is {maximum} MiB.",
            guidance="Choose a smaller educational ELF sample.",
        ),
        413,
    )


@bp.app_errorhandler(TooManyRequests)
def handle_rate(error):
    return (
        render_template(
            "error.html",
            title="Please wait",
            message=error.description,
            guidance="The local rate limit protects server resources.",
        ),
        429,
        {"Retry-After": str(current_app.config["RATE_WINDOW"])},
    )


@bp.app_errorhandler(BadRequest)
def handle_bad_request(_error):
    return (
        render_template(
            "error.html",
            title="Invalid request",
            message="The upload request was incomplete or malformed.",
            guidance="Refresh the upload page and try again.",
        ),
        400,
    )


@bp.app_errorhandler(404)
def not_found(_error):
    return (
        render_template(
            "error.html",
            title="Page not found",
            message="The requested page does not exist.",
            guidance="Use the navigation to return to the analyzer.",
        ),
        404,
    )


@bp.app_errorhandler(403)
def forbidden(_error):
    return (
        render_template(
            "error.html",
            title="Access denied",
            message="Your account does not have permission to open this page.",
            guidance="Return to the analyzer or sign in with an approved role.",
        ),
        403,
    )


@bp.app_errorhandler(500)
def internal_error(error):
    current_app.logger.error("Unexpected server error: %s", error)
    return (
        render_template(
            "error.html",
            title="Unexpected error",
            message="The server could not complete this request.",
            guidance="No uploaded file was intentionally executed. Try again.",
        ),
        500,
    )
