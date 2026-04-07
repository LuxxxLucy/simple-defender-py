"""HTTP server for simple-defender.

Run with:
    uv run python -m simple_defender.server
    uv run python -m simple_defender.server --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import argparse
import time
from dataclasses import asdict

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .defender import Defender


def _create_app(defender: Defender | None = None) -> Starlette:
    """Create the Starlette application."""
    d = defender or Defender()

    async def health(request: Request) -> JSONResponse:
        return JSONResponse({
            "status": "ok",
            "tier1": d.tier1_enabled,
            "tier2": d.tier2_enabled,
            "model_loaded": d.model_loaded,
        })

    async def scan(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "Invalid JSON body"},
                status_code=400,
            )

        if not body:
            return JSONResponse(
                {"error": "Empty request body"},
                status_code=400,
            )

        # Accept either {"text": "..."} or {"value": {...}} or {"value": [...]}
        text = body.get("text")
        value = body.get("value")
        tool_name = body.get("tool_name")
        sanitize = body.get("sanitize", False)

        if text is None and value is None:
            return JSONResponse(
                {"error": "Request must include 'text' or 'value' field"},
                status_code=400,
            )

        scan_input = text if text is not None else value
        result = d.scan(scan_input, tool_name=tool_name, sanitize=sanitize)
        return JSONResponse(asdict(result))

    async def scan_batch(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"error": "Invalid JSON body"},
                status_code=400,
            )

        if not isinstance(body, dict) or "items" not in body:
            return JSONResponse(
                {"error": "Request must include 'items' field"},
                status_code=400,
            )

        items = body["items"]
        if not isinstance(items, list):
            return JSONResponse(
                {"error": "'items' must be a list"},
                status_code=400,
            )

        results = d.scan_batch(items)
        return JSONResponse({"results": [asdict(r) for r in results]})

    app = Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/scan", scan, methods=["POST"]),
            Route("/scan/batch", scan_batch, methods=["POST"]),
        ],
    )
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="simple-defender HTTP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-tier2", action="store_true", help="Disable ML classifier")
    args = parser.parse_args()

    defender = Defender(enable_tier2=not args.no_tier2)
    defender.warmup()
    app = _create_app(defender)

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
