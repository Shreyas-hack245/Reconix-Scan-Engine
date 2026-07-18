"""
OpenAPI / Swagger discovery and parsing for Reconix Scan Engine.

If a target application publishes an OpenAPI/Swagger specification,
importing it gives Reconix Scan Engine a precise, authoritative list of
API endpoints, methods, and parameters -- far more reliable than
inference from crawling alone.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from app.core.logging_config import logger
from app.core.rate_limiter import RateLimiter
from app.utils.http_client import safe_request

COMMON_OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/.well-known/openapi.json",
)

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


@dataclass
class OpenApiEndpoint:
    """An endpoint discovered from an OpenAPI/Swagger specification."""

    path: str
    method: str
    parameters: list[str] = field(default_factory=list)
    summary: str = ""


def _extract_parameters(operation: dict) -> list[str]:
    params: list[str] = []
    for param in operation.get("parameters", []) or []:
        name = param.get("name")
        if name:
            params.append(name)

    request_body = operation.get("requestBody", {}) or {}
    content = request_body.get("content", {}) or {}
    for media in content.values():
        schema = media.get("schema", {}) or {}
        for prop_name in (schema.get("properties") or {}).keys():
            params.append(prop_name)

    return params


def _parse_spec_document(spec: dict) -> list[OpenApiEndpoint]:
    endpoints: list[OpenApiEndpoint] = []
    paths = spec.get("paths", {}) or {}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            endpoints.append(
                OpenApiEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=_extract_parameters(operation),
                    summary=operation.get("summary", ""),
                )
            )

    return endpoints


async def discover_openapi_endpoints(
    base_url: str,
    client: httpx.AsyncClient,
    rate_limiter: RateLimiter,
    candidate_paths: tuple[str, ...] = COMMON_OPENAPI_PATHS,
) -> list[OpenApiEndpoint]:
    """
    Probe a set of well-known OpenAPI/Swagger locations under `base_url`
    and parse the first valid specification document found.
    """
    for path in candidate_paths:
        spec_url = urljoin(base_url, path)
        response = await safe_request(client, rate_limiter, "GET", spec_url)

        if response is None or response.status_code != 200:
            continue

        content_type = response.headers.get("content-type", "")
        if "json" not in content_type and not response.text.lstrip().startswith("{"):
            continue

        try:
            spec = response.json()
        except ValueError:
            continue

        if "paths" not in spec:
            continue

        logger.info("Discovered OpenAPI specification at %s", spec_url)
        return _parse_spec_document(spec)

    logger.info("No OpenAPI/Swagger specification found at common paths for %s", base_url)
    return []