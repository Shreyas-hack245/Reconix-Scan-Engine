"""
HTML form discovery for Reconix Scan Engine.

Extracts <form> elements from a page so scanner modules (XSS, SQLi,
CSRF, file upload, etc.) know which fields exist and how to submit
test values safely.
"""

from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup

INPUT_LIKE_TAGS = ("input", "textarea", "select")


@dataclass
class FormField:
    """A single field within a discovered HTML form."""

    name: str
    field_type: str = "text"  # text, password, hidden, email, checkbox, select, textarea, file, etc.
    default_value: str = ""


@dataclass
class DiscoveredForm:
    """A discovered HTML form and its fields."""

    action_url: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)
    has_file_upload: bool = False
    has_csrf_token: bool = False

    @property
    def field_names(self) -> list[str]:
        return [f.name for f in self.fields]


_CSRF_NAME_HINTS = ("csrf", "token", "authenticity", "_token", "nonce")


def extract_forms(html: str, page_url: str) -> list[DiscoveredForm]:
    """Parse HTML and return all discovered forms with their fields."""
    soup = BeautifulSoup(html, "lxml")
    forms: list[DiscoveredForm] = []

    for form_tag in soup.find_all("form"):
        raw_action = form_tag.get("action", "").strip()
        action_url = urljoin(page_url, raw_action) if raw_action else page_url
        method = (form_tag.get("method") or "GET").strip().upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            method = "GET"

        discovered = DiscoveredForm(action_url=action_url, method=method)

        for tag in form_tag.find_all(INPUT_LIKE_TAGS):
            name = tag.get("name")
            if not name:
                continue

            tag_name = tag.name.lower()
            if tag_name == "textarea":
                field_type = "textarea"
            elif tag_name == "select":
                field_type = "select"
            else:
                field_type = (tag.get("type") or "text").strip().lower()

            if field_type == "file":
                discovered.has_file_upload = True
            if any(hint in name.lower() for hint in _CSRF_NAME_HINTS):
                discovered.has_csrf_token = True

            discovered.fields.append(
                FormField(
                    name=name,
                    field_type=field_type,
                    default_value=tag.get("value", ""),
                )
            )

        forms.append(discovered)

    return forms