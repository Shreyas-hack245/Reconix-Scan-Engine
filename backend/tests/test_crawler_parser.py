import pytest

from app.crawler.crawler import Crawler
from app.crawler.form_extractor import extract_forms
from app.crawler.js_endpoint_extractor import extract_js_endpoints


@pytest.mark.asyncio
async def test_html_parsing_uses_available_parser():
    html = "<html><body><a href='/next'>Next</a><form action='/submit'><input name='q' /></form><script>fetch('/api/test')</script></body></html>"

    links = Crawler._extract_links(html, "https://example.com")
    forms = extract_forms(html, "https://example.com")
    js_endpoints = await extract_js_endpoints(html, "https://example.com", client=None, rate_limiter=None, fetch_external=False)

    assert links == ["https://example.com/next"]
    assert forms[0].action_url == "https://example.com/submit"
    assert forms[0].fields[0].name == "q"
    assert js_endpoints[0].url == "https://example.com/api/test"
