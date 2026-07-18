"""
Crawler / discovery engine package for Reconix Scan Engine.

Responsible for building a sitemap of a target application by
recursively following links, discovering HTML forms, extracting
endpoints referenced in JavaScript, parsing robots.txt, and importing
any published OpenAPI/Swagger specification.
"""