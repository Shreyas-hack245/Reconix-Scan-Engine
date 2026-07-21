"""
Vulnerability scanner package for Reconix Scan Engine.

Each module in this package (xss, sqli, ssrf, rce, idor, csrf, headers,
cors, cookies, redirect, upload, access_control, info_disclosure,
directory_traversal, clickjacking) implements one independent,
self-contained detection technique and returns a list of `ScanFinding`
objects. All modules are strictly detection-only: they use safe,
non-destructive probes (unique benign markers, boolean/timing
comparisons, read-only header/cookie inspection) and never execute or
return weaponized exploit payloads.
"""