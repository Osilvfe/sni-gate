from pathlib import Path
import runpy

readme = Path("README.md")
text = readme.read_text()
old = 'For `type = "ech"` and `type = "h3-ech"` routes, the ECHConfigList is sourced by\n'
new = 'For `type = "ech"` routes on TCP or QUIC, the ECHConfigList is sourced by\n'
old_count = text.count(old)
new_count = text.count(new)
if old_count == 1 and new_count == 0:
    text = text.replace(old, new, 1)
elif old_count == 0 and new_count == 1:
    pass
else:
    raise SystemExit(
        f"README ECH wording: expected exactly one old or new spelling; "
        f"old={old_count}, new={new_count}"
    )

scope_old = '''HTTP/3 can coalesce origins too, but `h3`/`h3-ech` are semantic rather than byte
splices. They therefore have an additional guard: every request's `:authority` is
routed again and a request crossing the handshake route boundary gets **421
Misdirected Request** before it reaches the existing upstream H3 connection.
'''
scope_new = '''HTTP/3 can coalesce origins too, but terminating QUIC `tls`/`ech` routes are
semantic rather than byte splices. They therefore have an additional guard: every
request's `:authority` is routed again and a request crossing the handshake route
boundary gets **421 Misdirected Request** before it reaches the existing upstream
H3 connection.
'''
scope_count = text.count(scope_old)
if scope_count == 1:
    text = text.replace(scope_old, scope_new, 1)
elif scope_count == 0 and scope_new in text:
    pass
else:
    raise SystemExit(f"README H3 coalescing wording: expected one old/new spelling; old={scope_count}")

readme.write_text(text)

runpy.run_path("scripts/tmp_route_simplify_impl.py", run_name="__main__")

# The implementation completed its own sanity checks. Remove all temporary
# validation scaffolding before fmt/test and before the workflow commits the
# validated source/docs diff.
for name in [
    "sitecustomize.py",
    "scripts/tmp_route_simplify.py",
    "scripts/tmp_route_simplify_impl.py",
    "scripts/sitecustomize.py",
    ".ci-route-simplify-trigger",
    ".ci-route-simplify-trigger-v2",
    ".github/workflows/tmp-route-simplify.yml",
    ".github/workflows/tmp-route-simplify-v2.yml",
]:
    p = Path(name)
    if p.exists():
        p.unlink()
