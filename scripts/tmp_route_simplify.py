from pathlib import Path
import runpy

readme = Path("README.md")
text = readme.read_text()
old = 'For `type = "ech"` and `type = "h3-ech"` routes, the ECHConfigList is sourced by\n'
new = 'For `type = "ech"` routes on TCP or QUIC, the ECHConfigList is sourced by\n'
count = text.count(old)
if count != 1:
    raise SystemExit(f"README ECH wording: expected one match, found {count}")
readme.write_text(text.replace(old, new, 1))

runpy.run_path("scripts/tmp_route_simplify_impl.py", run_name="__main__")

# The implementation completed its own sanity checks. Remove all temporary
# validation scaffolding before fmt/test and before the workflow commits the
# validated source/docs diff.
for name in [
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
