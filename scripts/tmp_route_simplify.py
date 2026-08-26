from pathlib import Path
import runpy

readme = Path("README.md")
text = readme.read_text()
old = 'For `type = "ech"` and `type = "h3-ech"` routes, the ECHConfigList is sourced by\n'
new = 'For `type = "ech"` routes on TCP or QUIC, the ECHConfigList is sourced by\n'
old_count = text.count(old)
new_count = text.count(new)
if old_count == 1 and new_count == 0:
    readme.write_text(text.replace(old, new, 1))
elif old_count == 0 and new_count == 1:
    pass
else:
    raise SystemExit(
        f"README ECH wording: expected exactly one old or new spelling; "
        f"old={old_count}, new={new_count}"
    )

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
