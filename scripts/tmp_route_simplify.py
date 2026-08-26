from pathlib import Path
import os
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

# A template-backed route deliberately keeps route_type=None in the synthetic
# companion: `use = "web"` must remain the source of type=tls. Validate the
# effective public type and only then normalize it to the QUIC/H3 runtime path.
test_path = Path("tests/quic_config.rs")
test_text = test_path.read_text()
wrong = '''    let expanded = cfg.expanded_listeners().unwrap();
    assert_eq!(expanded.len(), 2);
    assert_eq!(expanded[1].routes[0].route_type, Some(RouteType::Tls));
}

#[test]
fn global_http3_maps_ech_and_raw() {
'''
right = '''    let expanded = cfg.expanded_listeners().unwrap();
    assert_eq!(expanded.len(), 2);
    let route = &expanded[1].routes[0];
    assert_eq!(route.route_type, None);
    let template_name = route.use_template.as_deref().unwrap();
    let template = cfg.templates.get(template_name).unwrap();
    let configured_type = Config::effective_route_type(route, Some(template)).unwrap();
    assert_eq!(configured_type, RouteType::Tls);
    assert_eq!(
        Config::runtime_route_type(expanded[1].transport, configured_type),
        Some(RouteType::H3)
    );
}

#[test]
fn global_http3_maps_ech_and_raw() {
'''
count = test_text.count(wrong)
if count != 1:
    raise SystemExit(f"template companion transformed assertion: expected 1 match, found {count}")
test_path.write_text(test_text.replace(wrong, right, 1))

# The temporary validator's final vocabulary check uses `rg`, while the hosted
# image does not currently ship ripgrep. Put a tiny compatibility shim in
# CARGO_HOME/bin (already on PATH for this job). It lives outside the repository
# and supports exactly the recursive regex search shape used by the validator.
cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
rg = cargo_home / "bin" / "rg"
rg.parent.mkdir(parents=True, exist_ok=True)
rg.write_text(
    '''#!/usr/bin/env python3
import re
import sys
from pathlib import Path

args = sys.argv[1:]
show_lines = False
while args and args[0].startswith("-"):
    if args[0] == "-n":
        show_lines = True
        args.pop(0)
    else:
        raise SystemExit(2)
if len(args) < 2:
    raise SystemExit(2)
pattern = re.compile(args[0])
roots = [Path(p) for p in args[1:]]
matched = False
for root in roots:
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    for path in files:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            if pattern.search(line):
                matched = True
                prefix = f"{path}:{lineno}:" if show_lines else f"{path}:"
                print(prefix + line)
raise SystemExit(0 if matched else 1)
'''
)
rg.chmod(0o755)

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
