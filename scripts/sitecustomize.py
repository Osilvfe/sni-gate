from pathlib import Path

p = Path("README.md")
text = p.read_text()
old = 'For `type = "ech"` and `type = "h3-ech"` routes, the ECHConfigList is sourced by\n'
new = 'For `type = "ech"` routes on TCP or QUIC, the ECHConfigList is sourced by\n'
count = text.count(old)
if count != 1:
    raise RuntimeError(f"README ECH wording: expected one match, found {count}")
p.write_text(text.replace(old, new, 1))

# This is a one-shot CI preflight. Delete all tracked trigger helpers before the
# main transform runs so the validated source commit cannot retain CI scaffolding.
Path(__file__).unlink()
marker = Path(".ci-route-simplify-trigger")
if marker.exists():
    marker.unlink()
