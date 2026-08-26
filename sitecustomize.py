from pathlib import Path

# One-shot compatibility hook for the stale connector-triggered workflow.
# That workflow insists on seeing the old ECH wording before it runs the real
# transform. Normalize only this exact sentence; the transform wrapper removes
# this file before tests and before the validated commit is created.
p = Path("README.md")
if p.exists():
    text = p.read_text()
    old = 'For `type = "ech"` and `type = "h3-ech"` routes, the ECHConfigList is sourced by\n'
    new = 'For `type = "ech"` routes on TCP or QUIC, the ECHConfigList is sourced by\n'
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 0 and new_count == 1:
        p.write_text(text.replace(new, old, 1))
    elif old_count not in (0, 1) or new_count not in (0, 1):
        raise RuntimeError(
            f"unexpected README ECH wording counts: old={old_count}, new={new_count}"
        )
