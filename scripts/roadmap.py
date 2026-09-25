"""Render the roadmap graphic, charts and tables from docs/roadmap.json.

Edit docs/roadmap.json, then run `python3 scripts/roadmap.py` to rewrite the
generated regions. `--check` exits non-zero when a generated file is stale.
"""

from pathlib import Path
import argparse
import json
import re
import sys
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "docs" / "roadmap.json"
SVG = ROOT / "docs" / "assets" / "roadmap-overview.svg"
ROADMAP = ROOT / "docs" / "ROADMAP.md"
README = ROOT / "README.md"
USE_CASES = ROOT / "docs" / "USE-CASES.md"
PRIORITY_NAME = {"first": "First", "next": "Next", "later": "Later"}
AVAILABILITY_NAME = {
    "planned": "Proposed; unavailable", "pilot": "Restricted pilot", "released": "General release",
}

# Stages in progress order. The index is the number of stage segments reached.
STAGES = ("planned", "design", "build", "pilot", "released")
SEGMENTS = ("Design", "Build", "Restricted pilot", "General release")
STAGE_NAME = {
    "planned": "Planned", "design": "Design", "build": "Build",
    "pilot": "Restricted pilot", "released": "General release",
}
STATUS_WORD = {
    "planned": "Planned", "design": "Designing", "build": "Building",
    "pilot": "Pilot", "released": "Released",
}
ALT_PHRASE = {
    "planned": "planned", "design": "in design", "build": "being built",
    "pilot": "in a restricted pilot", "released": "generally released",
}
COLOR = {
    "planned": "#99a696", "design": "#edbe70", "build": "#6f9b4b",
    "pilot": "#b6f36a", "released": "#e4fbc8",
}
SVG_STATUS_COLOR = {**COLOR, "build": "#f0f3e9"}
# Summary order: most mature first.
DISPLAY_ORDER = ("released", "pilot", "build", "design", "planned")
NUMBER_WORDS = (
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    "sixteen", "seventeen", "eighteen", "nineteen", "twenty",
)
ID = re.compile(r"^[a-z][a-z0-9]*$")
MAX_NAME = 46
MAX_SHORT = 30


def load(path: Path = DATA) -> dict:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    validate(data)
    return data


def capabilities(data: dict) -> list[dict]:
    return [cap for track in data["tracks"] for cap in track["capabilities"]]


def validate(data: dict) -> None:
    """Reject data that would render a misleading or broken roadmap."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(data.get("snapshot", ""))):
        raise ValueError("snapshot must be a YYYY-MM-DD date")
    track_ids = [track["id"] for track in data["tracks"]]
    if not track_ids or len(track_ids) != len(set(track_ids)):
        raise ValueError("track ids must be present and unique")
    seen = set()
    for track in data["tracks"]:
        if not ID.match(track["id"]) or not track["capabilities"]:
            raise ValueError(f"track {track['id']!r} needs a lowercase id and capabilities")
        for cap in track["capabilities"]:
            cid = cap["id"]
            if not ID.match(cid) or cid in seen:
                raise ValueError(f"capability id {cid!r} is invalid or duplicated")
            seen.add(cid)
            if cap["stage"] not in STAGES:
                raise ValueError(f"{cid}: unknown stage {cap['stage']!r}")
            if len(cap["name"]) > MAX_NAME or len(cap["short"]) > MAX_SHORT:
                raise ValueError(f"{cid}: name or short name is too long for the graphic")
            if not cap["evidence"]:
                raise ValueError(f"{cid}: link at least one piece of evidence")
            if cap["stage"] != "planned" and not cap["done"]:
                raise ValueError(f"{cid}: a started capability needs at least one done item")
            if cap["stage"] != "released" and not cap["todo"]:
                raise ValueError(f"{cid}: an unreleased capability needs at least one open item")
    for source, target in data["dependencies"]:
        if source not in seen or target not in seen or source == target:
            raise ValueError(f"dependency {source} -> {target} is invalid")
    # Cycles would make prerequisite-based availability checks meaningless.
    for cid in seen:
        prerequisites(data, [cid])
    if sorted(data["track_map_order"]) != sorted(track_ids):
        raise ValueError("track_map_order must list every track once")
    if not data["general_send_gate"] or not all(data["general_send_gate"]):
        raise ValueError("general_send_gate needs non-empty groups")
    for group in data["general_send_gate"]:
        for step in group:
            if not isinstance(step.get("done"), bool) or not step.get("text"):
                raise ValueError("general sending gates need text and boolean done values")
    caps = {cap["id"]: cap for cap in capabilities(data)}
    use_case_ids = set()
    if not data.get("use_cases"):
        raise ValueError("use_cases must contain at least one customer outcome")
    for case in data["use_cases"]:
        cid = case["id"]
        if not ID.fullmatch(cid) or cid in use_case_ids:
            raise ValueError(f"use case id {cid!r} is invalid or duplicated")
        use_case_ids.add(cid)
        if case["priority"] not in PRIORITY_NAME or case["availability"] not in AVAILABILITY_NAME:
            raise ValueError(f"{cid}: unknown priority or availability")
        for field in ("title", "audience", "problem", "example"):
            if not isinstance(case.get(field), str) or not case[field].strip():
                raise ValueError(f"{cid}: {field} must be non-empty text")
        for field in ("journey", "acceptance", "success_signals"):
            values = case.get(field)
            if not isinstance(values, list) or not values or not all(
                isinstance(value, str) and value.strip() for value in values
            ):
                raise ValueError(f"{cid}: {field} needs non-empty text items")
        required = case.get("requires", [])
        if not required or len(required) != len(set(required)) or any(cid not in caps for cid in required):
            raise ValueError(f"{cid}: requires must list unique, known capabilities")
        if case["availability"] != "planned":
            floor = STAGES.index(case["availability"])
            if any(STAGES.index(caps[dep]["stage"]) < floor for dep in prerequisites(data, required)):
                raise ValueError(f"{cid}: availability exceeds its prerequisites")
            if not all(step["done"] for group in data["general_send_gate"] for step in group):
                raise ValueError(f"{cid}: customer workflows require the general sending gates")


def prerequisites(data: dict, required: list[str]) -> set[str]:
    """Include direct requirements and their upstream capability dependencies."""
    upstream: dict[str, list[str]] = {}
    for source, target in data["dependencies"]:
        upstream.setdefault(target, []).append(source)
    result, visiting = set(), set()

    def visit(cid: str) -> None:
        if cid in visiting:
            raise ValueError(f"cyclic capability dependency at {cid}")
        if cid in result:
            return
        visiting.add(cid)
        for parent in upstream.get(cid, []):
            visit(parent)
        visiting.remove(cid)
        result.add(cid)

    for cid in required:
        visit(cid)
    return result


def counts(data: dict) -> dict[str, int]:
    result = {stage: 0 for stage in STAGES}
    for cap in capabilities(data):
        result[cap["stage"]] += 1
    return result


def number(value: int) -> str:
    return NUMBER_WORDS[value] if value < len(NUMBER_WORDS) else str(value)


def alt_text(data: dict) -> str:
    total = counts(data)
    parts = []
    for stage in DISPLAY_ORDER:
        if stage == "released" or not total[stage]:
            continue
        verb = "is" if total[stage] == 1 else "are"
        parts.append(f"{number(total[stage])} {verb} {ALT_PHRASE[stage]}")
    sentence = ", ".join(parts[:-1]) + " and " + parts[-1] if len(parts) > 1 else parts[0]
    released = total["released"]
    tail = ("None has reached general release." if not released else
            f"{number(released).capitalize()} {'has' if released == 1 else 'have'} reached general release.")
    return (f"Roadmap at a glance: {len(capabilities(data))} capabilities in "
            f"{number(len(data['tracks']))} tracks. {sentence[0].upper()}{sentence[1:]}. {tail}")


# --- SVG -------------------------------------------------------------------

def render_svg(data: dict) -> str:
    width, pad = 1200, 56
    seg_x0, seg_w, seg_gap = 560, 112, 8
    status_x = width - pad
    row_h, track_h = 34, 40
    font = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
    total = counts(data)

    body = []
    y = 150
    for i, name in enumerate(SEGMENTS):
        cx = seg_x0 + i * (seg_w + seg_gap) + seg_w // 2
        body.append(f'<text x="{cx}" y="{y}" text-anchor="middle" class="col">{escape(name.upper())}</text>')
    body.append(f'<text x="{status_x}" y="{y}" text-anchor="end" class="col">NOW</text>')
    y += 14
    for track in data["tracks"]:
        y += track_h - 12
        body.append(f'<text x="{pad}" y="{y}" class="track">{escape(track["title"])}</text>')
        body.append(f'<line x1="{pad}" y1="{y + 9}" x2="{width - pad}" y2="{y + 9}" class="rule"/>')
        y += 12
        for cap in track["capabilities"]:
            reached = STAGES.index(cap["stage"])
            y += row_h
            text_y = y - 11
            body.append(f'<text x="{pad + 14}" y="{text_y}" class="item">{escape(cap["name"])}</text>')
            for i in range(len(SEGMENTS)):
                cls = "on" if i < reached else "next" if i == reached else "off"
                x = seg_x0 + i * (seg_w + seg_gap)
                body.append(f'<rect x="{x}" y="{y - 26}" width="{seg_w}" height="18" rx="4" class="seg {cls}"/>')
            body.append(f'<text x="{status_x}" y="{text_y}" text-anchor="end" class="status" '
                        f'fill="{SVG_STATUS_COLOR[cap["stage"]]}">{STATUS_WORD[cap["stage"]]}</text>')

    y += 36
    body.append(f'<line x1="{pad}" y1="{y - 18}" x2="{width - pad}" y2="{y - 18}" class="rule"/>')
    x = pad
    for cls, label in (("on", "Stage reached"), ("next", "Next stage"), ("off", "Not started")):
        body.append(f'<rect x="{x}" y="{y - 11}" width="28" height="12" rx="3" class="seg {cls}"/>')
        body.append(f'<text x="{x + 38}" y="{y}" class="foot">{label}</text>')
        x += 180
    body.append(f'<text x="{width - pad}" y="{y}" text-anchor="end" class="foot">'
                f'Roadmap snapshot, {data["snapshot"]} · direction, not release dates</text>')
    y += 24
    body.append(f'<text x="{pad}" y="{y}" class="foot">Restricted pilot = allowlisted accounts and '
                'recipients, synthetic or controlled tests. No general or hosted SMS service is available.</text>')
    height = y + 34

    chips = []
    x = width - pad
    for stage in reversed(DISPLAY_ORDER):
        if not total[stage]:
            continue
        label = f"{total[stage]} {STATUS_WORD[stage].lower()}"
        chip_w = round(14 + len(label) * 7.6)
        x -= chip_w
        chips.append(f'<rect x="{x}" y="54" width="{chip_w}" height="28" rx="14" fill="#111712" stroke="#29332a"/>')
        chips.append(f'<text x="{x + chip_w / 2:g}" y="73" text-anchor="middle" class="status chip" '
                     f'fill="{SVG_STATUS_COLOR[stage]}">{label}</text>')
        x -= 8

    style = "\n".join((
        f"text{{font-family:{font}}}",
        ".h1{font-size:28px;font-weight:700;fill:#f0f3e9}",
        ".sub{font-size:15px;fill:#99a696}",
        ".col{font-size:11px;font-weight:600;letter-spacing:.08em;fill:#99a696}",
        ".track{font-size:13px;font-weight:700;letter-spacing:.04em;fill:#b6f36a}",
        ".item{font-size:15px;fill:#f0f3e9}",
        ".status{font-size:14px;font-weight:600}",
        ".chip{font-size:13px}",
        ".foot{font-size:12px;fill:#99a696}",
        ".rule{stroke:#29332a;stroke-width:1}",
        ".seg.on{fill:#b6f36a}",
        ".seg.next{fill:#161e17;stroke:#b6f36a;stroke-width:1.5;stroke-dasharray:5 4}",
        ".seg.off{fill:#161e17;stroke:#29332a;stroke-width:1}",
    ))
    head = [
        "<!-- Generated by scripts/roadmap.py from docs/roadmap.json. Do not edit by hand. -->",
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
        f'height="{height}" role="img" aria-labelledby="t d">',
        '<title id="t">ZROtext roadmap at a glance</title>',
        f'<desc id="d">{escape(alt_text(data))}</desc>',
        f"<style>\n{style}\n</style>",
        f'<rect width="{width}" height="{height}" rx="18" fill="#0b0f0c"/>',
        f'<rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="17" fill="none" stroke="#29332a"/>',
        f'<g transform="translate({pad} 44)"><rect width="48" height="48" rx="11" fill="#b6f36a"/>'
        '<path d="M12 14h24L15 33h21M13 24h9" fill="none" stroke="#0b100b" stroke-width="4" '
        'stroke-linecap="square"/></g>',
        f'<text x="{pad + 66}" y="68" class="h1">Roadmap at a glance</text>',
        f'<text x="{pad + 66}" y="94" class="sub">Where each capability stands today. '
        "Stages show progress, not dates.</text>",
    ]
    return "\n".join(head + chips + body + ["</svg>"]) + "\n"


# --- Markdown --------------------------------------------------------------

def slug(title: str) -> str:
    """GitHub heading anchor for plain-text headings."""
    return re.sub(r"[^a-z0-9 -]", "", title.lower()).replace(" ", "-")


def mermaid_label(text: str) -> str:
    return text.replace('"', "#quot;")


def wrap(text: str, limit: int = 24) -> str:
    """Split a long diagram label into two lines at the space nearest the middle."""
    if len(text) <= limit or " " not in text:
        return text
    middle = len(text) // 2
    spaces = [i for i, char in enumerate(text) if char == " "]
    cut = min(spaces, key=lambda i: abs(i - middle))
    return f"{text[:cut]}<br/>{text[cut + 1:]}"


def link(label: str, target: str) -> str:
    return f"[{label}]({target})"


def stage_text(cap: dict) -> str:
    name = STAGE_NAME[cap["stage"]]
    return f"{name} ({cap['qualifier']})" if cap.get("qualifier") else name


def overview(data: dict, image: str, width: int, href: str | None) -> str:
    img = f'<img src="{image}" alt="{escape(alt_text(data), {chr(34): "&quot;"})}" width="{width}">'
    if href:
        img = f'<a href="{href}">{img}</a>'
    return f'<p align="center">{img}</p>'


def summary(data: dict) -> str:
    total = counts(data)
    present = [stage for stage in DISPLAY_ORDER if total[stage]]
    colors = {f"pie{i + 1}": COLOR[stage] for i, stage in enumerate(present)}
    theme = {**colors, "pieSectionTextColor": "#0b0f0c", "pieStrokeColor": "#29332a",
             "pieOuterStrokeColor": "#29332a"}
    lines = [
        "```mermaid",
        "%%{init: " + json.dumps({"themeVariables": theme}) + "}%%",
        "pie showData",
        f"    title Capabilities by stage ({len(capabilities(data))} tracked)",
    ]
    lines += [f'    "{STAGE_NAME[stage]}" : {total[stage]}' for stage in present]
    lines += ["```", ""]
    lines.append("| Track | " + " | ".join(STAGE_NAME[s] for s in DISPLAY_ORDER) + " |")
    lines.append("|---|" + ":---:|" * len(DISPLAY_ORDER))
    for track in data["tracks"]:
        row = [str(sum(c["stage"] == s for c in track["capabilities"]) or "") for s in DISPLAY_ORDER]
        lines.append(f"| {link(track['title'], '#' + slug(track['title']))} | " + " | ".join(row) + " |")
    return "\n".join(lines)


def gate(data: dict) -> str:
    lines = [
        "```mermaid",
        "flowchart LR",
        "    classDef done fill:#b6f36a,stroke:#6f9b4b,color:#0b0f0c",
        "    classDef open fill:#161e17,stroke:#edbe70,color:#f0f3e9,stroke-dasharray:5 4",
        "    classDef gate fill:#0b0f0c,stroke:#b6f36a,color:#f0f3e9,stroke-width:2px",
        "",
    ]
    groups = []
    for g, group in enumerate(data["general_send_gate"]):
        ids = []
        for i, step in enumerate(group):
            node = f"g{g}_{i}"
            mark, cls = ("✓", "done") if step["done"] else ("○", "open")
            lines.append(f'    {node}["{mark} {mermaid_label(wrap(step["text"]))}"]:::{cls}')
            ids.append(node)
        groups.append(ids)
    lines += ['    G{{"General send route"}}:::gate', ""]
    for left, right in zip(groups, groups[1:] + [["G"]]):
        lines.append(f"    {' & '.join(left)} --> {' & '.join(right)}")
    lines += ["```", "", "✓ marks work done in the restricted pilot; ○ marks work still open."]
    return "\n".join(lines)


def track_map(data: dict) -> str:
    tracks = {track["id"]: track for track in data["tracks"]}
    owner = {cap["id"]: track["id"] for track in data["tracks"] for cap in track["capabilities"]}
    lines = [
        "```mermaid",
        "flowchart LR",
        "    classDef released fill:#e4fbc8,stroke:#6f9b4b,color:#0b0f0c",
        "    classDef pilot fill:#b6f36a,stroke:#6f9b4b,color:#0b0f0c",
        "    classDef build fill:#161e17,stroke:#b6f36a,color:#f0f3e9",
        "    classDef design fill:#161e17,stroke:#edbe70,color:#f0f3e9,stroke-dasharray:5 4",
        "    classDef planned fill:#111712,stroke:#29332a,color:#99a696,stroke-dasharray:2 4",
    ]
    for tid in data["track_map_order"]:
        track = tracks[tid]
        lines += ["", f'    subgraph t_{tid}["{mermaid_label(track["title"])}"]', "        direction TB"]
        for cap in track["capabilities"]:
            lines.append(f'        c_{cap["id"]}["{mermaid_label(cap["short"])}<br/>· '
                         f'{STAGE_NAME[cap["stage"]].lower()}"]:::{cap["stage"]}')
        for source, target in data["dependencies"]:
            if owner[source] == owner[target] == tid:
                lines.append(f"        c_{source} --> c_{target}")
        lines.append("    end")
    lines.append("")
    for source, target in data["dependencies"]:
        if owner[source] != owner[target]:
            lines.append(f"    c_{source} --> c_{target}")
    lines.append("```")
    return "\n".join(lines)


def tracks(data: dict) -> str:
    out = []
    for track in data["tracks"]:
        out += [f"## {track['title']}", "", track["intro"], "",
                "| Capability | Stage | Evidence |", "|---|---|---|"]
        for cap in track["capabilities"]:
            evidence = ", ".join(link(label, target) for label, target in cap["evidence"])
            if cap.get("evidence_note"):
                evidence += f" {cap['evidence_note']}"
            out.append(f"| {cap['name']} | {stage_text(cap)} | {evidence} |")
        for cap in track["capabilities"]:
            detail = STAGE_NAME[cap["stage"]].lower()
            if cap.get("qualifier"):
                detail += f", {cap['qualifier']}"
            out += ["", f'<a id="cap-{cap["id"]}"></a>', "<details>",
                    f"<summary><b>{escape(cap['name'])}</b> · {detail}</summary>", ""]
            out += [f"- [x] {item}" for item in cap["done"]]
            out += [f"- [ ] {item}" for item in cap["todo"]]
            out += ["", "</details>"]
        out.append("")
    return "\n".join(out).rstrip()


def use_case_summary(data: dict, prefix: str = "", first_only: bool = False) -> str:
    lines = ["| Priority | Experience | Example | Availability |", "|---|---|---|---|"]
    for priority in PRIORITY_NAME:
        for case in data["use_cases"]:
            if case["priority"] != priority or (first_only and priority != "first"):
                continue
            title = link(case["title"], f'{prefix}USE-CASES.md#{case["id"]}')
            lines.append(f"| {PRIORITY_NAME[priority]} | {title} | {case['example']} | "
                         f"{AVAILABILITY_NAME[case['availability']]} |")
    return "\n".join(lines)


def use_case_details(data: dict) -> str:
    caps = {cap["id"]: cap for cap in capabilities(data)}
    out = []
    for priority in PRIORITY_NAME:
        for case in data["use_cases"]:
            if case["priority"] != priority:
                continue
            out += [f'<a id="{case["id"]}"></a>', "", f'## {case["title"]}', "",
                    f"**{PRIORITY_NAME[priority]} · {AVAILABILITY_NAME[case['availability']]}**", "",
                    f"**For:** {case['audience']}", "", case["problem"], "",
                    f"**Example:** {case['example']}", "", "### Intended journey", ""]
            out += [f"{i}. {step}" for i, step in enumerate(case["journey"], 1)]
            out += ["", "### Required capabilities", ""]
            out += [f"- {link(caps[cid]['name'], 'ROADMAP.md#cap-' + cid)} "
                    f"({STAGE_NAME[caps[cid]['stage']]})" for cid in case["requires"]]
            out += ["", "These also inherit their upstream roadmap dependencies and the "
                    "[general sending gates](ROADMAP.md#path-to-general-sending).", "",
                    "### Acceptance criteria", ""]
            out += [f"- {item}" for item in case["acceptance"]]
            out += ["", "### Success signals to measure", ""]
            out += [f"- {item}" for item in case["success_signals"]]
            out.append("")
    return "\n".join(out).rstrip()


def blocks_for(path: Path, data: dict) -> dict[str, str]:
    if path == ROADMAP:
        return {
            "overview": overview(data, "assets/roadmap-overview.svg", 900, None),
            "summary": summary(data),
            "gate": gate(data),
            "map": track_map(data),
            "tracks": tracks(data),
            "usecases": use_case_summary(data),
        }
    if path == README:
        return {
            "overview": overview(data, "docs/assets/roadmap-overview.svg", 820, "docs/ROADMAP.md"),
            "usecases": use_case_summary(data, "docs/", first_only=True),
        }
    if path == USE_CASES:
        return {"usecases": use_case_summary(data), "cases": use_case_details(data)}
    raise ValueError(f"no generated blocks for {path}")


def replace_blocks(text: str, blocks: dict[str, str], name: str) -> str:
    """Replace each `<!-- roadmap:NAME -->` ... `<!-- /roadmap:NAME -->` region."""
    for key, content in blocks.items():
        pattern = re.compile(
            rf"(<!-- roadmap:{key} -->\n).*?(\n<!-- /roadmap:{key} -->)", re.DOTALL)
        found = len(pattern.findall(text))
        if found != 1:
            raise ValueError(f"{name}: expected one roadmap:{key} region, found {found}")
        text = pattern.sub(lambda match: match.group(1) + content + match.group(2), text)
    return text


def rendered(data: dict) -> dict[Path, str]:
    """Return the full expected contents of every generated file."""
    files = {SVG: render_svg(data)}
    for path in (ROADMAP, README, USE_CASES):
        with open(path, encoding="utf-8") as handle:
            current = handle.read()
        files[path] = replace_blocks(current, blocks_for(path, data), path.name)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="fail if generated files differ from docs/roadmap.json")
    args = parser.parse_args()
    try:
        files = rendered(load())
    except (ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"roadmap: {error}", file=sys.stderr)
        return 1

    stale = []
    for path, content in files.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current is not None:
            current = current.replace("\r\n", "\n")
        if current == content:
            continue
        stale.append(path.relative_to(ROOT).as_posix())
        if not args.check:
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)

    if args.check and stale:
        print("Roadmap output is out of date: " + ", ".join(stale), file=sys.stderr)
        print("Run `python3 scripts/roadmap.py` and commit the result.", file=sys.stderr)
        return 1
    print("Updated: " + ", ".join(stale) if stale else "Roadmap output is current.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
