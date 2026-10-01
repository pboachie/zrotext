#!/usr/bin/env python3
# Independent reference implementation used once to derive the shared
# vectors; the SDK must match the JSON, not the other way round.
import json

BS = chr(92)
import io

GSM_DEFAULT = set(
    "@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5"
    "\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u00c6\u00e6\u00df"
    "\u00c9 !\"#\u00a4%&'()*+,-./0123456789:;<=>?\u00a1"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7\u00bf"
    "abcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0"
)
GSM_EXT = set("\u000c^{}\\[~]|\u20ac")


def is_gsm(text: str) -> bool:
    return all(c in GSM_DEFAULT or c in GSM_EXT for c in text)


def estimate(text: str) -> dict:
    for i, ch in enumerate(text):
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDBFF:
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if not (len(nxt) == 1 and 0xDC00 <= ord(nxt) <= 0xDFFF):
                raise ValueError("lone surrogate")
        elif 0xDC00 <= cp <= 0xDFFF:
            raise ValueError("lone surrogate")
        elif cp < 0x20 and ch not in "\n\r\f":
            raise ValueError("control character")
    if is_gsm(text):
        length = sum(2 if c in GSM_EXT else 1 for c in text)
        per = 160 if length <= 160 else 153
        parts = 1 if length <= 160 else -(-length // per)
        enc = "gsm"
    else:
        length = len(text.encode("utf-16-le")) // 2  # UTF-16 code units
        per = 70 if length <= 70 else 67
        parts = 1 if length <= 70 else -(-length // per)
        enc = "ucs2"
    if parts > 6:
        raise ValueError("too long")
    return {"encoding": enc, "parts": parts, "perPart": per,
            "length": length, "empty": len(text) == 0}


cases = []


def ok(name, text):
    cases.append({"name": name, "text": text, "estimate": estimate(text)})


def err(name, text, error):
    cases.append({"name": name, "text": text, "error": error})


ok("plain gsm", "hello world")
ok("empty text", "")
ok("single gsm escape", "a^b")
ok("all ten escapes", "\u000c^{}\\[~]|\u20ac")
ok("gsm 158 letters plus escape is 160", "a" * 158 + "^")
ok("gsm exactly 160", "a" * 160)
ok("gsm 161 two parts", "a" * 161)
ok("gsm 305 two parts", "a" * 305)
ok("gsm 306 exactly two parts", "a" * 306)
ok("gsm 307 three parts", "a" * 307)
ok("gsm 459 three parts", "a" * 459)
ok("gsm 460 four parts", "a" * 460)
ok("gsm 918 exactly six parts", "a" * 918)
err("gsm 919 over six parts", "a" * 919, "too long")
ok("gsm newline and cr count one each", "line1\nline2\r")
ok("unicode forces ucs2", "gr\u00fc\u00df\u55b5")
ok("emoji astral pair counts two units", "\U0001f44d")
ok("ucs2 exactly 70", "\u55b5" * 70)
ok("ucs2 71 two parts", "\u55b5" * 71)
ok("ucs2 134 two parts", "\u55b5" * 134)
ok("ucs2 135 three parts", "\u55b5" * 135)
ok("ucs2 402 exactly six parts", "\u55b5" * 402)
err("ucs2 403 over six parts", "\u55b5" * 403, "too long")
err("lone high surrogate", "a\ud800", "lone surrogate")
err("lone low surrogate", "\udc00a", "lone surrogate")
err("tab control character", "a\tb", "control character")
err("nul control character", "a\x00b", "control character")
ok("mixed gsm plus one unicode switches", "abc\u55b5def")

doc = {
    "vectorVersion": 1,
    "spec": "protocol/v1/sms-segment-estimate.md",
    "notes": (
        "Text lengths are UTF-16 code units. GSM septets count "
        "extension-table characters as two. Estimates are composition aids "
        "only; the device re-checks bounds before dispatch."
    ),
    "cases": cases,
}
def surrogate_safe(value):
    # Lone surrogates cannot exist in UTF-8; keep them JSON-escaped in the
    # file so every consumer reads the same code-unit sequence.
    if isinstance(value, str):
        return "".join(
            ch if not (0xD800 <= ord(ch) <= 0xDFFF) else "\\u%04x" % ord(ch)
            for ch in value
        )
    return value


def escape_cases(value):
    if isinstance(value, dict):
        return {k: escape_cases(v) for k, v in value.items()}
    if isinstance(value, list):
        return [escape_cases(v) for v in value]
    return surrogate_safe(value)


dumped = json.dumps(escape_cases(doc), indent=2, ensure_ascii=False) + "\n"
# The lone-surrogate error cases must appear as single JSON escapes so
# every parser reads the same code unit; json.dumps doubled our
# backslashes, so un-double exactly those two.
for code in ("ud800", "udc00"):
    dumped = dumped.replace(BS + BS + code, BS + code)
out = dumped
io.open("protocol/v1/vectors/sms-segment-estimate-01.json", "w",
        encoding="utf-8", newline="\n").write(out)
print("vectors written:", len(cases), "cases")
for c in cases:
    if "estimate" in c:
        e = c["estimate"]
        print(f"{c['name'][:44]:46} {e['encoding']:4} parts={e['parts']} len={e['length']}")
