"""A small, safe Markdown renderer for the served documentation.

The judge guide lives in one place (``JUDGE_GUIDE.md``) and is rendered to HTML
at request time, so the file a judge reads on the site and the file in the
repository cannot drift. This is deliberately a *subset* of Markdown - headings,
paragraphs, lists, fenced code, inline code, bold/italic, links, blockquotes,
horizontal rules and simple pipe tables - which is everything the guide uses.

Safety: every text run is HTML-escaped before any markup is added, and link
targets are restricted to ``http``/``https``/``mailto`` and same-page anchors, so
a document can never inject script or an off-site navigation. The renderer is
pure and deterministic.
"""

from __future__ import annotations

import re

_ESCAPE = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}
_SAFE_LINK = re.compile(r"^(https?://|mailto:|#|/|\.{0,2}/)")
_INLINE_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def _escape(text: str) -> str:
    return "".join(_ESCAPE.get(ch, ch) for ch in text)


def _inline(text: str) -> str:
    """Render inline markup on already-escaped text."""
    out = _escape(text)

    def link(match: re.Match[str]) -> str:
        label, target = match.group(1), match.group(2).strip()
        if not _SAFE_LINK.match(target):
            return label  # drop an unsafe target, keep the text
        return f'<a href="{target}">{label}</a>'

    out = _LINK.sub(link, out)
    out = _INLINE_CODE.sub(r"<code>\1</code>", out)
    out = _BOLD.sub(r"<strong>\1</strong>", out)
    out = _ITALIC.sub(r"<em>\1</em>", out)
    return out


def _table(rows: list[str]) -> str:
    def cells(line: str) -> list[str]:
        return [c.strip() for c in line.strip().strip("|").split("|")]

    header = cells(rows[0])
    body = [cells(r) for r in rows[2:]]  # rows[1] is the separator
    html = ["<table><thead><tr>"]
    html += [f"<th>{_inline(c)}</th>" for c in header]
    html.append("</tr></thead><tbody>")
    for row in body:
        html.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in row) + "</tr>")
    html.append("</tbody></table>")
    return "".join(html)


def render(markdown_text: str) -> str:
    """Render a Markdown subset to HTML. Deterministic and XSS-safe."""
    lines = markdown_text.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Fenced code block.
        if stripped.startswith("```"):
            lang = stripped[3:].strip()
            i += 1
            block: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                block.append(lines[i])
                i += 1
            i += 1  # consume closing fence
            cls = f' class="lang-{_escape(lang)}"' if lang else ""
            out.append(f"<pre><code{cls}>{_escape(chr(10).join(block))}</code></pre>")
            continue

        # Table: a line with pipes followed by a separator row.
        if "|" in line and i + 1 < n and re.match(r"^\s*\|?[\s:-]+\|", lines[i + 1]) and "-" in lines[i + 1]:
            rows = [line]
            i += 1
            while i < n and "|" in lines[i] and lines[i].strip():
                rows.append(lines[i])
                i += 1
            out.append(_table(rows))
            continue

        # Headings.
        heading = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if heading:
            level = len(heading.group(1))
            out.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            i += 1
            continue

        # Horizontal rule.
        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            out.append("<hr>")
            i += 1
            continue

        # Blockquote.
        if stripped.startswith(">"):
            quote: list[str] = []
            while i < n and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip()[1:].strip())
                i += 1
            out.append("<blockquote>" + _inline(" ".join(quote)) + "</blockquote>")
            continue

        # Unordered list.
        if re.match(r"^[-*]\s+", stripped):
            items: list[str] = []
            while i < n and re.match(r"^[-*]\s+", lines[i].strip()):
                items.append(_inline(lines[i].strip()[2:]))
                i += 1
            out.append("<ul>" + "".join(f"<li>{it}</li>" for it in items) + "</ul>")
            continue

        # Ordered list.
        if re.match(r"^\d+\.\s+", stripped):
            items = []
            while i < n and re.match(r"^\d+\.\s+", lines[i].strip()):
                items.append(_inline(re.sub(r"^\d+\.\s+", "", lines[i].strip())))
                i += 1
            out.append("<ol>" + "".join(f"<li>{it}</li>" for it in items) + "</ol>")
            continue

        # Blank line.
        if not stripped:
            i += 1
            continue

        # Paragraph: gather until a blank line or a block starter.
        para: list[str] = []
        while i < n:
            s = lines[i].strip()
            if not s or s.startswith(("#", ">", "```", "|")) or re.match(r"^[-*]\s+", s) or re.match(r"^\d+\.\s+", s):
                break
            para.append(s)
            i += 1
        out.append("<p>" + _inline(" ".join(para)) + "</p>")
    return "\n".join(out)


__all__ = ["render"]
