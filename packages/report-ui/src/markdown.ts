// A tiny, dependency-free markdown renderer for advisory bodies.
//
// OSV/GHSA `details` fields are full markdown documents (headings, fenced code,
// tables, lists, GitHub <details>/<summary> wrappers, PoC code). Dumping them
// into a single text node collapses every newline into one unreadable run-on
// block — the original dashboard bug. This renders the common markdown subset
// to structured, readable HTML.
//
// SECURITY: advisory text is semi-untrusted (it flows from OSV into the page).
// Every piece of text content is HTML-escaped, output is composed only from a
// fixed tag whitelist, and links are restricted to http(s). The result is used
// with dangerouslySetInnerHTML, so these invariants must hold.

// Private-use sentinel that brackets extracted inline spans. It must (a) never
// occur in advisory text, (b) survive escapeHtml untouched, and (c) survive the
// build — note NUL would be stripped when the bundle is inlined into HTML, so a
// PUA code point is used instead.
const MARK = '\uE000';

function escapeHtml(s: string): string {
  return s.replace(
    /[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!,
  );
}

/** Return the URL only if it is an http(s) link — blocks javascript:/data: hrefs. */
function safeHref(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? url : undefined;
  } catch {
    return undefined;
  }
}

/** Render inline markup (links, code, bold) within a single line of text. */
function inline(raw: string): string {
  const tokens: string[] = [];
  const stash = (html: string): string => `${MARK}${tokens.push(html) - 1}${MARK}`;

  // Links and inline code are extracted first so their contents are not
  // re-processed by the bold pass and are escaped exactly once.
  let t = raw.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, label: string, url: string) => {
    const href = safeHref(url);
    if (!href) return escapeHtml(label);
    return stash(
      `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
        label,
      )}</a>`,
    );
  });
  t = t.replace(/`([^`]+)`/g, (_m, code: string) => stash(`<code>${escapeHtml(code)}</code>`));

  t = escapeHtml(t);
  t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  return t.replace(new RegExp(`${MARK}(\\d+)${MARK}`, 'g'), (_m, i: string) => tokens[Number(i)]!);
}

function splitRow(row: string): string[] {
  return row
    .trim()
    .replace(/^\||\|$/g, '')
    .split('|')
    .map((c) => c.trim());
}

const isTableSep = (line: string): boolean =>
  /^\s*\|?[\s:|-]+\|?\s*$/.test(line) && line.includes('-');
const isTableRow = (line: string): boolean => /^\s*\|.*\|\s*$/.test(line);

/** Render a markdown string to safe HTML for the advisory detail panel. */
export function renderMarkdown(src: string | undefined): string {
  if (!src) return '';

  // Drop GitHub's collapsible wrappers and surface the <summary> label as text.
  const cleaned = src
    .replace(/\r\n?/g, '\n')
    .replace(/<\/?details>/gi, '')
    .replace(/<summary>([\s\S]*?)<\/summary>/gi, '$1\n');

  const lines = cleaned.split('\n');
  const out: string[] = [];
  let para: string[] = [];
  let i = 0;

  const flushPara = (): void => {
    if (para.length) {
      out.push(`<p>${para.map(inline).join('<br>')}</p>`);
      para = [];
    }
  };

  while (i < lines.length) {
    const line = lines[i]!;
    const trimmed = line.trim();

    // Fenced code block.
    if (/^\s*```/.test(line)) {
      flushPara();
      i++;
      const code: string[] = [];
      while (i < lines.length && !/^\s*```/.test(lines[i]!)) code.push(lines[i++]!);
      i++; // consume closing fence
      out.push(`<pre><code>${escapeHtml(code.join('\n'))}</code></pre>`);
      continue;
    }

    // Heading.
    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      flushPara();
      out.push(`<h4 class="md-h">${inline(heading[2]!.trim())}</h4>`);
      i++;
      continue;
    }

    // GFM table (header row + separator row + body rows).
    if (isTableRow(line) && i + 1 < lines.length && isTableSep(lines[i + 1]!)) {
      flushPara();
      const head = splitRow(line);
      i += 2; // consume header + separator
      const body: string[][] = [];
      while (i < lines.length && isTableRow(lines[i]!)) body.push(splitRow(lines[i++]!));
      const thead = `<tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr>`;
      const tbody = body
        .map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`)
        .join('');
      out.push(`<table class="md-table">${thead}${tbody}</table>`);
      continue;
    }

    // Unordered list.
    if (/^\s*[-*]\s+/.test(line)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i]!)) {
        items.push(`<li>${inline(lines[i++]!.replace(/^\s*[-*]\s+/, ''))}</li>`);
      }
      out.push(`<ul>${items.join('')}</ul>`);
      continue;
    }

    // Ordered list.
    if (/^\s*\d+\.\s+/.test(line)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i]!)) {
        items.push(`<li>${inline(lines[i++]!.replace(/^\s*\d+\.\s+/, ''))}</li>`);
      }
      out.push(`<ol>${items.join('')}</ol>`);
      continue;
    }

    // Blank line ends a paragraph; non-blank lines accumulate into one.
    if (trimmed === '') flushPara();
    else para.push(trimmed);
    i++;
  }

  flushPara();
  return out.join('\n');
}
