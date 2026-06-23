import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../src/markdown.js';

describe('renderMarkdown — safety', () => {
  it('escapes HTML in plain text so advisory content can never inject markup', () => {
    const html = renderMarkdown('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('escapes HTML inside inline code', () => {
    expect(renderMarkdown('use `<script>`')).toContain('<code>&lt;script&gt;</code>');
  });

  it('escapes HTML inside fenced code blocks', () => {
    const html = renderMarkdown('```\n<script>alert(1)</script>\n```');
    expect(html).toContain('<pre><code>&lt;script&gt;alert(1)&lt;/script&gt;</code></pre>');
  });

  it('only emits http(s) links; unsafe schemes degrade to plain text', () => {
    expect(renderMarkdown('[ok](https://example.com)')).toContain(
      '<a href="https://example.com" target="_blank" rel="noopener noreferrer">ok</a>',
    );
    const bad = renderMarkdown('[x](javascript:alert(1))');
    expect(bad).not.toContain('<a ');
    expect(bad).toContain('x');
  });
});

describe('renderMarkdown — formatting', () => {
  it('returns an empty string for empty/undefined input', () => {
    expect(renderMarkdown('')).toBe('');
    expect(renderMarkdown(undefined)).toBe('');
  });

  it('renders headings', () => {
    expect(renderMarkdown('## Description')).toContain('<h4 class="md-h">Description</h4>');
  });

  it('renders inline code', () => {
    expect(renderMarkdown('call `cookies.read()`')).toContain('<code>cookies.read()</code>');
  });

  it('renders bold', () => {
    expect(renderMarkdown('**Component:** cookies.js')).toContain('<strong>Component:</strong>');
  });

  it('renders fenced code blocks preserving newlines', () => {
    const html = renderMarkdown('```js\nconst x = 1;\nconst y = 2;\n```');
    expect(html).toContain('<pre><code>const x = 1;\nconst y = 2;</code></pre>');
  });

  it('renders unordered lists', () => {
    expect(renderMarkdown('- one\n- two')).toContain('<ul><li>one</li><li>two</li></ul>');
  });

  it('renders GFM tables (CVSS metric tables)', () => {
    const html = renderMarkdown('| Metric | Value |\n|---|---|\n| Attack Vector | Network |');
    expect(html).toContain('<table class="md-table">');
    expect(html).toContain('<th>Metric</th>');
    expect(html).toContain('<td>Attack Vector</td>');
  });

  it('strips GitHub <details> wrappers and surfaces <summary> text', () => {
    const html = renderMarkdown('<details><summary>poc.js</summary>\n\nthe body\n\n</details>');
    expect(html).not.toContain('details');
    expect(html).toContain('poc.js');
    expect(html).toContain('the body');
  });
});

describe('renderMarkdown — adversarial XSS (advisory content is semi-untrusted)', () => {
  const payloads: Array<[string, string]> = [
    ['event handler in img', '<img src=x onerror="alert(1)">'],
    ['script in heading', '## <script>alert(1)</script>'],
    [
      'script inside a <summary>',
      '<details><summary><img src=x onerror=alert(1)></summary>b</details>',
    ],
    ['bold wrapping raw html', '**<b onclick="x">hi</b>**'],
    ['html in a table cell', '| a | b |\n|---|---|\n| <img src=x onerror=1> | y |'],
    ['html in a list item', '- <iframe src=javascript:alert(1)>'],
    ['attribute breakout via link url', '[x](https://e.com" onmouseover="alert(1))'],
  ];

  // Output is composed only from this fixed tag whitelist. Stripping those tags
  // must leave NO `<` behind — i.e. nothing the attacker injected survives as
  // live markup. (Escaped text like `&lt;img ... onerror=...` is inert and is
  // expected: it renders the advisory faithfully without executing.)
  const WHITELIST = /<\/?(?:p|br|h4|pre|code|ul|ol|li|table|tr|th|td|strong|a)\b[^>]*>/gi;

  for (const [name, src] of payloads) {
    it(`emits no live markup beyond the whitelist: ${name}`, () => {
      const html = renderMarkdown(src);
      expect(html.replace(WHITELIST, '')).not.toContain('<');
      // Any anchor that IS emitted must carry an http(s) href — never javascript:/data:.
      for (const tag of html.match(/<a\b[^>]*>/gi) ?? []) {
        expect(tag).toMatch(/href="https?:/i);
      }
    });
  }

  it('escapes injected tags rather than dropping them (faithful + inert)', () => {
    expect(renderMarkdown('<img src=x onerror=alert(1)>')).toContain('&lt;img');
  });

  it('only ever emits anchors with a validated http(s) href', () => {
    const html = renderMarkdown('see [docs](https://example.com/x?a=1&b=2)');
    expect(html).toContain('href="https://example.com/x?a=1&amp;b=2"');
    // every <a> in the output carries the safe rel
    for (const m of html.matchAll(/<a\b[^>]*>/g)) {
      expect(m[0]).toContain('rel="noopener noreferrer"');
    }
  });
});

describe('renderMarkdown — the cookie-advisory regression', () => {
  // The bug: a real advisory body collapsed into one unreadable run-on <p>.
  // The fix must produce structured blocks instead of a single text node.
  it('splits a multi-section advisory into distinct block elements', () => {
    const body = [
      '## 5. Description',
      '',
      'The `cookies.read()` function builds a RegExp from the cookie name.',
      '',
      '```javascript',
      "document.cookie.match(new RegExp('(?:^|; )' + name));",
      '```',
    ].join('\n');
    const html = renderMarkdown(body);
    expect(html).toContain('<h4 class="md-h">5. Description</h4>');
    expect(html).toContain('<p>');
    expect(html).toContain('<pre><code>');
    // No raw markdown syntax leaking into the rendered output.
    expect(html).not.toContain('## 5');
    expect(html).not.toContain('```');
  });
});
