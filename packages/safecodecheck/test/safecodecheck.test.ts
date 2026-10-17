import { describe, expect, it } from 'vitest';
import { analyzeSource } from '../src/index.js';
import plugin from '../src/eslint.js';
import { parseSource } from '../src/analyze.js';

const rules = (src: string, file = 'a.tsx') => analyzeSource(src, file).findings.map((f) => [f.ruleId, f.severity, f.location?.line]);

describe('DOM insertion', () => {
  it('flags dynamic innerHTML and escalates tainted sources', () => {
    expect(
      rules(`
el.innerHTML = '<b>static</b>';
el.innerHTML = userBio;
el.innerHTML = location.hash.slice(1);
el.innerHTML = DOMPurify.sanitize(userBio);
el.insertAdjacentHTML('beforeend', \`<li>\${name}</li>\`);
document.write(param);
el.textContent = userBio;
`),
    ).toEqual([
      ['dom-unsafe-html', 'high', 3],
      ['dom-unsafe-html', 'critical', 4],
      ['dom-unsafe-html', 'high', 6],
      ['dom-unsafe-html', 'high', 7],
    ]);
  });

  it('checks React dangerouslySetInnerHTML', () => {
    expect(
      rules(`
const A = () => <div dangerouslySetInnerHTML={{ __html: post.body }} />;
const B = () => <div dangerouslySetInnerHTML={{ __html: sanitize(post.body) }} />;
const C = () => <div dangerouslySetInnerHTML={{ __html: '<hr/>' }} />;
`),
    ).toEqual([['react-dangerous-html', 'high', 2]]);
  });

  it('checks Vue, Svelte and Angular escape hatches', () => {
    expect(rules(`<template><div v-html="comment.body"></div></template>\n<script setup lang="ts">\nconst x = 1\n</script>`, 'C.vue')).toEqual([
      ['framework-unsafe-html', 'medium', 1],
    ]);
    expect(rules(`{@html $page.url.searchParams}`, 'P.svelte')[0]?.[0]).toBe('framework-unsafe-html');
    expect(rules(`this.html = this.sanitizer.bypassSecurityTrustHtml(input);`, 'c.component.ts')[0]?.[0]).toBe('framework-unsafe-html');
  });
});

describe('dynamic code execution', () => {
  it('flags eval, Function and string timers but not function timers', () => {
    expect(
      rules(`
eval(code);
new Function('a', body);
setTimeout("refresh()", 100);
setTimeout(() => refresh(), 100);
setInterval(tick, 100);
`),
    ).toEqual([
      ['dynamic-code-execution', 'high', 2],
      ['dynamic-code-execution', 'high', 3],
      ['dynamic-code-execution', 'medium', 4],
    ]);
  });

  it('flags shell commands built from input', () => {
    expect(rules('const { exec } = require("child_process");\nexec(`git log ${req.query.branch}`);', 'a.js')).toEqual([['command-injection', 'critical', 2]]);
    expect(rules('child_process.execFile("git", ["log", branch]);', 'a.js')).toEqual([]);
  });
});

describe('insecure randomness', () => {
  it('only flags Math.random() in security-sensitive contexts', () => {
    expect(
      rules(`
const sessionToken = Math.random().toString(36).slice(2);
function generatePassword() { return Math.random().toString(36); }
const user = { apiKey: Math.random().toString(16) };
const jitter = Math.random() * 100;
const items = list.map((x) => <li key={Math.random()}>{x}</li>);
`),
    ).toEqual([
      ['insecure-randomness', 'high', 2],
      ['insecure-randomness', 'high', 3],
      ['insecure-randomness', 'high', 4],
    ]);
  });
});

describe('URL handling', () => {
  it('flags redirects, javascript: URLs and postMessage issues', () => {
    expect(
      rules(`
window.location.href = new URLSearchParams(location.search).get('next');
location.assign(target);
location.href = '/home';
const a = <a href={params.get('url')}>go</a>;
const b = <a href="javascript:alert(1)">x</a>;
const c = <a href="javascript:void(0)">x</a>;
frame.contentWindow.postMessage(data, '*');
window.addEventListener('message', (e) => handle(e.data));
window.addEventListener('message', (e) => { if (e.origin !== ORIGIN) return; handle(e.data); });
`),
    ).toEqual([
      ['open-redirect', 'high', 2],
      ['open-redirect', 'medium', 3],
      ['open-redirect', 'high', 5],
      ['javascript-url', 'medium', 6],
      ['postmessage-wildcard', 'medium', 8],
      ['message-origin-unchecked', 'medium', 9],
    ]);
  });
});

describe('reporting', () => {
  it('honours suppression comments', () => {
    expect(rules(`// safecodecheck-disable-next-line dom-unsafe-html -- reviewed\nel.innerHTML = x;\nel.innerHTML = y; // safecodecheck-disable-line`)).toEqual([]);
  });

  it('includes location, snippet, remediation and CWE', () => {
    const [f] = analyzeSource('const x = 1;\n  el.innerHTML = userInput;', 'src/a.ts').findings;
    expect(f).toMatchObject({ location: { file: 'src/a.ts', line: 2, column: 3 }, snippet: 'el.innerHTML = userInput;', tags: ['CWE-79'] });
    expect(f?.remediation).toMatch(/textContent/);
  });

  it('parses TypeScript with casts and generics', () => {
    expect(rules('const el = document.getElementById("x") as HTMLElement;\nel!.innerHTML = <string>value;', 'a.ts')).toEqual([['dom-unsafe-html', 'high', 2]]);
  });

  it('keeps going on syntax errors', () => {
    const r = analyzeSource('el.innerHTML = x;\nconst = ;', 'a.js');
    expect(r.findings.length + (r.error ? 1 : 0)).toBeGreaterThan(0);
  });
});

describe('ESLint plugin', () => {
  it('reports through the ESLint rule API', () => {
    const src = 'el.innerHTML = userInput;';
    const { ast } = parseSource(src, 'a.js');
    const reports: unknown[] = [];
    const rule = plugin.rules['dom-unsafe-html']!;
    const visitor = rule.create({ sourceCode: { text: src }, report: (d) => reports.push(d) });
    visitor['Program:exit'](ast);
    expect(reports).toHaveLength(1);
    expect(plugin.configs.recommended).toBeDefined();
  });
});
