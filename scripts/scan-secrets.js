#!/usr/bin/env node
'use strict';
/**
 * Lightweight repository secret scan (no dependencies).
 * Fails when a text file contains something that looks like a credential or a
 * personal e-mail address. Binary files and generated folders are skipped.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SKIP_DIRS = new Set(['.git', 'node_modules']);
const BINARY_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.zip', '.pdf']);
const ALLOWED_EMAILS = new Set(['YOUR_EMAIL@gmail.com']);
const ALLOWED_EMAIL_DOMAINS = new Set(['example.com', 'example.net', 'example.org', 'users.noreply.github.com', 'b.test']);

const RULES = [
  [/AIza[0-9A-Za-z_-]{35}/, 'Google API key'],
  [/\bsk-[A-Za-z0-9]{20,}/, 'OpenAI-style secret key'],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}/, 'GitHub token'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/, 'Slack token'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key'],
  [/(x-apikey|api[_-]?key|auth[_-]?key|secret|password|token)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{24,}/i, 'hard-coded credential'],
  [/Bearer\s+[A-Za-z0-9._-]{24,}/, 'bearer token'],
];

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return SKIP_DIRS.has(e.name) ? [] : walk(p);
    return BINARY_EXT.has(path.extname(e.name).toLowerCase()) ? [] : [p];
  });
}

const findings = [];
for (const file of walk(ROOT)) {
  const rel = path.relative(ROOT, file);
  const text = fs.readFileSync(file, 'utf8');
  text.split(/\r?\n/).forEach((line, i) => {
    for (const [re, label] of RULES) {
      if (re.test(line)) findings.push(`${rel}:${i + 1} ${label}`);
    }
    for (const m of line.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)) {
      const email = m[0];
      const domain = email.split('@')[1].toLowerCase();
      if (!ALLOWED_EMAILS.has(email) && !ALLOWED_EMAIL_DOMAINS.has(domain)) {
        findings.push(`${rel}:${i + 1} e-mail address ${email}`);
      }
    }
  });
}

if (findings.length) {
  console.error('Secret scan failed:');
  for (const f of findings) console.error(`  - ${f}`);
  process.exit(1);
}
console.log('Secret scan passed: no credentials or personal e-mail addresses found.');
