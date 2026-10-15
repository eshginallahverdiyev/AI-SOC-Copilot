#!/usr/bin/env node
'use strict';
/**
 * Static validation of every exported n8n workflow in ./workflows
 *  - valid JSON with the expected top-level keys
 *  - unique node names and ids
 *  - every connection points at an existing node
 *  - every $('Node Name') reference points at an existing node
 *  - no embedded credentials, no personal e-mail addresses, no API-key-like strings
 *  - every Code node compiles (syntax check, nothing is executed)
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..');
const WORKFLOWS = path.join(ROOT, 'workflows');
const ALLOWED_EMAILS = new Set(['YOUR_EMAIL@gmail.com']);

function listJson(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return listJson(p);
    return e.name.endsWith('.json') ? [p] : [];
  });
}

const errors = [];
const fail = (file, msg) => errors.push(`${path.relative(ROOT, file)}: ${msg}`);

const SECRET_PATTERNS = [
  [/AIza[0-9A-Za-z_-]{35}/, 'Google API key'],
  [/\bsk-[A-Za-z0-9]{20,}/, 'OpenAI-style secret key'],
  [/\bgh[pousr]_[A-Za-z0-9]{36,}/, 'GitHub token'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key'],
  [/(x-apikey|api[_-]?key|auth[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}/i, 'hard-coded API key'],
  [/Bearer\s+[A-Za-z0-9._-]{20,}/, 'bearer token'],
];

let checked = 0;
for (const file of listJson(WORKFLOWS)) {
  checked += 1;
  const raw = fs.readFileSync(file, 'utf8');
  let wf;
  try {
    wf = JSON.parse(raw);
  } catch (e) {
    fail(file, `invalid JSON (${e.message})`);
    continue;
  }

  for (const key of ['name', 'nodes', 'connections']) {
    if (!(key in wf)) fail(file, `missing top-level key "${key}"`);
  }
  if (!Array.isArray(wf.nodes)) continue;

  const names = new Set();
  const ids = new Set();
  for (const n of wf.nodes) {
    if (names.has(n.name)) fail(file, `duplicate node name "${n.name}"`);
    names.add(n.name);
    if (ids.has(n.id)) fail(file, `duplicate node id "${n.id}"`);
    ids.add(n.id);
    if (n.credentials) fail(file, `node "${n.name}" embeds credentials`);
  }

  for (const [src, conn] of Object.entries(wf.connections || {})) {
    if (!names.has(src)) fail(file, `connection source "${src}" does not exist`);
    for (const branch of conn.main || []) {
      for (const link of branch) {
        if (!names.has(link.node)) fail(file, `connection "${src}" -> "${link.node}": target does not exist`);
      }
    }
  }

  for (const n of wf.nodes) {
    const blob = JSON.stringify(n.parameters || {});
    for (const m of blob.matchAll(/\$\(\\?['"]([^'"\\]+)\\?['"]\)/g)) {
      if (!names.has(m[1])) fail(file, `node "${n.name}" references missing node "${m[1]}"`);
    }
    if (n.type === 'n8n-nodes-base.code') {
      try {
        new vm.Script(`(async function () {\n${n.parameters.jsCode}\n})`, { filename: `${n.name}.js` });
      } catch (e) {
        fail(file, `Code node "${n.name}" has a syntax error: ${e.message}`);
      }
    }
  }

  for (const m of raw.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)) {
    if (!ALLOWED_EMAILS.has(m[0])) fail(file, `contains e-mail address "${m[0]}" (use the YOUR_EMAIL@gmail.com placeholder)`);
  }
  for (const [re, label] of SECRET_PATTERNS) {
    if (re.test(raw)) fail(file, `looks like it contains a ${label}`);
  }
}

if (errors.length) {
  console.error(`Workflow validation failed (${errors.length} problem${errors.length === 1 ? '' : 's'}):`);
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}
console.log(`Workflow validation passed: ${checked} workflow files checked.`);
