'use strict';
/**
 * Tiny dependency-free harness that executes the JavaScript of n8n "Code" nodes
 * outside n8n, with mocked n8n globals ($, $json, $input, $itemIndex, ...).
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

function loadWorkflow(relPath) {
  const wf = JSON.parse(fs.readFileSync(path.join(ROOT, relPath), 'utf8'));
  const byName = Object.fromEntries(wf.nodes.map((n) => [n.name, n]));
  return { wf, byName };
}

function loadSample(relPath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'samples', relPath), 'utf8'));
}

/**
 * Run a Code node.
 * opts.json         -> current item json ($json / $input.item.json)
 * opts.binary       -> current item binary
 * opts.nodes        -> { 'Node Name': [{ json, binary }, ...] } used by $('Node Name')
 * opts.staticData   -> object returned by $getWorkflowStaticData('global')
 * opts.buffers      -> { propertyName: Buffer } for this.helpers.getBinaryDataBuffer
 * opts.withRequire  -> expose Node's require() (n8n only exposes it when allowed)
 */
async function runCode(byName, nodeName, opts = {}) {
  const node = byName[nodeName];
  if (!node) throw new Error(`Unknown node: ${nodeName}`);
  const item = { json: opts.json || {}, binary: opts.binary };
  const nodes = opts.nodes || {};
  const $ = (name) => {
    const data = nodes[name];
    if (!data) throw new Error(`No mock data for $('${name}')`);
    return { first: () => data[0], last: () => data[data.length - 1], all: () => data, item: data[0] };
  };
  const $input = { first: () => item, all: () => [item], item };
  const staticData = opts.staticData || {};
  const helpers = {
    getBinaryDataBuffer: async (_i, prop) => {
      const buf = (opts.buffers || {})[prop];
      if (!buf) throw new Error('no binary buffer');
      return buf;
    },
  };
  const params = ['$', '$json', '$input', '$itemIndex', '$getWorkflowStaticData'];
  const args = [$, item.json, $input, 0, () => staticData];
  if (opts.withRequire) {
    params.push('require');
    args.push(require);
  }
  const fn = new AsyncFunction(...params, node.parameters.jsCode);
  const out = await fn.apply({ helpers }, args);
  return Array.isArray(out) ? out : [out];
}

let passed = 0;
let failed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed += 1;
    failures.push({ name, err });
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

function summary() {
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
}

module.exports = { ROOT, loadWorkflow, loadSample, runCode, test, section, summary };
