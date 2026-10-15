#!/usr/bin/env node
'use strict';
/**
 * Generates prompts/*.md from the Code nodes in the workflows, so the documented
 * prompts can never drift from what the workflows really send to the model.
 *
 *   node scripts/generate-prompts.js          write the files
 *   node scripts/generate-prompts.js --check  fail if the files are out of date
 */
const fs = require('fs');
const path = require('path');
const { loadWorkflow, runCode, ROOT } = require('../tests/lib');

const CHECK = process.argv.includes('--check');

async function extract(workflowFile, nodeName, input) {
  const { byName } = loadWorkflow(workflowFile);
  const [out] = await runCode(byName, nodeName, { json: input });
  const body = out.json.requestBody;
  return {
    system: body.systemInstruction.parts[0].text,
    schema: body.generationConfig.responseSchema,
    temperature: body.generationConfig.temperature,
  };
}

function render({ title, pipeline, node, intro, system, schema, temperature, notes }) {
  return `# ${title}

> Generated from the **${node}** Code node of \`${pipeline}\` by \`scripts/generate-prompts.js\`. Do not edit by hand: change the workflow, then run \`npm run prompts\`.

${intro}

## System prompt

\`\`\`text
${system}
\`\`\`

## Structured output schema

The model is called with \`responseMimeType: application/json\` and the schema below (temperature ${temperature}), so the reply can be parsed deterministically by the report node.

\`\`\`json
${JSON.stringify(schema, null, 2)}
\`\`\`

## Design notes

${notes.map((n) => `- ${n}`).join('\n')}
`;
}

(async () => {
  const phishing = await extract('workflows/phishing-analysis.json', 'Build AI Request', { email: {}, urlResults: [], attachmentResults: [] });
  const wazuh = await extract('workflows/wazuh-alert-triage.json', 'Build WZ AI Request', { alert: {}, enrichment: {}, signals: {} });

  const files = {
    'prompts/phishing-analyst.md': render({
      title: 'Phishing analyst prompt',
      pipeline: 'workflows/phishing-analysis.json',
      node: 'Build AI Request',
      intro: 'Used by the **Phishing & Attachment Analysis** pipeline. The user message contains the email metadata, the URLScan/VirusTotal results per URL and the SHA-256 lookups per attachment, serialised as JSON.',
      ...phishing,
      notes: [
        'Email text, file names and tool output are declared **untrusted data**, which is the first line of defence against prompt injection from the email body.',
        'Absence of a file in VirusTotal is explicitly **not** treated as proof of safety.',
        'Risk levels are defined in the prompt and re-rendered with a matching colour by the **Build Report** node.',
        'The workflow keeps the original context (`ctx`) next to the request so the report never depends on which branch ran.',
      ],
    }),
    'prompts/wazuh-triage.md': render({
      title: 'Wazuh triage prompt',
      pipeline: 'workflows/wazuh-alert-triage.json',
      node: 'Build WZ AI Request',
      intro: 'Used by the **Wazuh Alert Triage** pipeline. The user message contains the normalised alert, the enrichment results (URL, IP, hash) and a small `signals` object with the strongest threat-intelligence indicators.',
      ...wazuh,
      notes: [
        'The model proposes a verdict, but **deterministic guard rails** in the **Build WZ Report** node have the last word: a VirusTotal count of 10 or more is always Critical, an AbuseIPDB score of 75 or more is at least High, and the EICAR test file is capped at Medium and labelled as a test artefact.',
        'If the AI call fails, the alert is **never dropped**: it is reported as a True Positive with a "manual review required" banner.',
        'Alerts with no extractable IOC are judged from the rule level, description, MITRE mapping and log line only.',
      ],
    }),
  };

  let stale = false;
  for (const [rel, content] of Object.entries(files)) {
    const target = path.join(ROOT, rel);
    if (CHECK) {
      const current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : '';
      if (current !== content) {
        console.error(`${rel} is out of date. Run: npm run prompts`);
        stale = true;
      }
    } else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, content);
      console.log(`wrote ${rel}`);
    }
  }
  if (CHECK) {
    if (stale) process.exit(1);
    console.log('Prompt documentation is up to date.');
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
