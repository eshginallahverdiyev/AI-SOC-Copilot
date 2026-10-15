'use strict';
const assert = require('assert');
const { loadWorkflow, loadSample, runCode, test, section } = require('./lib');

const { byName } = loadWorkflow('workflows/wazuh-alert-triage.json');

// n8n's Webhook node delivers the POST body under "body".
const asWebhook = (body) => ({ headers: {}, params: {}, query: {}, body });
const normalize = (body, staticData = {}) => runCode(byName, 'Normalize Alert', { json: asWebhook(body), staticData }).then(([o]) => o.json);

module.exports = async function run() {
  section('Wazuh pipeline: Normalize Alert');

  await test('EICAR file alert: SHA-256 is selected as the hash IOC', async () => {
    const a = await normalize(loadSample('wazuh/eicar-file-added.json'));
    assert.strictEqual(a.hash, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
    assert.strictEqual(a.hasHash, true);
    assert.strictEqual(a.hasIp, false);
    assert.strictEqual(a.ruleId, '87105');
    assert.strictEqual(a.filePath, '/tmp/eicar.com');
  });

  await test('SSH brute-force alert: public source IP extracted, agent and MITRE kept', async () => {
    const a = await normalize(loadSample('wazuh/ssh-bruteforce-malicious-ip.json'));
    assert.strictEqual(a.ip, '162.243.103.246');
    assert.strictEqual(a.hasIp, true);
    assert.strictEqual(a.level, 12);
    assert.strictEqual(a.agent.name, 'DESKTOP-TEST');
    assert.deepStrictEqual(a.mitre.id, ['T1078', 'T1110']);
  });

  await test('ransomware alert: destination IP extracted', async () => {
    const a = await normalize(loadSample('wazuh/ransomware-c2-connection.json'));
    assert.strictEqual(a.ip, '45.147.231.17');
    assert.strictEqual(a.hasHash, false);
  });

  await test('download alert: URL extracted from data.url', async () => {
    const a = await normalize(loadSample('wazuh/suspicious-download-url.json'));
    assert.strictEqual(a.url, 'https://secure.eicar.org/eicar.com');
    assert.strictEqual(a.hasUrl, true);
  });

  await test('alert without IOCs (new user) is still normalised for context-only triage', async () => {
    const a = await normalize(loadSample('wazuh/new-user-created.json'));
    assert.strictEqual(a.hasUrl || a.hasIp || a.hasHash, false);
    assert.strictEqual(a.ruleId, '5902');
    assert.ok(a.fullLog.includes('name=hacker'));
  });

  await test('accepts a raw Wazuh alert without the all_fields wrapper', async () => {
    const raw = loadSample('wazuh/ssh-bruteforce-malicious-ip.json').all_fields;
    const a = await normalize(raw);
    assert.strictEqual(a.ip, '162.243.103.246');
  });

  await test('private and loopback addresses are not treated as IOCs', async () => {
    const a = await normalize({ rule: { id: '1', level: 3 }, agent: { id: '1' }, data: { srcip: '192.168.1.10' }, full_log: 'from 10.0.0.5 and 127.0.0.1 and 172.20.1.1' });
    assert.strictEqual(a.hasIp, false);
  });

  await test('falls back to scanning full_log for a public IP', async () => {
    const a = await normalize({ rule: { id: '2', level: 5 }, agent: { id: '1' }, full_log: 'Failed password from 198.51.100.77 port 22' });
    assert.strictEqual(a.ip, '198.51.100.77');
  });

  await test('deduplicates identical alerts within the window, then lets them through again', async () => {
    const sd = {};
    const sample = loadSample('wazuh/ssh-bruteforce-malicious-ip.json');
    const first = await normalize(sample, sd);
    const second = await normalize(sample, sd);
    assert.strictEqual(first.isNew, true);
    assert.strictEqual(second.isNew, false);
    for (const k of Object.keys(sd.seen)) sd.seen[k] -= 6 * 60 * 1000;
    const third = await normalize(sample, sd);
    assert.strictEqual(third.isNew, true);
  });

  await test('different rules / agents / IOCs are not deduplicated against each other', async () => {
    const sd = {};
    const a = await normalize(loadSample('wazuh/ssh-bruteforce-malicious-ip.json'), sd);
    const b = await normalize(loadSample('wazuh/ransomware-c2-connection.json'), sd);
    assert.strictEqual(a.isNew, true);
    assert.strictEqual(b.isNew, true);
  });

  section('Wazuh pipeline: enrichment context');

  const alertFor = async (sample) => ({ json: await normalize(loadSample(sample)) });

  await test('Build WZ Context aggregates VirusTotal, MalwareBazaar and AbuseIPDB signals', async () => {
    const hashAlert = await alertFor('wazuh/eicar-file-added.json');
    const [out] = await runCode(byName, 'Build WZ Context', {
      nodes: {
        'Normalize Alert': [hashAlert],
        'WZ VT Hash': [{ json: { data: { attributes: { last_analysis_stats: { malicious: 66, suspicious: 0, harmless: 0 }, meaningful_name: 'eicar.com', type_description: 'EICAR', popular_threat_classification: { suggested_threat_label: 'virus.eicar/test' } } } } }],
        'WZ MalwareBazaar': [{ json: { query_status: 'hash_not_found' } }],
      },
    });
    assert.strictEqual(out.json.signals.maxMalicious, 66);
    assert.strictEqual(out.json.signals.malwareBazaarHit, false);
    assert.strictEqual(out.json.enrichment.hash.virustotal.threatLabel, 'virus.eicar/test');
    assert.strictEqual(out.json.ioc.hash, hashAlert.json.hash);
  });

  await test('Build WZ Context: failed lookups become "unverified", not "clean"', async () => {
    const hashAlert = await alertFor('wazuh/eicar-file-added.json');
    const [out] = await runCode(byName, 'Build WZ Context', {
      nodes: {
        'Normalize Alert': [hashAlert],
        'WZ VT Hash': [{ json: { error: { message: 'NotFoundError' } } }],
        'WZ MalwareBazaar': [{ json: { error: { message: 'timeout' } } }],
      },
    });
    assert.strictEqual(out.json.enrichment.hash.virustotal.found, false);
    assert.ok(/not proof of safety/.test(out.json.enrichment.hash.virustotal.note));
    assert.strictEqual(out.json.signals.maxMalicious, 0);
  });

  await test('Build WZ Context: IP enrichment feeds the AbuseIPDB score signal', async () => {
    const ipAlert = await alertFor('wazuh/ssh-bruteforce-malicious-ip.json');
    const [out] = await runCode(byName, 'Build WZ Context', {
      nodes: {
        'Normalize Alert': [ipAlert],
        'WZ VT IP': [{ json: { data: { attributes: { last_analysis_stats: { malicious: 16, suspicious: 0 }, as_owner: 'DigitalOcean, LLC', country: 'US' } } } }],
        'WZ AbuseIPDB': [{ json: { data: { abuseConfidenceScore: 80, totalReports: 12, countryCode: 'US', isp: 'DigitalOcean' } } }],
      },
    });
    assert.strictEqual(out.json.signals.maxMalicious, 16);
    assert.strictEqual(out.json.signals.abuseScore, 80);
  });

  section('Wazuh pipeline: AI request and deterministic guard rails');

  await test('AI request treats alert content as untrusted and carries the EICAR rule', async () => {
    const ctx = { alert: { description: 'x', ruleId: '1', level: 5 }, ioc: {}, enrichment: {}, signals: { maxMalicious: 0, abuseScore: 0, malwareBazaarHit: false } };
    const [out] = await runCode(byName, 'Build WZ AI Request', { json: ctx });
    const sys = out.json.requestBody.systemInstruction.parts[0].text;
    assert.ok(/UNTRUSTED DATA/.test(sys));
    assert.ok(/EICAR/.test(sys));
    assert.deepStrictEqual(out.json.requestBody.generationConfig.responseSchema.properties.classification.enum, ['True Positive', 'False Positive']);
    assert.deepStrictEqual(out.json.ctx, ctx);
  });

  const aiReply = (o) => ({ candidates: [{ content: { parts: [{ text: JSON.stringify(o) }] } }] });
  const ai = (o) => ({ classification: 'False Positive', risk_level: 'Low', confidence: 80, summary: 'summary', reasons: ['r'], recommended_actions: ['a'], mitre_techniques: [], ...o });
  const report = async ({ aiOut, signals = {}, alert = {}, ioc = {}, enrichment = {} }) => {
    const ctx = {
      alert: { timestamp: 't', ruleId: '100', level: 12, description: 'desc', mitre: {}, agent: { name: 'a' }, filePath: null, fullLog: 'log', ...alert },
      ioc,
      enrichment,
      signals: { maxMalicious: 0, abuseScore: 0, malwareBazaarHit: false, ...signals },
    };
    const [out] = await runCode(byName, 'Build WZ Report', {
      json: aiOut === null ? { error: { message: '503' } } : aiReply(aiOut),
      nodes: { 'Build WZ AI Request': [{ json: { ctx } }] },
    });
    return out.json;
  };

  await test('no signals and AI says False Positive: routed to the false-positive log', async () => {
    const r = await report({ aiOut: ai({}) });
    assert.strictEqual(r.isTP, false);
    assert.strictEqual(r.classification, 'False Positive');
    assert.strictEqual(r.override, '');
  });

  await test('VirusTotal >= 10 overrides an AI "Low / False Positive" verdict to Critical', async () => {
    const r = await report({ aiOut: ai({}), signals: { maxMalicious: 16 } });
    assert.strictEqual(r.risk, 'Critical');
    assert.strictEqual(r.isTP, true);
    assert.ok(/Rule override/.test(r.override));
  });

  await test('MalwareBazaar match with >= 5 VirusTotal detections is Critical', async () => {
    const r = await report({ aiOut: ai({}), signals: { malwareBazaarHit: true, maxMalicious: 6 } });
    assert.strictEqual(r.risk, 'Critical');
  });

  await test('AbuseIPDB >= 75 raises the risk to at least High', async () => {
    const r = await report({ aiOut: ai({}), signals: { abuseScore: 80 } });
    assert.strictEqual(r.risk, 'High');
    assert.strictEqual(r.isTP, true);
  });

  await test('guard rails never lower an AI verdict that is already higher', async () => {
    const r = await report({ aiOut: ai({ classification: 'True Positive', risk_level: 'Critical' }), signals: { abuseScore: 80 } });
    assert.strictEqual(r.risk, 'Critical');
  });

  await test('EICAR test file: True Positive, but risk capped at Medium and flagged as a test', async () => {
    const eicar = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    const r = await report({
      aiOut: ai({ classification: 'False Positive', risk_level: 'Critical' }),
      ioc: { hash: eicar },
      signals: { maxMalicious: 66 },
    });
    assert.strictEqual(r.isTP, true);
    assert.strictEqual(r.risk, 'Medium');
    assert.ok(/EICAR/.test(r.override));
  });

  await test('EICAR is also recognised from the file path', async () => {
    const r = await report({ aiOut: ai({ risk_level: 'High' }), alert: { filePath: '/tmp/eicar.com' }, signals: { maxMalicious: 40 } });
    assert.strictEqual(r.risk, 'Medium');
  });

  await test('AI failure fails safe: True Positive, manual review banner, never silently dropped', async () => {
    const r = await report({ aiOut: null });
    assert.strictEqual(r.aiFailed, true);
    assert.strictEqual(r.isTP, true);
    assert.ok(r.html.includes('Manual review required'));
  });

  await test('invalid risk level from the model is normalised to Medium', async () => {
    const r = await report({ aiOut: ai({ classification: 'True Positive', risk_level: 'Apocalyptic' }) });
    assert.strictEqual(r.risk, 'Medium');
  });

  await test('report HTML escapes attacker-controlled alert fields and defangs IOCs', async () => {
    const r = await report({
      aiOut: ai({ classification: 'True Positive', risk_level: 'High', summary: '<script>alert(1)</script>' }),
      alert: { description: '<img src=x onerror=alert(1)>', fullLog: '</pre><script>alert(2)</script>', agent: { name: '<b>x</b>', ip: '203.0.113.5' } },
      enrichment: { ip: { ip: '203.0.113.5', virustotal: 'no data', abuseipdb: 'no data' } },
    });
    assert.ok(!r.html.includes('<script>'));
    assert.ok(!r.html.includes('<img src=x'));
    assert.ok(r.html.includes('203[.]0[.]113[.]5'));
  });

  await test('email subject carries the risk level and rule description', async () => {
    const r = await report({ aiOut: ai({ classification: 'True Positive', risk_level: 'High' }), alert: { description: 'New user added' } });
    assert.strictEqual(r.subject, '[HIGH] Wazuh SOC ALERT - New user added');
  });
};
