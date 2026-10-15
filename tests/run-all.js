'use strict';
const { summary } = require('./lib');

(async () => {
  await require('./phishing.test')();
  await require('./wazuh.test')();
  summary();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
