// server.js
// Simple Express server that lists iptables rules and can apply/remove simple rules.
// IMPORTANT: Run and test only in a safe environment (VM / Docker with --cap-add=NET_ADMIN).

const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const basicAuth = require('basic-auth');
const path = require('path');
const ipt = require('./iptablesHelper');

const app = express();
app.use(helmet());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Simple HTTP Basic auth for demo (replace with stronger auth for real use)
const USERNAME = process.env.FWM_USER || 'admin';
const PASSWORD = process.env.FWM_PASS || 'password';
function requireAuth(req, res, next) {
  const user = basicAuth(req);
  if (!user || user.name !== USERNAME || user.pass !== PASSWORD) {
    res.set('WWW-Authenticate', 'Basic realm="Firewall Manager"');
    return res.status(401).send('Authentication required.');
  }
  next();
}

// API: get current rules (iptables-save output parsed)
app.get('/api/rules', requireAuth, async (req, res) => {
  try {
    const text = await ipt.listRules();
    const parsed = ipt.parseIptablesSave(text);
    res.json({ ok: true, parsed });
  } catch (e) {
    console.error('GET /api/rules error', e);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// API: preview a rule command (dry-run)
app.post('/api/rules/preview', requireAuth, (req, res) => {
  try {
    const cmd = ipt.buildInsertCmd(req.body);
    res.json({ ok: true, cmd });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// API: apply a rule with safe rollback window
app.post('/api/rules', requireAuth, async (req, res) => {
  try {
    const opts = req.body;
    ipt.validateRuleInput(opts);

    const backup = await ipt.backupRules();
    const rollbackDelay = typeof req.body.rollbackDelay === 'number' ? req.body.rollbackDelay : 60;
    const rollbackTimer = ipt.scheduleRestore(backup, rollbackDelay);

    const result = await ipt.applyRule(opts);

    ipt.cancelScheduledRestore(rollbackTimer);
    res.json({ ok: true, result });
  } catch (e) {
    console.error('POST /api/rules error', e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// API: delete a rule by exact rule-string match
app.post('/api/rules/delete', requireAuth, async (req, res) => {
  try {
    const { ruleLine } = req.body;
    if (!ruleLine || typeof ruleLine !== 'string') throw new Error('ruleLine required');
    const backup = await ipt.backupRules();
    const rollbackTimer = ipt.scheduleRestore(backup, 60);

    const result = await ipt.deleteRuleByExactLine(ruleLine);
    ipt.cancelScheduledRestore(rollbackTimer);
    res.json({ ok: true, result });
  } catch (e) {
    console.error('POST /api/rules/delete', e);
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// Restore endpoint
app.post('/api/restore', requireAuth, async (req, res) => {
  try {
    const { backupPath } = req.body;
    if (!backupPath) throw new Error('backupPath required');
    await ipt.restoreFromFile(backupPath);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Firewall Rule Manager running on port ${PORT}`));
