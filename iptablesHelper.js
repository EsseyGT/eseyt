// iptablesHelper.js
// Helper functions to interact with iptables safely.

const { execFile } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const ipaddr = require('ipaddr.js');

function execCommand(cmd, args = []) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`${cmd} ${args.join(' ')} failed: ${stderr || err.message}`));
      resolve(stdout);
    });
  });
}

async function listRules() {
  const out = await execCommand('sh', ['-c', 'iptables-save -c']);
  return out;
}

function parseIptablesSave(text) {
  const lines = text.split('\n');
  const chains = [];
  const rules = [];
  for (const line of lines) {
    if (!line) continue;
    if (line.startsWith(':')) chains.push(line);
    else if (line.startsWith('-A') || line.startsWith('-I')) rules.push(line);
  }
  return { chains, rules, raw: text };
}

function validateRuleInput(opts) {
  const allowedChains = ['INPUT', 'OUTPUT', 'FORWARD'];
  if (!opts.chain || !allowedChains.includes(opts.chain)) throw new Error('Invalid chain');
  if (!opts.jump) throw new Error('jump target required (ACCEPT/DROP/REJECT)');
  const j = opts.jump.toUpperCase();
  if (!['ACCEPT', 'DROP', 'REJECT'].includes(j)) throw new Error('Invalid jump');

  if (opts.src && !isValidIpOrCidr(opts.src)) throw new Error('Invalid src IP/CIDR');
  if (opts.dst && !isValidIpOrCidr(opts.dst)) throw new Error('Invalid dst IP/CIDR');
  if (opts.proto && !['tcp', 'udp', 'icmp', 'all'].includes(opts.proto.toLowerCase())) throw new Error('Invalid protocol');
  if (opts.dport && (isNaN(opts.dport) || opts.dport < 1 || opts.dport > 65535)) throw new Error('Invalid dport');
}

function isValidIpOrCidr(s) {
  try {
    if (s.includes('/')) {
      const [ip, prefix] = s.split('/');
      if (!ipaddr.isValid(ip)) return false;
      const p = parseInt(prefix, 10);
      return p >= 0 && p <= (ipaddr.process(ip).kind() === 'ipv6' ? 128 : 32);
    }
    return ipaddr.isValid(s);
  } catch {
    return false;
  }
}

function buildInsertCmd(opts) {
  validateRuleInput(opts);
  const parts = ['iptables', '-I', opts.chain];
  if (opts.proto && opts.proto !== 'all') parts.push('-p', opts.proto);
  if (opts.src) parts.push('-s', opts.src);
  if (opts.dst) parts.push('-d', opts.dst);
  if (opts.sport) parts.push('--sport', String(opts.sport));
  if (opts.dport) parts.push('--dport', String(opts.dport));
  parts.push('-j', opts.jump.toUpperCase());
  return parts.join(' ');
}

async function applyRule(opts) {
  const cmd = buildInsertCmd(opts);
  const out = await execCommand('sh', ['-c', cmd]);
  return out;
}

async function backupRules() {
  const out = await execCommand('sh', ['-c', 'iptables-save -c']);
  const fname = path.join('/tmp', `fw-backup-${Date.now()}.rules`);
  await fs.writeFile(fname, out, { mode: 0o600 });
  return fname;
}

function scheduleRestore(backupPath, seconds = 60) {
  const tid = setTimeout(async () => {
    try {
      await restoreFromFile(backupPath);
      console.warn(`Automatic restore executed from ${backupPath}`);
    } catch (e) {
      console.error('Automatic restore failed', e);
    }
  }, seconds * 1000);
  return { backupPath, tid };
}

function cancelScheduledRestore(timerObj) {
  if (timerObj) clearTimeout(timerObj.tid);
}

async function restoreFromFile(backupPath) {
  const content = await fs.readFile(backupPath, 'utf8');
  const tmp = backupPath + '.apply';
  await fs.writeFile(tmp, content, { mode: 0o600 });
  await execCommand('sh', ['-c', `iptables-restore < ${tmp}`]);
  return true;
}

async function deleteRuleByExactLine(ruleLine) {
  const snapshot = await listRules();
  const lines = snapshot.split('\n');
  const idx = lines.findIndex(l => l.trim() === ruleLine.trim());
  if (idx === -1) throw new Error('Rule not found');

  const delLine = ruleLine.replace(/^-(A|I)\s+/, '-D ');
  await execCommand('sh', ['-c', `iptables ${delLine.substr(2)}`]);
  return { deleted: true };
}

module.exports = {
  listRules,
  parseIptablesSave,
  buildInsertCmd,
  applyRule,
  backupRules,
  scheduleRestore,
  cancelScheduledRestore,
  restoreFromFile,
  deleteRuleByExactLine,
  validateRuleInput,
  isValidIpOrCidr
};
