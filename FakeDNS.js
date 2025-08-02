// fakedns.js - Node.js port of fakedns.py

const dgram = require('dgram');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const { argv } = require('yargs')
  .option('c', { alias: 'config', demandOption: true, describe: 'Path to configuration file', type: 'string' })
  .option('i', { alias: 'iface', default: '0.0.0.0', describe: 'Interface IP address to bind to', type: 'string' })
  .option('p', { alias: 'port', default: 53, describe: 'Port to bind to', type: 'number' })
  .option('rebind', { type: 'boolean', default: false, describe: 'Enable DNS rebinding' })
  .option('dns', { type: 'string', default: '8.8.8.8', describe: 'Upstream DNS server' })
  .option('noforward', { type: 'boolean', default: false, describe: 'Don\'t forward unmatched queries' })
  .option('non-authoritative', { type: 'boolean', default: false, describe: 'Set authoritative flag off' });

const TYPE = {
  'A': 0x0001,
  'AAAA': 0x001c,
  'CNAME': 0x0005,
  'PTR': 0x000c,
  'TXT': 0x0010,
  'MX': 0x000f,
  'SOA': 0x0006
};

function isShorthandIPv6(ip) {
  return ip.includes('::') || ip.split(':').some(x => x.length < 4);
}

function expandIPv6(ip) {
  if (!isShorthandIPv6(ip)) return ip;
  let parts = ip.split('::');
  let head = parts[0].split(':');
  let tail = parts[1] ? parts[1].split(':') : [];
  while (head.length + tail.length < 8) head.push('0000');
  return [...head, ...tail].map(x => x.padStart(4, '0')).join(':');
}

function buildA(ip) {
  return Buffer.from(ip.split('.').map(x => parseInt(x)));
}

function buildAAAA(ipv6) {
  let expanded = expandIPv6(ipv6);
  return Buffer.from(expanded.split(':').map(h => parseInt(h, 16) >> 8).concat(expanded.split(':').map(h => parseInt(h, 16) & 0xff)));
}

class Rule {
  constructor(type, domainRegex, ips, rebinds, threshold) {
    this.type = type;
    this.regex = new RegExp(domainRegex, 'i');
    this.ips = this._roundRobin(ips);
    this.rebinds = rebinds ? this._roundRobin(rebinds) : null;
    this.threshold = threshold;
    this.history = {};
  }
  _roundRobin(list) {
    let i = 0;
    return () => {
      const val = list[i];
      i = (i + 1) % list.length;
      return val;
    };
  }
  match(qtype, domain, srcIp) {
    if (qtype !== this.type || !this.regex.test(domain)) return null;
    if (this.rebinds) {
      this.history[srcIp] = (this.history[srcIp] || 0) + 1;
      if (this.history[srcIp] >= this.threshold) return this.rebinds();
    }
    return this.ips();
  }
}

function parseRules(configPath) {
  const lines = fs.readFileSync(configPath, 'utf-8').split('\n');
  const rules = [];
  lines.forEach((line, index) => {
    line = line.trim();
    if (!line || line.startsWith('#')) return;
    const parts = line.split(/\s+/);
    if (parts.length < 3) throw new Error(`Malformed rule at line ${index + 1}`);
    let [rtype, regex, ipPart, rebindPart] = parts;
    if (!(rtype in TYPE)) throw new Error(`Unknown type ${rtype} on line ${index + 1}`);
    let ips = ipPart.split(',');
    let rebinds = null, threshold = 1;
    if (rebindPart && rebindPart.includes('%')) {
      const [t, r] = rebindPart.split('%');
      threshold = parseInt(t);
      rebinds = r.split(',');
    }
    rules.push(new Rule(rtype, regex, ips, rebinds, threshold));
  });
  return rules;
}

function parseQuery(msg) {
  const id = msg.slice(0, 2);
  const flags = msg.slice(2, 4);
  const qdcount = msg.readUInt16BE(4);
  let offset = 12;
  let domain = '';
  while (msg[offset]) {
    const len = msg[offset];
    domain += msg.slice(offset + 1, offset + 1 + len).toString() + '.';
    offset += len + 1;
  }
  offset += 1;
  const qtype = msg.readUInt16BE(offset);
  return { id, domain, qtype, raw: msg };
}

function buildResponse(query, dataBuffer, typeCode) {
  const header = Buffer.alloc(12);
  query.id.copy(header);
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(1, 6);

  const qname = query.raw.slice(12, query.raw.length - 4);
  const qtype = query.raw.slice(query.raw.length - 4);
  const question = Buffer.concat([qname, qtype]);

  const answer = Buffer.concat([
    Buffer.from([0xc0, 0x0c]),
    Buffer.from([typeCode >> 8, typeCode & 0xff]),
    Buffer.from([0x00, 0x01]),
    Buffer.from([0x00, 0x00, 0x00, 0x3c]),
    Buffer.from([0x00, dataBuffer.length]),
    dataBuffer
  ]);

  return Buffer.concat([header, question, answer]);
}

function buildNoneFound(query) {
  const header = Buffer.alloc(12);
  query.id.copy(header);
  header.writeUInt16BE(0x8183, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(0, 6);
  return Buffer.concat([header, query.raw.slice(12)]);
}

const rules = parseRules(argv.config);
const server = dgram.createSocket('udp4');

server.on('message', (msg, rinfo) => {
  try {
    const query = parseQuery(msg);
    console.log(`[DNS] Query from ${rinfo.address}:${rinfo.port} for ${query.domain} (Type ${TYPE_INV(query.qtype)})`);

    const domain = query.domain;
    const srcIp = rinfo.address;
    const rule = rules.find(r => r.match(TYPE_INV(query.qtype), domain, srcIp));
    if (!rule) {
      console.log(`[MISS] No rule matched for ${domain}`);
      if (argv.noforward) {
        server.send(buildNoneFound(query), rinfo.port, rinfo.address);
        return;
      }
      const upstream = dgram.createSocket('udp4');
      upstream.send(msg, 53, argv.dns, () => {
        upstream.on('message', response => {
          server.send(response, rinfo.port, rinfo.address);
          upstream.close();
        });
      });
      return;
    }
    const ip = rule.match(TYPE_INV(query.qtype), domain, srcIp);
    console.log(`[MATCH] Rule matched for ${domain}: Responding with IP ${ip}`);
    
    let dataBuffer;
    if (query.qtype === TYPE.A) dataBuffer = buildA(ip);
    else if (query.qtype === TYPE.AAAA) dataBuffer = buildAAAA(ip);
    else dataBuffer = Buffer.from([127, 0, 0, 1]);
    
    const response = buildResponse(query, dataBuffer, query.qtype);
    server.send(response, rinfo.port, rinfo.address);
  } catch (err) {
    console.error('Error handling query:', err);
  }
});

server.on('listening', () => {
  const addr = server.address();
  console.log(`FakeDNS listening on ${addr.address}:${addr.port}`);
});

server.bind(argv.port, argv.iface);

function TYPE_INV(code) {
  return Object.keys(TYPE).find(key => TYPE[key] === code);
}
