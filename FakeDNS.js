//fakedns.js port of fakedns.py with added missing support.

const dgram = require('dgram');
const fs = require('fs');
const { argv } = require('yargs')
  .option('c', { alias: 'config', demandOption: true, describe: 'Path to configuration file', type: 'string' })
  .option('i', { alias: 'iface', default: '0.0.0.0', describe: 'Interface IP address to bind to', type: 'string' })
  .option('p', { alias: 'port', default: 53, describe: 'Port to bind to', type: 'number' })
  .option('rebind', { type: 'boolean', default: false, describe: 'Enable DNS rebinding' })
  .option('dns', { type: 'string', default: '8.8.8.8', describe: 'Upstream DNS server' })
  .option('noforward', { type: 'boolean', default: false, describe: 'Don\'t forward unmatched queries' });

const TYPE = {
  'A': 0x0001,
  'AAAA': 0x001c,
  'CNAME': 0x0005,
  'PTR': 0x000c,
  'TXT': 0x0010,
  'MX': 0x000f,
  'SOA': 0x0006
};

function encodeDomainName(domain) {
  const parts = domain.split('.');
  const buffers = parts.map(part => {
    const len = Buffer.alloc(1);
    len.writeUInt8(part.length);
    return Buffer.concat([len, Buffer.from(part)]);
  });
  return Buffer.concat([...buffers, Buffer.from([0x00])]);
}

function toUInt32BE(num) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(num, 0);
  return buf;
}

function isShorthandIPv6(ip) {
  return ip.includes('::') || ip.split(':').some(x => x.length < 4);
}

function expandIPv6(ip) {
  if (!isShorthandIPv6(ip)) return ip;
  const [head, tail = ''] = ip.split('::');
  const headParts = head.split(':').filter(Boolean);
  const tailParts = tail.split(':').filter(Boolean);
  const middle = Array(8 - (headParts.length + tailParts.length)).fill('0000');
  return [...headParts, ...middle, ...tailParts].map(p => p.padStart(4, '0')).join(':');
}

function buildA(ip) {
  return Buffer.from(ip.split('.').map(x => parseInt(x)));
}

function buildAAAA(ipv6) {
  return Buffer.from(
    expandIPv6(ipv6).split(':').flatMap(part => {
      const num = parseInt(part, 16);
      return [num >> 8, num & 0xff];
    })
  );
}

function buildCNAME(domain) {
  return encodeDomainName(domain);
}

function buildPTR(domain) {
  return encodeDomainName(domain);
}

function buildTXT(txt) {
  const buf = Buffer.from(txt);
  return Buffer.concat([Buffer.from([buf.length]), buf]);
}

function buildMX(preference, exchange) {
  const prefBuf = Buffer.alloc(2);
  prefBuf.writeUInt16BE(preference, 0);
  return Buffer.concat([prefBuf, encodeDomainName(exchange)]);
}

function buildSOA(ns, hostmaster, serial, refresh, retry, expire, minimum) {
  return Buffer.concat([
    encodeDomainName(ns),
    encodeDomainName(hostmaster),
    toUInt32BE(serial),
    toUInt32BE(refresh),
    toUInt32BE(retry),
    toUInt32BE(expire),
    toUInt32BE(minimum)
  ]);
}

class Rule {
  constructor(type, domainRegex, ips, rebinds, threshold) {
    this.type = type;
    this.regex = new RegExp(domainRegex, 'i');
    this.ips = this._roundRobin(ips);
    this.rebinds = rebinds ? this._roundRobin(rebinds) : null;
    this.threshold = threshold || 1;
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

function parseRules(file) {
  const rules = [];
  fs.readFileSync(file, 'utf-8').split('\n').forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 3) throw new Error(`Malformed rule at line ${i + 1}`);
    const [rtype, regex, ipPart, rebindPart] = parts;
    if (!(rtype in TYPE)) throw new Error(`Unknown type '${rtype}' at line ${i + 1}`);
    const ips = ipPart.split(',');
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
  const qtype = msg.readUInt16BE(msg.length - 4);
  const qname = msg.slice(12, msg.length - 4);
  let offset = 12, domain = '';
  while (msg[offset]) {
    const len = msg[offset];
    domain += msg.slice(offset + 1, offset + 1 + len).toString() + '.';
    offset += len + 1;
  }
  domain = domain.slice(0, -1);
  return { id, domain, qtype, raw: msg };
}

function buildResponse(query, dataBuffer, typeCode) {
  const header = Buffer.alloc(12);
  query.id.copy(header);
  header.writeUInt16BE(0x8180, 2); // standard query response, no error
  header.writeUInt16BE(1, 4);      // QDCOUNT
  header.writeUInt16BE(1, 6);      // ANCOUNT

  const question = query.raw.slice(12);

  const answer = Buffer.concat([
    Buffer.from([0xc0, 0x0c]),
    Buffer.from([typeCode >> 8, typeCode & 0xff]),
    Buffer.from([0x00, 0x01]),                 // Class IN
    Buffer.from([0x00, 0x00, 0x00, 0x3c]),     // TTL 60s
    Buffer.from([0x00, dataBuffer.length]),
    dataBuffer
  ]);

  return Buffer.concat([header, question, answer]);
}

function buildNoneFound(query) {
  const header = Buffer.alloc(12);
  query.id.copy(header);
  header.writeUInt16BE(0x8183, 2); // NXDOMAIN
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, query.raw.slice(12)]);
}

function TYPE_INV(code) {
  return Object.keys(TYPE).find(k => TYPE[k] === code);
}

const rules = parseRules(argv.config);
const server = dgram.createSocket('udp4');

server.on('message', (msg, rinfo) => {
  try {
    const query = parseQuery(msg);
    const domain = query.domain;
    const srcIp = rinfo.address;
    const rtype = TYPE_INV(query.qtype);

    console.log(`[DNS] Query ${rtype} ${domain} from ${srcIp}`);

    const rule = rules.find(r => r.match(rtype, domain, srcIp));
    if (!rule) {
      if (argv.noforward) {
        server.send(buildNoneFound(query), rinfo.port, rinfo.address);
      } else {
        const upstream = dgram.createSocket('udp4');
        upstream.send(msg, 53, argv.dns, () => {
          upstream.on('message', response => {
            server.send(response, rinfo.port, rinfo.address);
            upstream.close();
          });
        });
      }
      return;
    }

    const result = rule.match(rtype, domain, srcIp);
    let dataBuffer;

    switch (query.qtype) {
      case TYPE.A: dataBuffer = buildA(result); break;
      case TYPE.AAAA: dataBuffer = buildAAAA(result); break;
      case TYPE.CNAME: dataBuffer = buildCNAME(result); break;
      case TYPE.PTR: dataBuffer = buildPTR(result); break;
      case TYPE.TXT: dataBuffer = buildTXT(result); break;
      case TYPE.MX: dataBuffer = buildMX(10, result); break;
      case TYPE.SOA:
        dataBuffer = buildSOA('ns1.example.com', 'hostmaster.example.com', 20250801, 3600, 1800, 604800, 86400);
        break;
      default:
        dataBuffer = buildA('127.0.0.1');
    }

    const response = buildResponse(query, dataBuffer, query.qtype);
    server.send(response, rinfo.port, rinfo.address);
  } catch (err) {
    console.error('Failed to process DNS query:', err);
  }
});

server.on('listening', () => {
  const addr = server.address();
  console.log(`FakeDNS listening on ${addr.address}:${addr.port}`);
});

server.bind(argv.port, argv.iface);
