import fs from 'fs';
import child_process from 'child_process';

import tld from 'tldjs';
import CIDR from 'cidr-js';

let cidr = new CIDR();

const XML_PATH = './ChinaCIDR_forProxifier.xml';
const COMBINE_LINES = 1000;

function getChinaIPRange() {
  let stdout = child_process.execSync(`curl 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest' | grep ipv4 | grep CN | awk -F\\| '{ printf("%s/%d\\n", $4, 32-log($5)/log(2)) }'`);
  let lines = stdout.toString().split(/\n/);
  return lines.map((line) => {
    if (line.replace(/\s*/,'') !== '') {
      return cidr.range(line).start + '-' + cidr.range(line).end;
    } else {
      return null;
    }
  }).filter(line => line);
}

function getWhiteList() {
  let stdout = child_process.execSync(`curl 'https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf' | grep server | awk -F/ '{print $2}'`);
  return stdout.toString().split(/\n/).map((line) => `*.${line}`);
}

function getGFWList() {
  let stdout = child_process.execSync(`curl 'https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt' | base64 --decode`);
  let lines = stdout.toString().split(/\n/);
  return lines.map((line) => {
    if (line.startsWith('.') && tld.isValid(line.slice(1))) {
      return `*${line}`;
    } else {
      return tld.getDomain(line);
    }
  }).filter(line => line);
}


function splitArray(arr, length) {
  let newArr = [];
  while(arr.length) {
    newArr.push(arr.splice(0, length));
  }
  return newArr;
}

function buildRule(label, rules, type) {
  return `
<Rule enabled="true">
  <Name>${label}</Name>
  <Targets>${rules.join(';')}</Targets>
  <Action type="${type}" />
</Rule>
`;
}

let IPRanges = splitArray(getChinaIPRange(), COMBINE_LINES);
let WhiteList = splitArray(getWhiteList(), COMBINE_LINES);
// let GFWList = splitArray(getGFWList(), COMBINE_LINES);

let xmlContent = '';

// GFWList.forEach((rules, i) => {
//   xmlContent += buildRule('GFWList-' + (i + 1), rules, 'Proxy');
// });

WhiteList.forEach((rules, i) => {
  xmlContent += buildRule('WhiteList-' + (i + 1), rules, 'Direct');
});

IPRanges.forEach((rules, i) => {
  xmlContent += buildRule('CHINA-IP-' + (i + 1), rules, 'Direct');
});

fs.writeFileSync(XML_PATH, xmlContent);

console.log('All done!');
