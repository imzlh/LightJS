import { read, write } from "fs";
import { self } from "process";

const textSSR = self.args[0];

// 0. check input
if (!textSSR) {
    throw new Error('Please provide SSR link as first argument');
}

// 1. get Content
// using LightJS built-in fetch
const fe = await fetch(textSSR);
console.log('Got', fe.status, fe.ok);
const js = await fe.text();
console.log(js);
console.log('Got', js.length, 'bytes from server');

// 2. parse Content
const proxyies = [];
for (const line of js.split(/[\r\n]+/)) try{
    const [proto, content_base64] = line.split('://');
    const json = JSON.parse(atob(content_base64));
    /**
     * {"v":"2","ps":"...","add":"127.0.0.1",
     * "port":"443","id":"04b6142d-2eac-4730-a630-ca0924776f75","aid":"0","net":"tcp",
     * "type":"none","host":"","path":"","tls":""}
     */
    proxyies.push({
        proto,
        ...json
    });
}catch{
    throw new Error(`Invalid line, make sure your SSR link is correct: ${line}`);
}
console.log('Got', proxyies.length, 'proxyies');

// 3. get template
const tp = read(import.meta.dirname + '/template.yaml', true);

// 4. generate config to replace {{template:proxies}} and {{template:proxies-list}}
const mainSlot = proxyies.reduce((acc, cur) => {
    /**
     * - name: ...
        type: vmess
        server: 127.0.0.1
        port: 443
        uuid: 04b6142d-2eac-4730-a630-ca0924776f75
        alterId: 0
        cipher: auto
        udp: true
     */
    acc += `
  - name: ${cur.name}
    port: ${cur.port}    
    type: ${cur.proto}
    tls: ${cur.tls == '' ? 'false' : 'true'}
    server: ${cur.add}
    uuid: ${cur.id}
    alterId: ${cur.aid}
    cipher: auto
    udp: ${cur.net == 'udp' ? 'true' : 'false'}

`}, ''), listSlot = proxyies.reduce((acc, cur) => {
    acc += `      - ${cur.name}\n`
});

// 5. replace template
write(
    self.args[1] ?? 'config.yaml',
    tp.replace('{{template:proxies}}', mainSlot)
        .replace('{{template:proxies-list}}', listSlot)
)
console.log('Config generated to', self.args[1] ?? 'config.yaml');

export { }