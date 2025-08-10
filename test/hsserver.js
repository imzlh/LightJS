import { Certificate } from "crypto";
import { read } from "fs";
import { self } from "process";
import { bind, regCert, unregCert, upgradeTLS } from "socket"

self.cwd = import.meta.dirname;

test('globalCert', () => {
    regCert("localhost", read('server.crt', true), read('server.key', true));
    assert(unregCert("localhost"));
})

test('httpsServer', () => {
    const defcert = new Certificate(read('server.crt', true));
    const defkey = Certificate.parseKey(read('server.key', true));
    const close = bind('tcp://0.0.0.0:8443', async (client, addr) => {
        console.log('New client connected from', addr);
        
        // upgrade to TLS
        await upgradeTLS(client, {
            server: true,
            alpn: ['http/1.1'],
            hostname: 'localhost',
            cert: defcert,
            key: defkey,
            // sni: true
        });
    }, {
        reuseaddr: false
    })
})