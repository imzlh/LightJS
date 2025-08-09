import { bind, upgradeTLS } from "socket"

test('httpsServer', () => {
    const close = bind('tls://localhost:8443', async (client, addr) => {
        console.log('New client connected from', addr);
        
        // upgrade to TLS
        upgradeTLS(client, {
            server: true,
        })
    })
})