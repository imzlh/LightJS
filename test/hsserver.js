import { bind } from "socket"

test('httpsServer', () => {
    const close = bind('tls://localhost:8443', async (client, addr) => {
        console.log('New client connected from', addr);
        await client.write(encodeStr('Hello, world!'));
        client.close();
    })
})