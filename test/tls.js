import { connect, resolveDNS } from "socket"

test('tls', async () => {
    const addr = await resolveDNS('baidu.com', '114.114.114.114');
    const v4addr = /** @type {DNS_NORM} */ (addr.filter(a => a.type == 'A')[0]);
    console.log("Trying to connect to ", v4addr.data);
    const tlsconn = connect('tls://' + v4addr.data + ':443', {
        timeout: 1
    });
    await tlsconn.write(encodeStr('GET / HTTP/1.1\r\nHost: baidu.com\r\nConnection: close\r\n\r\n'));
    while(true){
        // @ts-ignore
        console.log(decodeStr(await tlsconn.readline()));
    }
})
