import { connect } from "socket"

test('tls', async () => {
    const tlsconn = connect('tls://baidu.com', {
        timeout: 1
    });
    await tlsconn.write(encodeStr('GET / HTTP/1.1\r\nHost: baidu.com\r\n\r\n'));
    while(true){
        console.log(await tlsconn.readline());
    }
})
