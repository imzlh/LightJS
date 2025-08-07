import { exit, self, signals } from "process";
import { bind, connect, resolveDNS } from "socket"

// const port = (Math.random() * 10000 + 10000).toFixed(0);
const port = 8080;

test('server', async () => {
    const server = bind("tcp://0.0.0.0:" + port, async function(client, addr){
        console.log("server: client connected", addr);
        client.write(encodeStr("hello"));
        client.write(encodeStr("world"));
        client.write(encodeStr("!"));
        await client.sync();
        client.close();
        server();   // close
        console.log("server: client disconnected", addr);
    }, {
        reuseaddr: true,
        onclose: () => console.log("server closed")
    });
    console.log("server started");

    self.signal(signals.SIGINT, () => {
        server();   // close
        console.log("server stopped");
        exit(0);
    });
})

await test('client', async () => {
    await delay(1000);
    const client = connect("tcp://127.0.0.1:" + port);
    client.onclose.catch(e => console.log("client: client connect failed", e));
    client.onclose.then(e => console.log("client: client closed"));
    for(let i = 0; i < 3; i++){
        const data = await client.readline();
        assert(data);
        // @ts-expect-error
        console.log(decodeStr(data));
    }
    // @ts-ignore
    console.log(decodeStr(data));
    client.close();
})

await test('async_dns', async () => {
    const res = await resolveDNS("www.bing.com", "114.114.114.114");
    assert(res.length > 0);
    console.log(res);
})

await test('remote http', async () => {
    const ip = await resolveDNS("www.baidu.com", "114.114.114.114");
    // @ts-ignore
    const client = connect(`tls://${ip.filter(x => x.type === 'A')[0].data}:443`);
    client.onclose.catch(e => console.log("client: client connect failed", e));
    client.onclose.then(e => console.log("client: client closed"));

    for(const line of [
        "POST / HTTP/1.1",
        "Host: www.baidu.com",
        "Connection: close",
        "Content-Length: 1",
        "",
        "a"
    ]) client.write(encodeStr(line + "\r\n"));
    await client.sync();
    while(true){
        const data = await client.readline();
        if(!data){
            break;
        }
        console.log(decodeStr(data));
    }
    console.log("client: remote http test done");
    client.close();
});