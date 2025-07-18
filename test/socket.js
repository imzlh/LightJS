import { exit, self, signals } from "process";
import { bind, connect } from "socket"

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

await test('remote http', async () => {
    const client = connect("tcp://172.23.224.1:8000");
    client.onclose.catch(e => console.log("client: client connect failed", e));
    client.onclose.then(e => console.log("client: client closed"));

    for(const line of [
        "GET / HTTP/1.1",
        "Host: www.google.com",
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