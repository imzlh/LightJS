import { Cookies, Handler, Headers, Response, WebSocket } from "http";
import { exit, self, signals, stdout } from "process";
import { bind } from "socket";

// console.log('create temp server');
// const server_close = bind('tcp://127.0.0.1:81', async (client, addr) => {
//     console.log('server got connection', addr);
//     await client.write(encodeStr('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 21\r\n\r\nMicrosoft Connect Test'));
//     while(true){
//         const data = await client.readline();
//         if(!data || data?.length == 0) break;
//         console.log(decodeStr(data), '\n');
//     }
//     client.close();
//     server_close();
// }, { onclose: () => console.log('server closed') });

// self.signal(signals.SIGINT, () => {
//     server_close();
//     console.log('exit');
//     exit(0);
// });

await test('fetch', async () => {
    // await delay(3000);  // wait async bind syscall
    console.log("fetch start");
    const response = await fetch('https://captive.apple.com/', {
        // note: keepalive会导致fd被占用测试完无法自动退出
        keepalive: false,
        method: 'GET'
    });
    console.log(response);
    assert(response instanceof Response);
    // for ts
    if(!(response instanceof Response)) return;
    console.log(response.ok, response.status, response.headers);
    // assert(response.status === 200);
    // assert(response.ok);
    const text = await response.text();
    console.log(text);
    console.log("fetch end");
    assert(text.includes('Success'));
})

// await test('ws-server', async () => {
//     const server_close = bind('tcp://127.0.0.1:8000', async (client, addr) => {
//         try{
//             var handler = await Handler.from(client);
//         }catch(e){
//             console.log(e);
//             return;
//         }
//         console.log('server got connection', addr);
//         const ws = handler.ws();
//         ws.onmessage = (data, is_fin) => {
//             if(typeof data == 'string') console.log('from client:', data);
//             else console.log('from client:', decodeStr(data));
//         };
//         await ws.send('hello');
//         console.log('server send hello');
//     });

//     self.signal(signals.SIGINT, () => {
//         server_close();
//         console.log('exit');
//         exit(0);
//     });
// });

// await delay(1000);

// await test('websocket', async () => {
//     // const ws = await fetch('ws://172.23.224.1:8000');
//     // const ws = await fetch('ws://127.0.0.1:8000');
//     const ws = await fetch('ws://172.23.224.1:8000');
//     if(!(ws instanceof WebSocket)) return;
//     ws.onmessage = (data, is_fin) => {
//         if(typeof data == 'string') console.log(data);
//         else console.log(decodeStr(data));
//     }
//     ws.send('hello');
//     await delay(1000);
//     ws.send('world');
//     await delay(1000);
//     ws.close();
// });

export {};

// test('url', () => {
//     for(const url of [
//         // 基础正常案例
//         "http://www.google.com",
//         "https://user:pass@www.example.com:8080/path?query=string#hash",
//         "ftp://ftp.example.com/path/file.txt",
//         "ws://localhost:8080/path?query=string#hash",
//         "/path/file.txt",
        
//         // 边界案例
//         // 1. 协议相关
//         "hTtP://example.com",  // 混合大小写协议
//         "custom://test.com",   // 自定义协议
//         "//example.com/path",  // 无协议(继承当前协议)
        
//         // 2. 认证相关
//         "http://user:pa@ss@example.com",  // 密码含@符号
//         "http://%E4%B8%AD%E6%96%87:密码@example.com",  // Unicode用户名密码
//         "http://:pass@example.com",  // 空用户名
        
//         // 3. 域名相关
//         "http://例子.测试",  // 国际化域名
//         "http://[2001:db8::1]",  // IPv6地址
//         "http://.example.com",  // 空子域名
        
//         // 4. 端口相关
//         "http://example.com:0",  // 最小端口
//         "http://example.com:65535",  // 最大端口
        
//         // 5. 路径相关
//         "http://example.com/../etc/passwd",  // 路径回溯
//         "http://example.com/%2F%2Ftest",  // 双重编码
//         "http://example.com/测试?name=@admin",  // Unicode路径
        
//         // 6. 查询参数相关
//         "http://example.com?a=1&a=2",  // 重复参数
//         "http://example.com?key=&empty",  // 空值参数
//         "http://example.com?q=<script>alert(1)</script>",  // 特殊字符
        
//         // 7. 片段相关
//         "http://example.com#fragment@test",  // 含特殊字符片段
//         "http://example.com#",  // 空片段
//     ]) try{
//         const url2 = new URL(url);
//         console.log(
//             url2.protocol,
//             url2.username,
//             url2.password,
//             url2.host,
//             url2.port,
//             url2.path,
//             url2.getQuery(),
//             url2.hash
//         );
//     }catch(e){
//         console.log(url, e);
//         throw e;
//     }
// })


// test('url_invalid', () => {
//     for(const url of [
//         "://:",  // 完全无效
//         "///////path?",  // 无协议和域名
//         "  http://example.com  ",  // 前后空格
//         "http://example.com:80abc",  // 非数字端口
//         "http://example.com:65536",  // 超出范围端口
//         "http://example.com#fragment@test",  // 含特殊字符片段
//         "http://[127.0.0.1:8080]",  // 无效IPV6
//     ]) try{
//         const url2 = new URL(url);
//         throw new Error(`url "${url}" should be invalid`);
//     }catch{
//         console.log(url, "is invalid");
//     }
// })


// test('cookiejar', () => {
//     const cookiejar = new Cookies({ "a": "v" });
//     cookiejar.set('name', 'value');
//     cookiejar.set('name2', 'value2');
//     cookiejar.fromSetCookies([
//         "name=value; path=/; domain=example.com"
//     ]);
//     cookiejar.fromCookies(['a=b; c=d']);
//     cookiejar.del('name');
//     console.log(cookiejar, cookiejar.getAll());
//     assert(cookiejar.get('name2') == 'value2');
//     assert(cookiejar.get('name') == null);
//     assert(cookiejar.getAll()['a'] == 'b');
// })

// test('header', () => {
//     const header = new Headers();
//     header.append('a', 'v');
//     header.set('a', 'v2');
//     header.delete('a');
//     header.append('b', 'v');
//     header.append('b', 'v2');
//     console.log(header);
//     assert(header.getall('b').length == 2);
// })