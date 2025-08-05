import { read } from "fs";
import Server from "../../lib/http/server";
import { Process, signals } from "process";

// 1. 创建服务器
const $server = new Server('0.0.0.0:4445', true);

// 2. 设置回调函数
$server.callback = (client, addr) => {
    // 3. 处理路径
    const url = new URL(client.request.path);

    if(url.path == '/'){
        // 4. 发送响应
        client.send(
            read(import.meta.dirname + "/index.html", true)
        ).header('Content-Type', 'text/html').done();
    }else{
        // 5. websocket升级
        const ws = client.ws();

        // 6. 创建子进程
        const proc = new Process(['/bin/sh'], {
            inheritPipe: false,
            env: {
                "TERM": "xterm-256color",
                "OLDPWD": import.meta.dirname,
                "COLORTERM": "truecolor",
            }
        });

        // 7. 重定向子进程的输入输出
        ws.send(`Welcome to WebTTY!\r\n`);
        ws.send(`Type 'exit' to exit the session.\r\n`);

        (async () => {
            while(true){
                const data = await proc.pipe.read();
                if(!data) continue;
                ws.send(data);
            }
        })().catch(() => ws.close()).catch(Boolean);

        ws.onmessage = (data, is_fin, is_binary) => {
            if(is_binary)
                proc.pipe.write(data);
            else{
                const j = JSON.parse(decodeStr(data));
                const { row, col } = j;
                proc.pipe.ttySize = [row, col];
            }
        };

        ws.closed.then(() => {
            Process.kill(proc.pid, signals.SIGQUIT);
        });
    }
}

// 8. 启动服务器
$server.run();