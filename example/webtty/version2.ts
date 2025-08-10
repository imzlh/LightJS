/**
 * 使用原生模块演示
 */

import { read } from "fs";
import { Handler } from "http";
import { Process, signals } from "process";
import { bind, upgradeTLS } from "socket";

// 1. 创建服务器
const $close_handler = bind("tcp://0.0.0.0:4561", async (pipe, addr) => {
    // 2. 捕获错误（必选！LightJS没有处理错误的能力，会导致连接hang住）
    try{
        // 3. 处理请求与路径
        const client = await Handler.from(pipe);
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
    }catch(e){
        console.error(e);
        pipe.close();
    }
}, {
    reuseaddr: false,
    onclose() {
        console.log("Server closed");
    },
});