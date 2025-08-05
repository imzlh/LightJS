import { Process } from "process";
import { bind } from "socket";
import TP from './protocol';

export class TelnetServer {
    #server_close;

    /**
     * 
     * @param {U8Pipe} client 
     */
    static async handle(client){
        await client.write(encodeStr("Welcome to Telnet Server\r\n"));
        const config = {
            echo: true,
        }

        try{
            const pty = new Process(["/bin/bash"], {
                inheritPipe: false,
                env: {
                    TERM: "linux",
                    COLORTERM: "truecolor",
                    TERM_PROGRAM: "vscode",
                    LANG: "en_US.UTF-8",
                    PATH: "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                },
                cwd: "/"
            });
            if(!pty.pipe) throw new Error("Failed to create pty");
            const pipe = pty.pipe;
            client.pipeTo(pty.pipe, (data) => {
                // debug?
                console.log(`PTY -> Client:`, decodeStr(data));
                // parse telnet command
                if(data.includes(TP.IAC)){
                    const pos = data.indexOf(TP.IAC);
                    if([TP.DO, TP.DONT, TP.WILL, TP.WONT].includes(data[pos+1])){
                        const cmd = data[pos+1];
                        let resp = (cmd == TP.DO || cmd == TP.DONT) ? TP.DONT : TP.WONT;
                        switch(data[pos+2]){
                            case TP.ECHO:   // ECHO
                                config.echo = cmd === TP.DO;
                                resp = TP.DO;
                                break;
                        }
                        client.write(new Uint8Array([TP.IAC, resp, data[pos+2]]));
                    }else if(data[pos+1] == TP.AYT){
                        client.write(new Uint8Array([TP.IAC, TP.AYT]));
                    }else if(data[pos+1] == TP.SB){
                        const buf = [];
                        for(let i = pos+2; i < data.length; i++){
                            if(data[i] == TP.IAC && data[i+1] == TP.SE){
                                break;
                            }
                            buf.push(data[i]);
                        }

                        switch(buf[0]){
                            case TP.NAWS:
                                const [, rows, cols] = buf;
                                pipe.ttySize = [ rows, cols ];
                                break;
                            case TP.LINEMODE:
                                const mode = buf[1];
                                if(mode == 0){
                                    pipe.ttyRaw(true);
                                }else if(mode == 1){
                                    pipe.ttyRaw(false);
                                }
                                break;
                            case TP.TTYPE:
                                const term = buf.slice(2).join('');
                                console.log(`Terminal type: ${term}`);
                                break;
                            case TP.X_DISPLAY_LOCATION:
                                const display = buf.slice(1).join('');
                                console.log(`X display location: ${display}`);
                                break;
                            case TP.ENVIRONMENT_OPTION:
                                const [key, value] = buf.slice(1).join('').split('=');
                                console.log(`Environment option: ${key}=${value}`);
                                break;
                        }
                    }
                    return false;   // block
                }
                if(config.echo){
                    client.write(data);
                }
                return true;    // pass
            });
            pipe.pipeTo(client, (data) => {
                client.write(data);
                return true;    // pass
            });
            client.onclose.then(() => {
                pipe.close();
                console.log(`Client closed`);
            });
            pty.onclose.then(() => {
                client.close();
                console.log(`Pty closed`);
            });
            pty.pipe.ttyTitle = "LightJS Telnet Server";
            pty.pipe.ttySize = [24, 80];
            console.log(`New client connected, pid=${pty.pid}, active=${pty.code}`)
        }catch(e){
            console.error('Handle client error', e);
            await client.write(encodeStr("Error: " + /** @type {Error} */ (e).message + "\r\n"));
            client.close();
        }
    }

    /**
     * 
     * @param {string} addr 
     */
    constructor(addr){
        this.#server_close = bind(addr, (client, addr) => {
            console.log(`New connection from`, addr);
            TelnetServer.handle(client);
        });
    }

    close(){
        this.#server_close();
    }
}