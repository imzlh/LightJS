import { read } from "fs";
import { Handler } from "http";
import { exit, Process, self, signals } from "process";
import { bind } from "socket";
import { parseArgs } from "../utils/args";

const instances = /** @type {Set<Server>} */ (new Set());

/**
 * @typedef {Object} IErrorStack
 * @property {string} fname
 * @property {string} name
 * @property {number} line
 * @property {number} column
 * @property {Array<string> | undefined} source
 */
const EPAGE = read(import.meta.dirname + "/error.html", true);
export default class Server {
    /**
     * 
     * @param {Error} error
     */
    static error_log(error) {
        const place = '/*{{error}}*/';
        const data = {
            message: error.name + ':'+ error.message,
            stack: this.parse_stack(error)
        };
        return EPAGE.replace(place, JSON.stringify(data) + ';');
    }

    /**
     * 
     * @param {Error} error 
     */
    static parse_stack(error) {
        const stack = error.stack?.split('\n');
        if (!stack) return [];
        const stack_trace = /** @type {IErrorStack[]} */ ([]);
        for (const line of stack) {
            const part = line.match(/at\s+(\S+)\s+\((\S+):(\d+):(\d+)\)/);
            console.debug(part);
            if (part) {
                const [_, function_name, file_name, line, column] = part;
                /** @type {string[]} */ let filectx;

                if(file_name == import.meta.name) continue;

                try {
                    filectx = read(file_name, true).split(/(?:\r?\n|\r)/);
                } catch {
                    filectx = [];
                }

                const lnum = parseInt(line);
                const cnum = parseInt(column);
                stack_trace.push({
                    name: function_name,
                    fname:file_name,
                    line: lnum,
                    column: cnum,
                    source: filectx.slice(lnum - 3, lnum + 2)
                });
            }
        }
        return stack_trace;
    }

    #close_handler;
    /**
     * @type {((client: Handler, addr: IAddr) => any) | undefined}
     */
    #callback;
    #destroyed = false;
    #connections = 0;
    #debug;

    /**
     * 
     * @param {string} addr 
     */
    constructor(addr, debug = true) {
        this.#close_handler = bind('tcp://' + addr, (client, addr) => {
            if (this.#callback) (async () => {
                const handler = await Handler.from(client);
                while(true){
                    this.#connections++;
                    // @ts-ignore
                    console.debug(`New connection from ${addr.type} ${addr.addr}:${addr.port}`);
                    await this.handle(handler, addr)
                        .then(() => this.#connections--)
                    if(client.closed) break;
                }
            })(); else { 
                client.close();
            }
        }, {
            onclose: () => this.#destroyed = true,
            reuseaddr: true
        });
        instances.add(this);
        this.#debug = debug;
    }

    /**
     * 
     * @param {(client: Handler, addr: IAddr) => any} callback 
     */
    set callback(callback) {
        if (typeof callback === 'function') this.#callback = callback;
        else throw new Error('Callback must be a function');
    }

    get connecions() {
        return this.#connections;
    }

    /**
     * @private
     * @param {Handler} handler 
     * @param {IAddr} addr 
     */
    async handle(handler, addr) {
        if (!this.#callback) return handler.close();
        if (this.#destroyed)

        if (handler.request.path.startsWith('/@debug/') && this.#debug){
            const url = new URL(handler.request.path);
            switch (url.path.slice(8)) {
                case 'log':
                    console.log.apply(null, url.getQuery('msg'));
                    handler.status(200).send('ok').done().close();
                break;

                case 'editor':
                    const fname = url.getQuery('file')[0];
                    const line = parseInt(url.getQuery('line')[0]);
                    const col = parseInt(url.getQuery('column')[0]);
                    console.debug(fname, line, col, url.getQuery());

                    if(!fname || isNaN(line) || isNaN(col)){
                        handler.status(400).send('Invalid request').done().close();
                        return;
                    }

                    new Process([
                        'code', '-n', '--goto', `${fname}:${line}:${col}`
                    ], {
                        inheritPipe: true
                    });
                    handler.status(200).send('ok').done().close();
                break;

                default:
                    handler.status(404).send('Not found').done().close();
                break;
            }
            await handler.end;
            return handler.reuse();
        }

        try {
            await this.#callback(handler, addr);
            try{ handler.done(true); } catch {}   // finalizer
            await handler.end;
            console.debug('Connection reset');
            await handler.reuse();
        } catch (e) {
            console.error(e);
            /** @var {string} */ let page;
            if (e instanceof Error) {
                page = Server.error_log(e);
            } else {
                page = `<h1>Internal Server Error</h1><p>${e}</p>`;
            }
            try{    // header可能已经发送
                handler.status(500)
            }catch{}
            try{    // body可能已经结束
                handler.send(page).done();
            }catch{}
            try{    // 可能已经close
                handler.close();
            }catch{}
        }
    }

    run() {
        if (!this.#callback) throw new Error('Callback not set');
    }

    close() {
        this.#close_handler();
        instances.delete(this);
        this.#destroyed = true;
    }
}

const h = () => {
    instances.forEach(i => i.close());
    console.log('Server closed');
    exit(0);
};

self.signal(signals.SIGINT, h);
self.signal(signals.SIGTERM, h);
self.signal(signals.SIGQUIT, h);

// const App = {
//     __addr: '',
//     __status: {
//         599: "ServerAPI Unavailable",
//         500: "Internal Server Error",
//         404: "Not Found",
//         400: "Bad Request"
//     },

//     /**
//      * 
//      * @param {string} api 
//      */
//     async _requestApi(api){
//         const addr = new URL(api, this.__addr);
//         const fe = await fetch(addr.href, {
//             method: 'SERVER:' + api.toUpperCase()
//         });
//         if(!fe.ok){
//             // @ts-ignore
//             throw new Error(`Server API error: ${fe.status} ${this.__status[fe.status] || 'Unknown Error'}`);
//         }
//         return fe.json();
//     },

//     reload(){
//         return this._requestApi('reload');
//     },

//     restart(){
//         return this._requestApi('restart');
//     },

//     status(){
//         return this._requestApi('status');
//     },

//     stop(){
//         return this._requestApi('stop');
//     },

//     run(){

//     }
// };

// /**
//  * @typedef {{description: string, short?: string, long?: string}[]} ExtArgs
//  */

// /**
//  * 
//  * @param {string} AppName 
//  * @param {ExtArgs} AppExtOpts 
//  */
// export async function launch(AppName = 'server', AppExtOpts = []) {
//     const args = parseArgs(self.args);

//     if(args._.includes('help')){
//         console.log(`${AppName} Server
// Usage: ${AppName} [options] [command?] ...

// Commands:
//   status         Show server status
//   stop           Stop server
//   help           Show help

// Options:
//   -a, --addr     Set server address (default: 127.0.0.1:8080)
//   -d, --debug    Enable debug mode (default: false)
//   ${AppExtOpts.map(opt => `${opt.short ? `-${opt.short}, ` : ''}\t${opt.long ? `--${opt.long} ` : ''}\t${opt.description}`).join('\n  ')}

// Copyright (c) 2021 Light.js Development Team. All rights reserved.`);
//     }
// }

// if(import.meta.main) await launch();
