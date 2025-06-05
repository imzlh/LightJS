import { read } from "fs";
import { Handler } from "http";
import { Process, self, signals } from "process";
import { bind } from "socket";

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
            message: error.message,
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
            if (this.#callback) {
                this.#connections++;
                this.handle(client, addr)
                    .then(() => this.#connections--)
            } else { 
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
     * @param {U8Pipe} client 
     * @param {IAddr} addr 
     */
    async handle(client, addr) {
        if (!this.#callback) return client.close();

        /** @type {Handler} */ let handler;
        try {
            handler = await Handler.from(client);
        } catch (e) {
            client.close();
            console.error(e);
            return;
        }

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
            handler.status(500).send(page).done().close();
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

self.signal(signals.SIGTERM, () => {
    instances.forEach(i => i.close());
    console.log('Server closed');
})