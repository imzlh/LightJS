/**
 * LightJS HTTP module
 * source: src/http.c
 */

type FetchOptions<WebSocket> = {
    method?: string;
    headers?: Record<string, string>;
    keepalive?: boolean;
    referer?: string;
    host?: string;  // 当URL为unix或ip地址时，需要用于指定请求的Host头
    body?: Uint8Array | U8Pipe | string;
    websocket?: WebSocket;
};

/**
 * 使用类似于WebAPI的fetch方法发起HTTP请求<br>
 * 注意
 *  - 不支持压缩，如果需要请自行通过`compress`模块实现
 *  - 支持WebSocket，但需要指定`ws://`协议，返回`WebSocket`
 *  - 支持内建的MbedTLS加密库，但需要指定`https/wss://`协议
 *  - 由于使用C实现，某些方面会与JS实现(如nodejs)有差异
 *  - `websocket`选项不被LightJS理解，但是指定可以让TypeScript提示正确的类型
 */
declare function fetch(url: string, options?: FetchOptions<false | undefined>): Promise<import('http').Response>;

/**
 * 发起WebSocket请求，请求成功后兑现已经连接成功的WebSocket对象
 */
declare function fetch(url: string, options: FetchOptions<true>): Promise<import('http').WebSocket>;

interface FormData {
    name: string;
    filename?: string;
    type?: string;

    data: Uint8Array;
}

declare module 'http' {
    export class Headers {
        constructor();
        append(key: string, value: string): void;
        delete(key: string): boolean;
        get(key: string): string | null;
        getAll(key: string): string[];
        getAll(): Record<string, string[]>;
        set(key: string, value: string): void;
        has(key: string): boolean;
    }

    export class Cookies {
        constructor(headers: Record<string, string> | Array<[string, string]>);
        readonly request: Response;

        set(name: string, value: string): void;
        get(name: string): string | null;
        getAll(): Record<string, string>;
        del(name: string): void;
        toString(): string;

        fromCookies(cookies: string[]): void;
        fromSetCookies(setCookies: string[]): void;
    }

    export class WebSocket {
        private constructor();

        send(data: string | Uint8Array): Promise<void>;
        close(): void;
        /**
         * Setter/ Getter for the onmessage event handler.
         */
        onmessage: (data: Uint8Array, is_fin: boolean, is_binary: boolean) => void;
        ping(data: string | Uint8Array): void;
    
        /**
         * 若兑现undefined，表示非正常关闭，否则为正常关闭，包含code和message字段<br>
         * LightJS没有error事件或不会reject，请小心使用这个Promise
         */
        readonly closed: Promise<undefined | { code: number, message: string }>;
        readonly cookies: Cookies;
    }

    export class Response {
        text(): Promise<string>;
        bytes(): Promise<Uint8Array>;
        json(): Promise<any>;
        formData(): Promise<FormData[]>;

        /**
         * 小心！与WebAPI的`body`属性不一样，获取U8Pipe后Response会locked，<br>
         * 此时其他读取操作（如`text()`）都会报错，无法继续使用流
         */
        pipe(): U8Pipe;

        get locked(): boolean;
        get status(): number;
        get ok(): boolean;

        readonly headers: Headers;
        readonly path: string;         // only for Handler.request
        readonly method: string;       // only for Handler.request
        readonly httpVersion: number;  // only for Handler.request
    }

    export class Handler {
        /**
         * （从Tcp服务器中）构造一个Handler实例
         * @param pipe bind()回调提供的U8Pipe实例，当然只要是基于fd的管道都可以
         */
        static from(pipe: U8Pipe): Promise<Handler>;

        /**
         * 从内建status列表中获取status描述
         */
        static status(status: number): string;

        /**
         * 从内建mimetype列表中获取后缀名的mimetype
         */
        static mimetype(extname: string): string;

        private constructor();

        /**
         * 等待所有数据流写入后关闭连接
         */
        close(): void;

        /**
         * 复用HTTP/1.1连接<br>
         * 复用需要`done()`后调用，只有HTTP请求完全结束后才能使用<br>
         * 复用后仍旧使用调用`reuse()`的`Handler`实例
         */
        reuse(): Promise<this>;

        /**
         * 升级为WebSocket请求
         */
        ws(): WebSocket;

        /**
         * 标记状态码，默认200 OK
         */
        status(code: number): this;
        
        /**
         * 发送数据给客户端<br>
         * 不建议一次性发大量数据，建议分批发送，或者使用`chunked()`开启chunked模式<br>
         * 发送一个小包后使用`wait()`等待成功发送，防止OOM
         * @param data 数据
         */
        send(data: string | Uint8Array | ArrayBuffer): this;

        /**
         * 等待写入任务完成，没有任务则立即兑现
         */
        wait(): Promise<void>;

        /**
         * 结束header内容，立即发送给客户端。之后就可以流式写入body了。<br>
         * 注意
         *  - 除非设置chunked，否则需要提前定义`Content-Length`
         *  - 务必有body，或者指定`done(true)`，否则会一直等待数据
         *  - 如果没有调用`chunked()`，会使用HTTP/1.0，此时不会长连接
         *  - `reuse()`前，务必确保响应处理完毕(`await handler.end`)
         * 
         * @example - 先填body再发送
         * ```ts
         * const handler = Handler.from(pipe);
         * handler.status(200).header('Content-Type', 'text/plain').send('hello').done();
         * ```
         * @example - 先发送header再填body
         * ```ts
         * const handler = Handler.from(pipe);
         * handler.status(200).header('Content-Type', 'text/plain').done().send('hello')
         *  .done(); // 注意done()两次，否则客户端可能一直等待数据
         * ```
         * @example - 提前定义长度，到达长度自动done
         * ```ts
         * const handler = Handler.from(pipe);
         * handler.status(200).header('Content-Type', 'text/plain').header('Content-Length', '5').send('hello')
         * // 此时无需`done()`，客户端会认为已经完成请求
         * ```
         * @see {@link Handler.chunked} 启用chunked模式，无需担心上面的限制 
         */
        done(no_body?: boolean): this;

        /**
         * Note: 别忘记再次调用`done()`指示客户端chunk发送完毕
         * @example
         * ```ts
         * const handler = Handler.from(pipe);
         * // 第一次done指示发送header，此后chunked发送
         * // 最后done()指示chunk发送完毕
         * handler.status(200).chunked().done().send('hello').done();
         * ```
         */
        chunked(): this;

        /**
         * `handler.headers.delete`的快捷方式
         */
        header(key: string, value?: null): this;

        /**
         * `handler.headers.set`的快捷方式
         */
        header(key: string, value: string): this;

        readonly end: Promise<void>;
        // readonly state: "WAITING" | "WAITING_BODY" | "WAITING_HEADER" | "DONE" | "ERROR";

        readonly request: Response;
        readonly headers: Headers;

        get finished(): boolean;
    }
}