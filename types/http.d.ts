/**
 * LightJS HTTP module
 * source: src/http.c
 */

declare function fetch(url: string, options?: {
    method?: string;
    headers?: Record<string, string>;
    keepalive?: boolean;
    referer?: string;
    host?: string;  // 当URL为unix或ip地址时，需要用于指定请求的Host头
    body?: Uint8Array | U8Pipe | string;
}): Promise<import('http').WebSocket | import('http').Response>;

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
        getall(key?: string): string[];
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
        onmessage: (data: Uint8Array | string, is_fin: boolean) => void;
    
        readonly ended: Promise<void>;
        readonly cookies: Cookies;
    }

    export class Response {
        text(): Promise<string>;
        bytes(): Promise<Uint8Array>;
        json(): Promise<any>;
        formData(): Promise<FormData[]>;

        get locked(): boolean;
        get body(): U8Pipe;
        get status(): number;
        get ok(): boolean;

        readonly headers: Headers;
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

        send(data: string | Uint8Array | ArrayBuffer): this;
        close(): void;
        reuse(): Promise<this>;
        ws(): WebSocket;
        status(code: number): this;

        /**
         * 结束header内容，立即发送给客户端。之后就可以流式写入body了。<br>
         * 注意
         *  - 除非设置chunked，否则需要提前定义`Content-Length`
         *  - 务必有body，或者指定`done(true)`，否则会一直等待数据
         *  - 如果没有调用`chunked()`，会使用HTTP/1.0，此时不会长连接
         *  - `reuse()`前，务必确保响应处理完毕(`await handler.end`)
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

        end: Promise<void>;
        request: Response & { path: string };

        headers: Headers;
    }
}