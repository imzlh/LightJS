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
        get headers(): Record<string, string>;
        get body(): U8Pipe;
        get status(): number;
        get ok(): boolean;
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

        send(data: string | Uint8Array | ArrayBuffer): void;
        close(): void;
        reuse(): Promise<this>;
        ws(): WebSocket;
        status(code: number): void;

        /**
         * 设置头。注意有重复会替换，如果不需要替换请用数组包装，如
         * ```ts
         * // 这里只是演示，实际上建议使用Cookies类(Handler.cookies)
         * res.header('Set-Cookie', ['a=b', 'c=d']);
         * ```
         */
        header(key: string, value: string | null): void;

        /**
         * 删除头
         */
        header(key: string, value?: undefined): string[];

        /**
         * 强制添加头，不会替换。对于类似于多Auth的场景，可以用此方法添加额外的Auth头。
         */
        header(key: string, value: string[]): void;

        /**
         * 结束header内容，立即发送给客户端。之后就可以流式写入body了。<br>
         * 注意：除非设置chunked，否则需要提前定义`Content-Length`
         */
        done(): Promise<void>;

        end: Promise<void>;
    }
}