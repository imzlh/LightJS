/// <reference path="./process.d.ts" />
/// <reference path="./socket.d.ts" />

type IModule = 'pipe' | 'socket' | 'process' | 'fs' | 'console' | 'event' | 'module' | 'url' | 'timer' |
    /* ES6 features */ 'base' | 'date' | 'eval' | 'regexp' | 'json' | 'proxy' | 'mapset' | 'typedarray' | 'promise' | 'bigint' | 'weakmap' | 'performance';
type TypedArray = Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | Float32Array | Float64Array;

declare const console: {
    log: (...args: any[]) => void;
    error: (...args: any[]) => void;
    warn: (...args: any[]) => void;
    debug: (...args: any[]) => void;
    info: (...args: any[]) => void;
    assert: (expression: any, message?: string) => void;
    clear: () => void;
}

declare function setTimeout(callback: () => void, timeout: number): number;
declare function setInterval(callback: () => void, timeout: number): number;
declare function clearTimer(intervalId: number): void;
declare function delay(time_ms: number): Promise<void>;

declare function atob(encoded: string): string;
declare function btoa(raw: string): string;

declare function encodeStr(str: string): Uint8Array;
declare function decodeStr(data: Uint8Array): string;

declare class Worker {
    // Note: static methods are only available in Worker threads
    static postMessage: (data: any) => void;
    // @ts-ignore
    static onmessage: (data: any) => void;  // setter getter
    static exit: (code: number, reason?: string) => void;

    constructor(url: string, module?: boolean);
    onmessage: (data: any) => void;  // setter getter
    onclose: () => any;  // setter getter
    postMessage(data: any): void;
    terminate(): void;
}

/**
 * URL
 */
declare class URL {
    /**
     * @link https://developer.mozilla.org/zh-CN/docs/Web/API/URL/revokeObjectURL_static
     */
    static canParse(url: string, base?: string): boolean;

    constructor(url: string, base?: string);
    href: string;
    protocol: string;
    username: string;
    password: string;
    host: string;
    port: number;
    path: string;
    query: string;
    hash: string;

    getQuery(): Record<string, string[]>;
    getQuery(name: string): string[];
    delQuery(name: string): void;
    addQuery(name: string, value: string): void;

    toString(): string;
}

/**
 * LightJS 管道
 */
declare class Pipe<T>{
    static READ: number;
    static WRITE: number;
    
    /**
     * 创建管道
     * @param mode 模式，可选 READ、WRITE
     * @param control 管道控制器，出现错误时关闭管道
     */
    constructor(mode: number, control: {
        start(): any;
        pull(): Promise<T>;
        write(data: T): void;
        close(): void;
    });

    /**
     * 读取数据
     */
    read(): Promise<T | null>;

    /**
     * 写入数据
     * @param data 要写入的数据
     */
    write(data: T): Promise<void>;

    /**
     * 输出到另一个管道
     * @param destination 目标管道
     * @param callback 回调函数，接收到数据时调用
     */
    pipeTo(destination: Pipe<T>, callback?: (data: T) => T): void;

    /**
     * 关闭管道
     */
    close(): void;

    readonly closed: boolean;
    readonly onclose: Promise<void>;
}

/**
 * 与 Pipe 类似，但数据类型为 Uint8Array
 * 支持截流方法
 */
declare class U8Pipe {
    static buffer_size: number;

    /**
     * PS: mode可以为undefined，默认依据control决定
     * @param control 
     * @param mode 
     */
    constructor(control: {
        start?(): any;
        pull?(): Promise<Uint8Array>;
        write?(data: Uint8Array): void;
        close?(): void;
    }, mode?: number);
    write(data: Uint8Array): Promise<void>;
    /**
     * 向另一个U8Pipe写入数据，可选参数为过滤函数，接收到数据时调用，返回true则写入，否则丢弃
     * @param destination 目标U8Pipe
     * @param filter 过滤函数，修改data可以实现修改写入对方的流
     */
    pipeTo(destination: U8Pipe, filter?: (data: Uint8Array) => boolean): Promise<void>;
    close(): void;
    read(length?: number): Promise<Uint8Array | null>;
    readline(): Promise<Uint8Array | null>;
    /**
     * 只支持基于fd的pipe(fdpipe)
     */
    sync(): Promise<void>;
    readonly closed: boolean;
    readonly onclose: Promise<void>;

    // features for tty
    ttyRaw(raw: boolean): boolean;
    set ttySize(size: [number, number]);
    get ttySize(): [number, number];
    get isTTY(): boolean;
    get ttyTitle(): string;
    set ttyTitle(title: string);

    // features for fd.
    /**
     * @deprecated read、write方法已经实现了Promise接口，此方法不再建议使用
     */
    fflush(): void;
    fseek(offset: number, whence: "start" | "current" | "end"): void;
}

interface ImportMeta {
    name: string;
    url: string;    // note: 如果是文件，为绝对路径，不带"file://"前缀(LJS URL class也可解析此类)
    filename: string;
    dirname: string;
    main: boolean;   // note: 检查 Worker.onmessage 以分辨是Worker还是主线程
}

// performance
declare const performance: {
    now(): number;
    readonly timeOrigin: number;
};