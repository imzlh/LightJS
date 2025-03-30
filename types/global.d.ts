/// <reference path="./process.d.ts" />
/// <reference path="./socket.d.ts" />

type IModule = 'pipe' | 'socket' | 'process' | 'stdio' | 'console' | 'event' | 'module' | 'url' | 'timer' |
    /* ES6 features */ 'base' | 'date' | 'eval' | 'regexp' | 'json' | 'proxy' | 'mapset' | 'typedarray' | 'promise' | 'bigint' | 'weakmap' | 'performance';

declare class Event {
    type: string;
    preventDefault: () => void;
}

declare class EvTarget {
    on: (type: string, listener: (event: Event) => void) => void;
    off: (type: string, listener: (event: Event) => void) => void;
    fire: (event: Event) => void;
}

declare const console: {
    log: (...args: any[]) => void;
    error: (...args: any[]) => void;
    warn: (...args: any[]) => void;
    debug: (...args: any[]) => void;
    info: (...args: any[]) => void;
    count: () => void;
    countReset: () => void;
    time: (label?: string) => void;
    timeEnd: (label?: string) => void;
    timeLog: (label?: string) => void;
    assert: (expression: any, message?: string) => void;
    clear: () => void;
}

declare function setTimeout(callback: () => void, timeout: number): void;
declare function setInterval(callback: () => void, timeout: number): void;
declare function clearTimer(intervalId: number): void;
declare function delay(time_ms: number): Promise<void>;

declare function atob(encoded: string): string;
declare function btoa(raw: string): string;

declare function encodeStr(str: string): Uint8Array;

declare function Worker(scriptURL: string, module?: boolean): U8Pipe;
declare class Sandbox {
    constructor(opts?: {
        loader?: (input: string) => string;
        init: Array<IModule>;
    })

    eval(code: string, import_meta: Record<string, any>): Promise<any>;
    eval(code: string): any;

    get context(): typeof globalThis;
}

/**
 * URL
 */
declare class URL {
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

    getQuery(name: string): string | null;
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
}

/**
 * 与 Pipe 类似，但数据类型为 Uint8Array
 * 支持截流方法
 */
declare class U8Pipe {
    static buffer_size: number;

    constructor(mode: number, control: {
        start(): any;
        pull(): Promise<Uint8Array>;
        write(data: Uint8Array): void;
        close(): void;
    });
    write(data: Uint8Array): Promise<void>;
    pipeTo(destination: Pipe<Uint8Array> | U8Pipe, callback?: (data: Uint8Array) => Uint8Array): void;
    close(): void;
    read(length?: number): Promise<Uint8Array | null>;
    readline(): Promise<Uint8Array | null>;
    readonly closed: boolean;
    readonly end: Promise<void>;

    // features for tty
    ttyRaw(raw: boolean): boolean;
    set ttySize(size: { rows: number, cols: number });
    get ttySize(): { rows: number, cols: number };
    get isTTY(): boolean;

    // features for fd.
    /**
     * @deprecated read、write方法已经实现了Promise接口，此方法不再建议使用
     */
    flush(): void;
}

interface ImportMeta {
    name: string;
    path: string;
    filename: string;
    dirname: string;
}