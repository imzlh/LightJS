type IAddr = {
    type: 'unknown'
} | {
    type: 'tcp4' | 'tcp6',
    addr: string,
    port: number
} | {
    type: 'unix',
    path: string
};

type CloseFunction = () => void;

declare module 'socket'{
    export const bind: (addr: string, handler: (client: U8Pipe, addr: IAddr) => void, settings?: {
        reuseaddr?: boolean,
        backlog?: number,
        bufferSize?: number,
        timeout?: number,
        nodelay?: boolean,
        keepalive?: boolean,
        bindto?: string,
        onclose: () => void
    }) => CloseFunction;

    export const connect: (addr: string, settings?: {
        bufferSize?: number,
        timeout?: number,
        // nodelay?: boolean
    }) => U8Pipe;

    export const upgradeTLS: (client: U8Pipe, settings: {
        server?: boolean,
        ciphers?: Array<string>,
        suiteb?: boolean
    }) => Promise<void>;

    export const resolveDNS: (host: string, dns_server?: string) => Promise<IAddr>;

    export const regCert: (key: string, cert: string, ca: string) => void;
    export const unregCert: (key: string) => boolean;
}