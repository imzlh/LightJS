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

declare module 'socket'{
    const bind: (addr: string, handler: (client: U8Pipe, addr: IAddr) => void, settings?: {
        reuseaddr?: boolean,
        backlog?: number,
        bufferSize?: number,
        timeout?: number,
        nodelay?: boolean,
        keepalive?: boolean,
        bindto?: string,
        onclose: () => void
    }) => () => void
}