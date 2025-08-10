import { Certificate } from "crypto";

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

interface DNS_NORM{
    type: 'A' | 'AAAA' | 'CNAME' | 'NS' | 'TXT',
    data: string
}

interface DNS_MX{
    type: 'MX',
    priority: number,
    data: string
}

interface DNS_SOA{
    type: 'SOA',
    mname: string,
    rname: string,
    serial: number,
    refresh: number,
    retry: number,
    expire: number,
    minimum: number
}

interface DNS_SRV{
    type: 'SRV',
    priority: number,
    weight: number,
    port: number,
    target: string
}

type DnsResult = DNS_NORM | DNS_MX | DNS_SOA | DNS_SRV | {
    type: 'UNKNOWN'
}

type CloseFunction = () => void;

declare module 'socket'{
    export const bind: (addr: string, handler: (client: IOPipe, addr: IAddr) => void, settings?: {
        reuseaddr?: boolean,
        backlog?: number,
        timeout?: number,
        nodelay?: boolean,
        keepalive?: boolean,
        bindto?: string,
        onclose?: () => void
    }) => CloseFunction;

    export const connect: (addr: string, settings?: {
        timeout?: number,
        // nodelay?: boolean,
        hostname?: string,              // for TLS
        alpn_protocols?: Array<string>, // for TLS
    }) => IOPipe;

    type UpgradeTLSOptions = {
        ciphers?: Array<string>,
        suiteb?: boolean
        alpn?: Array<string>
    } & (
        {
            server?: false,
            hostname: string,
        } | {
            server: true,
            hostname?: string,
            cert: typeof Certificate.prototype,
            key: ArrayBuffer,
            sni?: boolean
        }
    );

    // XXX: move to crypto.d.ts?
    export const upgradeTLS: (client: U8Pipe, settings: UpgradeTLSOptions) => Promise<typeof Certificate.prototype>;

    export const resolveDNS: (host: string, dns_server?: string) => Promise<Array<DnsResult>>;

    /**
     * 如果cert为二进制，则认为是DER格式的证书，否则认为是PEM格式的证书
     */
    export const regCert: (key: string, cert: string | Uint8Array, privkey?: string, options?: {
        keypwd?: string
    }) => void;
    export const unregCert: (key: string) => boolean;
}