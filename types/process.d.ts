declare module 'process'{
    type ReactiveEnviron = Record<string, string>;

    /**
     * Note: 通过pipe.tty*操作进程pty，如大小、标题
     */
    class Process{
        constructor(args: string[], options: {
            inheritPipe?: boolean,
            env?: Record<string, string>,
            cwd?: string
        })

        readonly alive: boolean;
        readonly pid: number;
        readonly code: number;
        readonly pipe?: U8Pipe; // undefined if interitPipe

        readonly onclose: Promise<void>;
    }

    const self: {
        readonly pid: number,
        readonly argv: string[],
        readonly entry: string,
        readonly dirname: string,
        readonly filename: string,
        cwd: string,
        readonly env: ReactiveEnviron,
        readonly ppid: number,

        signal: (sig: number, callback: () => void) => void,
        removeSignal: (callback: () => void, sig?: number) => boolean
    }

    const exit: (code?: number) => void;

    const signals: {
        readonly SIGHUP: number,
        readonly SIGINT: number,
        readonly SIGQUIT: number,
        readonly SIGILL: number,
        readonly SIGTRAP: number,
        readonly SIGABRT: number,
        readonly SIGBUS: number,
        readonly SIGFPE: number,
        readonly SIGUSR1: number,
        readonly SIGSEGV: number,
        readonly SIGUSR2: number,
        readonly SIGPIPE: number,
        readonly SIGALRM: number,
        readonly SIGTERM: number,
        readonly SIGCHLD: number,
        readonly SIGCONT: number,
        readonly SIGSTOP: number,
        readonly SIGTSTP: number,
        readonly SIGTTIN: number,
        readonly SIGTTOU: number,
        readonly SIGURG: number,
        readonly SIGXCPU: number,
        readonly SIGXFSZ: number,
        readonly SIGVTALRM: number,
        readonly SIGPROF: number,
        readonly SIGWINCH: number,
        readonly SIGIO: number,
        readonly SIGPWR: number,
        readonly SIGSYS: number
    }

    const sysinfo: () => {
        readonly platform: 'linux', // linux only
        readonly memory: {
            total: number,
            free: number,
            used: number,
            shared: number,
            buffers: number,
            cached: number,
            swap: number
        },
        readonly cpu: {
            count: number,
            speed: number,
            time: number    // sometimes undefined
        },
        readonly sys: {
            system: string,
            domain: string,
            release: string,
            node: string,
            version: string,
            arch: string   // machine in uname
        },
        readonly loadavg: [number, number, number],
        readonly uptime: number,
        readonly process: number
    }

    export const stdin: U8Pipe;
    export const stdout: U8Pipe;
    export const stderr: U8Pipe;

    export function sleep(ms: number): void;
}