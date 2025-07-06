declare module 'process'{
    type ReactiveEnviron = Record<string, string>;

    /**
     * Note: 通过pipe.tty*操作进程pty，如大小、标题
     */
    class Process<P extends boolean | undefined>{
        static kill(pid: number, signal?: number): void;

        constructor(args: string[], options?: {
            inheritPipe?: P,
            env?: Record<string, string>,
            cwd?: string
        });

        readonly alive: boolean;
        readonly pid: number;
        readonly code: number;
        readonly pipe: P extends true? undefined : U8Pipe; // undefined if interitPipe

        readonly onclose: Promise<void>;
    }

    const self: {
        readonly pid: number,
        readonly args: string[],
        readonly entry: string,

        /**
         * 当前工作目录<br>
         * 可以通过设置cwd属性修改，相当于chdir命令
         */
        cwd: string,

        /**
         * 环境变量对象<br>
         * 可以直接通过读写值修改，多个Worker间可以安全共享
         */
        readonly env: ReactiveEnviron,

        /**
         * ParentProcessIDentifier<br>
         * 父进程ID
         */
        readonly ppid: number,

        /**
         * 设置一个信号处理函数<br>
         * 线程安全，当信号处理时强制中断当前执行
         * @param sig 信号ID，通过`signal.SIGXXX`获取
         * @param callback 信号处理函数
         */
        signal: (sig: number, callback: () => void) => void,

        /**
         * 移除一个信号处理函数
         * @param callback 信号处理函数
         * @param sig 信号ID，通过`signal.SIGXXX`获取，不指定则移除所有信号处理函数
         * @returns 是否移除成功
         */
        removeSignal: (callback: () => void, sig?: number) => boolean
    }

    const exit: (code?: number) => never;

    const signals: {
        readonly SIGHUP: number,
        readonly SIGINT: number,
        readonly SIGQUIT: number,
        readonly SIGILL: number,
        readonly SIGTRAP: number,
        readonly SIGABRT: number,
        readonly SIGBUS: number,
        readonly SIGFPE: number,
        readonly SIGSEGV: number,
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