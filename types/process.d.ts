declare module 'process'{
    type ReactiveEnviron = Record<string, string>;

    class Process{
        constructor(args: string[], options: {
            inheritPipe: boolean,
            env: Record<string, string>,
            cwd: string
        })

        readonly alive: boolean;
        readonly pid: number;
        readonly code: number;
        readonly title: string;
        size: [number, number];
    }

    const self: {
        readonly pid: number,
        readonly argv: string[],
        readonly entry: string,
        readonly dirname: string,
        readonly filename: string,
        cwd: string,
        readonly env: ReactiveEnviron,
        readonly ppid: number
    }

    const exit: (code?: number) => void;
}