declare module "fs" {
    type Stat = {
        mtime: bigint,
        atime: bigint,
        ctime: bigint,
        ino: number,
        dev: number,
        mode: number,
        nlink: number,
        uid: number,
        gid: number
    } & (
        { isDirectory: true } |
        { isFile: true, size: number, blksize: number, blocks: number } |
        { isSymbolicLink: true, target: string } |
        { isCharacterDevice: true, rdev: number } |
        { isBlockDevice: true, rdev: number } |
        { isFIFO: true } |
        { isSocket: true }
    ) & Record<string, undefined>;
    
    type FileTypes = "directory" | "file" | "symlink" | "chardev" | "blkdrv" | "fifo" | "socket";
    
    /**
     * Open flags for `open` function.
     * Same as Node.js `fs.constants.O_XXX` constants.
     */
    type OpenFlag = "a" | "ax" | "a+" | "ax+" | "r" | "r+" | "w" | "wx" | "w+" | "wx+";

    class SyncPipe{
        constructor(fd: number);
        write(data: Uint8Array | string, block: boolean): number;
        read(max_size: number): Uint8Array;
        close(): void;
        seek(offset: number, whence: number): void;
        tell(): number;
        prealloc(size: number, mode: number): boolean;

        get eof(): boolean;
        get size(): number;

        // for seek()
        static SEEK_CUR: number;
        static SEEK_END: number;
        static SEEK_SET: number;

        // for prealloc()
        static FL_KEEP_SIZE: number;
        static FL_PUNCH_HOLE: number;

        block: boolean; // setter and getter for blocking mode
        readonly fd: number;
    }

    type InWD = number;
    class Inotify {
        constructor(cb: (type: number, path: string, move_to?: string) => void);
        watch(path: string, mask: number): InWD;
        unwatch(wd: InWD): void;
        find(path: string): InWD;
        close(): void;
    }

    export function write(filename: string, data: string | Uint8Array): void;

    export function read(filename: string, as_str?: false): Uint8Array;
    export function read(filename: string, as_str: true): string;

    export function scandir(path: string): ({name: string, type: FileTypes})[];

    export function mkdir(path: string): void;

    export function unlink(path: string): void;

    export function symlink(src: string, dest: string): void;

    export function chmod(path: string, mode: number): void;

    export function chown(path: string, uid: number, gid: number): void;

    export function rename(oldpath: string, newpath: string): void;

    export function stat(path: string): Stat;

    export function open(path: string, flags: OpenFlag, mode?: number, sync?: false): U8Pipe;
    // @ts-ignore
    export function open(path: string, flags: string, mode?: number, sync: true): SyncPipe;

    export function copy(src: string, dest: string): void;

    export function realpath(path: string): string;
}