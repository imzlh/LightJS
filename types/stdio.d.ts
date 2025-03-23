declare module "stdio" {
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

    export function open(path: string, flags: OpenFlag, mode?: number): U8Pipe;
}