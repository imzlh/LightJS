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

    type FileTypes = "dir" | "file" | "symlink" | "chardev" | "blkdrv" | "fifo" | "socket";

    /**
     * Open flags for `open` function.
     * Same as Node.js `fs.constants.O_XXX` constants.
     */
    type OpenFlag = "a" | "ax" | "a+" | "ax+" | "r" | "r+" | "w" | "wx" | "w+" | "wx+";

    class SyncPipe {
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
        static ACCESS: number;
        static MODIFY: number;
        static ATTRIB: number;
        static CLOSE_WRITE: number;
        static CLOSE_NOWRITE: number;
        static OPEN: number;
        static CREATE: number;
        static DELETE: number;
        static DELETE_SELF: number;
        static MOVE_SELF: number;
        static UNMOUNT: number;

        /**
         * Event queue overflow (events were lost due to kernel queue size limit)
         */
        static Q_OVERFLOW: number;

        /**
         * Watch was automatically removed (typically because watched file was deleted)
         */
        static IGNORED: number;

        /**
         * Only watch the path if it is a directory
         */
        static ONLYDIR: number;

        /**
         * Do not follow symbolic links
         */
        static DONT_FOLLOW: number;

        /**
         * Add (OR) events to watch mask instead of replacing
         */
        static MASK_ADD: number;

        /**
         * Event occurred against directory
         */
        static ISDIR: number;

        /**
         * Only send event once then remove watch
         */
        static ONESHOT: number;

        /**
         * Monitor all valid event types
         */
        static ALL_EVENTS: number;

        /**
         * Create a new inotify instance
         * @param cb The callback to call when an event occurs
         */
        constructor(cb: (type: number, path: string, move_to?: string) => void);

        /**
         * Add a watch for a path
         * @param path The path to watch
         * @param mask The event mask to watch for(`Inotify.*`)
         */
        watch(path: string, mask: number): InWD;

        /**
         * Remove a watch for a path
         * @param wd The watch descriptor returned by `watch`
         */
        unwatch(wd: InWD): void;

        /**
         * find a watch descriptor for a path
         * @param path The path to find a watch descriptor for
         */
        find(path: string): InWD;

        /**
         * Close the inotify instance and release resources
         */
        close(): void;

        closed: Promise<void>;
    }

    export function write(filename: string, data: string | Uint8Array): void;

    export function read(filename: string, as_str?: false): Uint8Array;
    export function read(filename: string, as_str: true): string;

    export function scandir(path: string): ({ name: string, type: FileTypes })[];

    export function mkdir(path: string): void;

    export function unlink(path: string): void;

    export function symlink(src: string, dest: string): void;

    export function chmod(path: string, mode: number): void;

    export function chown(path: string, uid: number, gid: number): void;

    export function rename(oldpath: string, newpath: string): void;

    export function stat(path: string): Stat;

    export const access: {
        (path: string, mode: number, safe_call?: false): void;
        (path: string, mode: number, safe_call: true): boolean;

        ACCESS: number; // alias for F_OK
        EXECUTE: number;// alias for X_OK
        WRITE: number;  // alias for W_OK
        READ: number;   // alias for R_OK
    };

    /**
     * Open a file for reading or writing synchronously.
     */
    export function open(path: string, flags: OpenFlag, mode?: number, sync?: false): IOPipe;
    
    /**
     *  - LightJS will use AIO which has bad performance for small files.
     *    Mostly used for large files.
     *  - `flags` (E.G. `r+`/`w+` has the same behavior here) will be ignored if `sync` is `false`.
     *     You may needed to `fseek()` by yourself.
     */
    // @ts-ignore
    export function open(path: string, flags: string, mode?: number, sync: true): SyncPipe;

    /**
     * Note: This function is synchronous and will block the main thread.
     * If you want to copy a large file, use async `open` + `pipeTo` instead.
     */
    export function copy(src: string, dest: string): void;

    export function realpath(path: string): string;
}