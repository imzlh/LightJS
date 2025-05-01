declare module 'compress' {
    export function zlib(data: Uint8Array, decompress: boolean, level?: number): Uint8Array;
    export function deflate(data: Uint8Array, decompress: boolean, level?: number): Uint8Array;
    export function deflateStream(decompress: boolean, level?: number): U8Pipe;
}