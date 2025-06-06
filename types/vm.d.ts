/**
 * source: src/global.c
 */

declare module 'vm' {
    export function gc(): void;
    export function dump(obj: any, strip?: boolean): Uint8Array;
    export function load(code: Uint8Array): any;
    export function compile(code: string, module_name?: string): Uint8Array;

    export class Sandbox {
        constructor(opts?: {
            loader?: (input: string) => string;
            init: Array<IModule>;
        })
    
        eval(code: string): any;
        eval(code: string, import_meta: Record<string, any>): Promise<any>;    
    
        get context(): typeof globalThis;
    }

    export function setEventNotifier(callback: (event: string, data: any) => void): void;
}