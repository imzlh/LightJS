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
    
        /**
         * 在Sandbox中执行一段代码，返回执行结果
         * 类似于`eval`，在沙箱内运行可以有效隔离全局上下文
         * @param code 
         */
        eval(code: string): any;

        /**
         * 相似的，在沙箱内执行一段代码，返回执行结果。
         * `import_meta`将拷贝到代码所对应的模块的`import.meta`对象中
         * @param code 
         * @param import_meta 
         */
        eval(code: string, import_meta: Record<string, any>): Promise<any>;    

        /**
         * 执行一个函数，`fn`可以是线程内的任何函数
         * 注意：如果是闭包函数，会导致捕获的变量也在沙箱内运行，没有任何安全效果<br>
         * 此时建议使用`vm.dump` + `vm.load`来序列化和反序列化函数，此时函数将使用沙箱上下文
         * @example
         * ```
         * const fn = new Function(`function add(a, b) { return a + b; }`);
         * const sandbox = new vm.Sandbox();
         * const add = sandbox.call(fn);
         * console.log(add(1, 2)); // 3
         * ```
         * @example - 闭包函数
         * ```
         * let i = 0;
         * const fn = () => i++;
         * const sandbox = new vm.Sandbox();
         * sandbox.content.i = 0;   // 给闭包函数添加变量
         * sandbox.call(vm.dump(vm.load(fn)));
         * i; // 0;
         * sandbox.call(fn);
         * i; // 1;
         * ```
         * @param fn 
         * @param thisArg 
         * @param args 
         */
        call(fn: Function, thisArg: any, args: Array<any>): any;
    
        get context(): typeof globalThis;
    }

    export function setEventNotifier(callback: (event: string, data: any) => void): void;
}