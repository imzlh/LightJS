/**
 * 注意：使用`vm`模块很危险，不要轻易使用，除非你知道自己在做什么。<br>
 * 不正确的使用会导致QuickJS崩溃，甚至导致进程崩溃。<br>
 * source: src/global.c
 */

declare module 'vm' {
    export function gc(): void;
    export function dump(obj: any, strip?: boolean): Uint8Array;
    export function load(code: Uint8Array): any;
    export function compile(code: string, opts: {
        module?: boolean,
        filename?: string,
        strip?: boolean
    }): Uint8Array;

    export class Module {
        constructor();
        get pointer(): number;
        dump(): Uint8Array;
        /**
         * 可读可写，当读取时拷贝一个副本，修改副本不会影响原对象
         */
        meta: Record<string, any>;
    }

    /**
     * 封包成jspack，需要ModuleRef<br>
     * 危险：`ArrayBuffer`需要来自于`vm.compileModule`，否则可能会导致崩溃
     * @param obj 模块路径与内容的映射
     */
    export function pack(obj: Record<string, Module>): Uint8Array;

    /**
     * 解包jspack，返回模块路径与内容（二进制）的映射<br>
     * 不可以直接`vm.load()`，但可以传递给sandbox让sandbox执行<br>
     * 危险：不要修改返回的ArrayBuffer，否则传递给Sandbox可能会导致崩溃
     * @example - 使用sandbox模块
     * ```ts
     * const mod = unpack(buf);
     * const sb = new Sandbox({ loader(name){
     *     if(name in mod){
     *         return mod[name];
     *     } else {
     *         throw new Error(`Module ${name} not found`);
     *     }
     * } });
     * await sb.eval('(await import("mod1")).foo()');
     * @param buf 
     */
    export function unpack(buf: Uint8Array): Record<string, ArrayBuffer>;

    export class Sandbox {
        constructor(opts?: {
            loader?: (this: void, input: string) => string | Module;
            format?: (this: void, modulename: string) => string
            // init: Array<IModule>;
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

        loadModule(code: string, module_name: string): Module;
    
        get context(): typeof globalThis;
    }

    /**
     * (不安全，请小心使用)设置VM底层选项，可能会导致崩溃
     * @param opts 
     */
    export function setVMOptions(opts: Partial<{
        disablePromiseReport: boolean,
        memoryLimit: bigint,
        stackLimit: number,
        codeExecutionTimeout: number,
        eventNotifier: (event: string, data: any) => void,
        /**
         * 手动接管代码是否取消执行，返回任何可以认作`true`的值将结束代码执行
         */
        tickCallback: (this: void) => any,
        /**
         * 接管模块路径解析，返回模块路径<br>
         * 允许抛出错误，将被LightJS传递给用户
         */
        moduleResolver: (module_name: string, base_name: string) => string,
        /**
         * 解析模块，允许返回Module字节码（class Module），或返回JS内容<br>
         * 谨慎返回字节码，可能会造成QuickJS崩溃<br>
         * 字节码返回前，如果是模块，确保已经加载所有依赖，否则将报错
         * @param module_name 已经被moduleResolver解析过的模块名
         */
        moduleLoader: (module_name: string) => Module | string,
    }>): void;

    /**
     * 为非标准模块添加source map，用于错误追踪时显示原始文件位置<br>
     * 对于tsc esbuild等编译的模块非常有用<br>
     * 如果你对模块名疑惑，可以cmake切换到debug编译查看日志
     * @param module_name 名称，注意需要相对路径全名
     * @param source_map JSON source map字符串或对象
     */
    export function loadSourceMap(module_name: string, source_map: string | object): boolean;

    export const version: {
        mbedtls?: string,        
        ffi?: null, // note: FFI没有版本信息
        zlib?: string,
        expat?: string,

        quickjs: string,
        version: string,
    };
}