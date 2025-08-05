/**
 * @typedef {Record<string, string|string[]|undefined> & { _: string[], '-'?: string }} Args
 */

/**
 * 解析传入的参数
 * @example
 * ```ts
 * // ljs test.js --name=light --age=18 -h -
 * import { self } from "process";
 * console.log(parseArgs(self.args, { h: 'help' }));
 * // { _: [ 'test.js' ], name: 'light', age: '18', help: 'true', '-': 'true' }
 * ```
 * @example - 使用空格分隔风格
 * ```ts
 * // ljs test.js --name light --age 18 -h -
 * import { self } from "process";
 * // 注意：这里一定要指定哪些参数有参数值，否则会被当作bool参数
 * console.log(parseArgs(self.args, { h: 'help' }, false, ['name']));
 * // { _: [ 'test.js', '18'], name: 'light', age: 'true', help: 'true', '-': 'true' }
 * ```
 * @param {string[]} args 参数
 * @param {Record<string, string>} [map] 短选项对应的长选项
 * @param {boolean} [useEqSeparate] 是否使用等号分隔键值的风格
 * @param {string[]} [hasParamValue] 带有参数值的选项
 * @param {boolean} [stopAtFirstUnknown] 是否在遇到非参数时停止解析，类似于LightJS的行为
 */
export function parseArgs(args, map = {}, useEqSeparate = true, hasParamValue = [], stopAtFirstUnknown = false) {
    const result = /** @type {Args} */ ({ _: [] });
    let previousKey = /** @type {string|undefined} */ (undefined);

    const push = (/** @type {string | undefined} */ key, /** @type {string | undefined} */ value) => {
        if (previousKey) {
            result[previousKey] = value ?? 'true';  // 如果有值就用值，否则设为'true'
        } else if (value) {
            result._.push(value);
        }
        if(!key || hasParamValue.includes(key)) previousKey = key;
        else result[key] = 'true', previousKey = undefined;
    }


    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg.startsWith('--')) {
            if(useEqSeparate){
                const [key, value] = arg.slice(2).split('=');
                result[key] = value;
            }else{
                push(arg.slice(2));
            }
        } else if (arg.startsWith('-')) {
            for (let j = 1; j < arg.length; j++){
                const char = arg[j];
                const key = map[char] ?? char;
                (!useEqSeparate && j == arg.length -1) 
                   ? push(key)
                   : result[key] = 'true';
            }
            if(arg.length == 1){
                result['-'] = 'true';
            }
        } else if(useEqSeparate) {
            result._.push(arg);
            if(stopAtFirstUnknown) break;
        } else {
            push(undefined, arg);
            if(stopAtFirstUnknown) break;
        }
    }

    if(!useEqSeparate){
        push();
    }

    return result;
}

// test suite
if(import.meta.main){
    console.log(parseArgs((await import('process')).self.args, { h: 'help' }, false, ['test']));
}