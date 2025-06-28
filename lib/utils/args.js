/**
 * @typedef {Record<string, string|string[]|undefined> & {_: string[]}} Args
 */

/**
 * 解析传入的参数
 * @example
 * ```ts
 * // ljs test.js --name=light --age=18 -h
 * import { self } from "process";
 * console.log(parseArgs(self.args));
 * // { _: [ 'test.js' ], name: 'light', age: '18', h: true }
 * ```
 * @param {string[]} args 
 */
export function parseArgs(args) {
    const result = /** @type {Args} */ ({});
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg.startsWith('--')) {
            const [key, value] = arg.slice(2).split('=');
            result[key] = value;
        } else if (arg.startsWith('-')) {
            const [key, value] = arg.slice(1).split('=');
            result[key] = value;
        } else {
            result._.push(arg);
        }
    }
    return result;
}