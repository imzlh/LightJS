/**
 * LightJS Standard Library - Path Utils
 */

import { self } from "process";

/**
 * @description Returns the basename of a path
 * @param {string} path - The path to extract the basename from
 * @returns {string} The basename of the path
 * @example
 * ```ts
 * import { basename } from "./lib/io/path";
 * console.log(basename("/path/to/file.txt")); // "file.txt"
 * ```
 */
export function basename(path) {
    if(!path) return basename(self.entry);
    return /** @type {string} */(path.split('/').pop());
}

/**
 * @description Returns the dirname of a path
 * @param {string} path - The path to extract the dirname from
 * @returns {string} The dirname of the path
 * @example
 * ```ts
 * import { dirname } from "./lib/io/path";
 * console.log(dirname("/path/to/file.txt")); // "/path/to"
 * ```
 */
export function dirname(path) {
    if(!path) return dirname(self.entry);
    return /** @type {string} */(path.split('/').slice(0, -1).join('/'));
}

/**
 * @description Joins multiple paths into a single path
 * @param {...string} paths - The paths to join
 * @returns {string} The joined path
 * @example
 * ```ts
 * import { join } from "./lib/io/path";
 * console.log(join("/path", "to", "file.txt")); // "/path/to/file.txt"
 * ```
 */
export function join(...paths) {
    return normalize(paths.join('/'));
}

/**
 * @description Resolves a path to an absolute path
 * @param {string} path - The path to resolve
 * @returns {string} The resolved path
 * @example
 * ```ts
 * import { resolve } from "./lib/io/path";
 * console.log(resolve("file.txt")); // "/path/to/file.txt"
 * ```
 */
export function normalize(path) {
    return new URL(path, 'file://' + self.cwd).path;
}