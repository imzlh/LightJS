/**
 * Sucrase & JSX global Declarations
 * This file is a part of LightJS project
 * and tsutils.js is a part of Sucrase project.
 * @link https://github.com/alangpierce/sucrase
 */

export type Transform = "jsx" | "typescript" | "flow" | "imports" | "react-hot-loader" | "jest";

export interface SourceMapOptions {
    /**
     * The name to use in the "file" field of the source map. This should be the name of the compiled
     * file.
     */
    compiledFilename: string;
}

export interface Options {
    /**
     * Unordered array of transform names describing both the allowed syntax
     * (where applicable) and the transformation behavior.
     */
    transforms: Array<Transform>;
    /**
     * Opts out of all ES syntax transformations: optional chaining, nullish
     * coalescing, class fields, numeric separators, optional catch binding.
     */
    disableESTransforms?: boolean;
    /**
     * Transformation mode for the JSX transform.
     * - "classic" refers to the original behavior using `React.createElement`.
     * - "automatic" refers to the transform behavior released with React 17,
     *   where the `jsx` function (or a variation) is automatically imported.
     * - "preserve" leaves the JSX as-is.
     *
     * Default value: "classic".
     */
    jsxRuntime?: "classic" | "automatic" | "preserve";
    /**
     * Compile code for production use. Currently only applies to the JSX
     * transform.
     */
    production?: boolean;
    /**
     * If specified, import path prefix to use in place of "react" when compiling
     * JSX with the automatic runtime.
     */
    jsxImportSource?: string;
    /**
     * If specified, function name to use in place of React.createClass when
     * compiling JSX with the classic runtime.
     */
    jsxPragma?: string;
    /**
     * If specified, function name to use in place of React.Fragment when
     * compiling JSX with the classic runtime.
     */
    jsxFragmentPragma?: string;
    /**
     * If specified, disable automatic removal of type-only import and export
     * statements and names. Only statements and names that explicitly use the
     * `type` keyword are removed.
     */
    keepUnusedImports?: boolean;
    /**
     * If specified, the imports transform does not attempt to change dynamic
     * import() expressions into require() calls.
     */
    preserveDynamicImport?: boolean;
    /**
     * Only relevant when targeting ESM (i.e. when the imports transform is *not*
     * specified). This flag changes the behavior of TS require imports:
     *
     * import Foo = require("foo");
     *
     * to import createRequire, create a require function, and use that function.
     * This is the TS behavior with module: nodenext and makes it easier for the
     * same code to target ESM and CJS.
     */
    injectCreateRequireForImportRequire?: boolean;
    /**
     * If true, replicate the import behavior of TypeScript's esModuleInterop: false.
     */
    enableLegacyTypeScriptModuleInterop?: boolean;
    /**
     * If true, replicate the import behavior Babel 5 and babel-plugin-add-module-exports.
     */
    enableLegacyBabel5ModuleInterop?: boolean;
    /**
     * If specified, we also return a RawSourceMap object alongside the code.
     * filePath must be specified if this option is enabled.
     */
    sourceMapOptions?: SourceMapOptions;
    /**
     * File path to use in error messages, React display names, and source maps.
     */
    filePath?: string;
}

export interface TransformResult {
    code: string;
    sourceMap?: RawSourceMap;
}

export interface RawSourceMap {
    version: number;
    file: string;
    sources: Array<string>;
    sourceRoot?: string;
    sourcesContent?: Array<string>;
    mappings: string;
    names: Array<string>;
}

export function transform(code: string, options: Options): TransformResult;

export function getVersion(): string;

export function getFormattedTokens(code: string, options: Options): string;

// TSX
declare global {
    function renderToString(element: any): string;
    function createElement(type: any, props: any,...children: any[]): any;
    function Fragment(props: any): any;
}