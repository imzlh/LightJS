/**
 * TSRuntime for LightJS
 */

import { exit, self } from "process";
import { parseArgs } from "../utils/args";
import { getVersion } from "./tsutils";
import { version } from "vm";
import { addTransformer, addVModule } from "./resolver";
import { realpath } from "fs";

if(!import.meta.main || Worker.isWorker)
    throw new Error("TSRuntime can only be used in the main thread and as entry");

const args = parseArgs(self.args, {
    h: 'help',
    v: 'version',
    j: 'no-jsx',
    e: 'eval'
}, true, undefined, true);

if(args.help){
    console.log(`
TSRuntime for LightJS v${version.version}
Copyright (c) 2025-present LightJS Team

Usage: tsrt [options] [file]

Options:
    -h, --help     Show this help message
    -v, --version  Show version information
    -j, --no-jsx   Disable JSX support
    -e, --eval     Evaluate code and exit

Examples:
    tsrt index.ts
    tsrt -j index.tsx
`);
    exit(0);
}

if(args.version){
    console.log(`TSRuntime for LightJS v${version.version}`);
    console.log(`with QuickJS v${version.quickjs}, Sucrase v${getVersion()}`);
    exit(0);
}

if(args._.length === 0){
    console.error("No input file specified");
    console.log("Use -h or --help for help");
    exit(1);
}

if(!args['no-jsx']){
    addTransformer('jsx');
}

if(args.eval){
    const code = args._.slice(1).join(' ');
    addVModule('__main__', code);
    // @ts-ignore
    await import('__main__');
}else{
    const file = args._[0];
    await import(realpath(file));
}