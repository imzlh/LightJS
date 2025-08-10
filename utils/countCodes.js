import { read } from "fs";
import { Glob2RegExp } from "../lib/io/glob";
import { tree } from "../lib/io/tree";

const findCode = [
    Glob2RegExp('main.c'),
    Glob2RegExp('test/*'),
    Glob2RegExp('types/*'),
    Glob2RegExp('src/*'),
    Glob2RegExp('lib/**'),
    Glob2RegExp('example/**')
];

const files = tree('.').filter(f => findCode.some(g => g.test(f.path)));

const codes = files.map(f => read(f.path, true))
    .reduce((acc, cur) => acc + cur.split('\n').length, 0);

console.log('Total codes:', codes, 'lines in', files.length, 'files');
for(const f of files) console.log('| ', f.path);