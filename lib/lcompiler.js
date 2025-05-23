import { self } from "process";
import { read, write } from "fs";
import { compile } from "vm";

const filename = self.argv[0];
if(!filename) throw new Error("No filename provided");

const content = read(filename, true);
const out = compile(content, self.argv[2] ?? 'main');
const basename = /** @type {string} */(filename.split('/').pop()).split('.')[0];
if(!self.argv[1]) self.argv[1] = basename + '.h';

// write to C file
let c_out = '// Generated by LightJS lcompiler\n\n#pragma once\n#include <stdint.h>\n\nconst uint8_t code_' + basename + '[] = {';
for(let i = 0; i < out.length; i+= 32){
    c_out += '\n    ' +  out.slice(i, i+32).reduce((acc, val) => acc += '0x' + val.toString(16).padStart(2, '0').toUpperCase() + ', ', "");
}
c_out += '\n};\n';

// write to header file
write(self.argv[1], c_out);
console.log("Compiled to " + self.argv[1]);