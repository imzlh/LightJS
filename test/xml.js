import { self } from "process";
import { read } from "fs"
import { parse } from "xml";
import { compileXML } from "../lib/utils/xmlcompiler";

self.cwd = import.meta.dirname;
console.log(import.meta);

test('xml', () => {
    const file = read('xmltest.xml', true);
    const xml = parse(file);
    
    // build XML tree
    console.log(compileXML(xml));
    // console.log(xml);
})