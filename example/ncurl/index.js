import { exit, self } from "process";
import { parseArgs } from "../../lib/utils/args";
import { Handler } from "http";
import { parse } from "xml";
import { printXMLTree } from "./xml";
import { version } from "vm";

const args = parseArgs(self.args, {
    X: "request",
    H: "header",
    d: "data",
    f: "format",
    h: "help"
}, false, [
    'header',
    'request',
    'data',
    'format'
]);
const url = args._[0];
const startTime = performance.now();

if (!url) {
    console.error("curl: try 'curl --help' for more information");
    exit(1);
} else if(args.help){
    console.log("Usage: curl [options] [URL...]");
    console.log("Options:");
    console.log("   -d, --data <data>   HTTP POST data");
    console.log("   -X, --request <command>  Specify request command to use");
    console.log("   -H, --header <header>  Custom header to pass to server");
    console.log("   -f, --format <format>  Output formatting, support json, form, xml, text")
    console.log("   -h, --help     Show this help message");
    exit(0);
}

const firstEl = (/** @type {string[]|string} */ el) => 
    el instanceof Array ? el[0] : el;
const options = {
    method: firstEl(args.request ?? "GET"),
    headers: args.header ? (
            typeof args.header == 'object'
                ? args.header.map(it => it.split('='))
                : [args.header.split('=')]
        ) : [],
    body: firstEl(args.data ?? ""),
    format: firstEl(args.format ?? "text")
};

console.log(`🌐 Fetching ${url} (${options.method})...`)
const xhr = await fetch(url, {
    "body": options.body ? options.body : undefined,
    "method": options.method,
    "headers": { 
        "User-Agent": "ncurl/0.1 LightJS/" + version.version,
        ...Object.fromEntries(options.headers)
    }
});
if(!xhr.ok){
    console.warn(`Server responded with: ${xhr.status} ${Handler.status(xhr.status)}`);
}

console.log(`<< HTTP/${xhr.httpVersion.toFixed(1)} ${xhr.status} ${Handler.status(xhr.status)}`);
for(const [header, values] of Object.entries(xhr.headers.getAll())){
    for(const value of values){
        console.log(`<< ${header}: ${value}`);
    }
}
console.log(`>> `);

switch(options.format){
    case "json":
        console.log(await xhr.json());
    break;

    case "form":
        console.log(await xhr.formData());
    break;

    case "xml":
        const text = await xhr.text();
        printXMLTree(parse(text));
    break;

    case "text":
        console.log(await xhr.text());
    break;

    default:
        console.error(`Unsupported format: ${options.format}`);
    break;
}

let timeStr;
const time = performance.now() - startTime;
if(time <= 10){
    timeStr = `${(time *1000).toFixed(2)}us`;
}else if(time <= 800){
    timeStr = `${(time).toFixed(2)}ms`;
}else{
    timeStr = `${(time / 1000).toFixed(2)}s`;
}

console.log(`Done in ${timeStr}`);