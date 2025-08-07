import { resolveDNS } from "socket";

const dns = await resolveDNS("www.bing.com", "114.114.114.114");
console.log(dns);