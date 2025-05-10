interface RootNode {
    name: '<root>';
    children: Node[];
}

interface Node {
    name: string;
    content: string;
    attributes: {[key: string]: string};
    children: Node[];
    parent: Node | RootNode;
}

declare module 'xml'{
    export function parse(xml: string): RootNode;
}