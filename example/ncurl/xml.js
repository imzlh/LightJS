/**
 * 打印XML根节点（RootNode专用）
 * @param {RootNode} rootNode - XML根节点
 */
export function printXMLTree(rootNode) {
    console.log(`🌳 XML 树结构`);
    console.log(`└─ ${rootNode.name}`);
    
    // 根节点没有attributes和content，直接处理子节点
    if (rootNode.children && rootNode.children.length > 0) {
        const childPrefix = '  '; // 根节点子节点的缩进
        console.log(`${childPrefix}│`);
        
        rootNode.children.forEach((child, index) => {
            const isLastChild = index === rootNode.children.length - 1;
            printXmlNode(child, childPrefix, isLastChild);
        });
    }
}

/**
 * 打印XML普通节点（Node专用）
 * @param {Node} node - XML节点
 * @param {string} [prefix=''] - 当前层级的前缀字符串
 * @param {boolean} [isLastChild=true] - 是否是父节点的最后一个子节点
 */
function printXmlNode(node, prefix = '', isLastChild = true) {
    // 当前节点的连接符号
    const connector = isLastChild ? '└─' : '├─';
    
    // 打印当前节点名称行
    console.log(`${prefix}${connector} ${node.name}`);
    
    // 准备子节点的前缀
    const childPrefix = prefix + (isLastChild ? '  ' : '│ ');
    
    // 打印属性（Node类型有attributes）
    if (node.attributes && Object.keys(node.attributes).length > 0) {
        const attrEntries = Object.entries(node.attributes);
        attrEntries.forEach(([key, value], index) => {
            const lastAttr = index === attrEntries.length - 1;
            const attrConnector = lastAttr ? '└─' : '├─';
            console.log(`${childPrefix}${attrConnector} @${key} = "${value}"`);
        });
    }
    
    // 打印内容（如果有）
    if (node.content && node.content.trim()) {
        const lines = node.content.split('\n');
        lines.forEach((line, index) => {
            const lastLine = index === lines.length - 1;
            const contentConnector = lastLine ? '└─' : '├─';
            console.log(`${childPrefix}${contentConnector} ${line.trim() || '(空行)'}`);
        });
    }
    
    // 递归打印子节点
    if (node.children && node.children.length > 0) {
        console.log(`${childPrefix}│`);
        node.children.forEach((child, index) => {
            const lastChild = index === node.children.length - 1;
            printXmlNode(child, childPrefix, lastChild);
        });
    }
}
