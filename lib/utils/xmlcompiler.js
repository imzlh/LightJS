/**
 * 将 RootNode 对象转换为 XML 字符串
 * @param {RootNode} root - 要转换的根节点对象
 * @returns {string} 生成的 XML 字符串
 */
export function compileXML(root) {
    const childrenXml = root.children.map(node => nodeToXml(node)).join('');
    return childrenXml;
}

/**
 * 将单个 Node 对象转换为 XML 字符串
 * @param {Node} node - 要转换的节点对象
 * @returns {string} 生成的 XML 片段
 */
function nodeToXml(node) {
    const attributes = Object.entries(node.attributes)
        .map(([key, value]) => ` ${key}="${escapeXml(value)}"`)
        .join('');
    
    const childrenXml = node.children.map(child => nodeToXml(child)).join('');
    
    if (!node.content && !childrenXml.length) {
        return `<${node.name}${attributes}/>`;
    }
    
    return `<${node.name}${attributes}>${escapeXml(node.content)}${childrenXml}</${node.name}>`;
}

/**
 * 转义 XML 特殊字符
 * @param {string} unsafe - 需要转义的原始字符串
 * @returns {string} 转义后的安全字符串
 */
function escapeXml(unsafe) {
    return unsafe.replace(/[<>&'"]/g, c => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
            default: return c;
        }
    });
}
