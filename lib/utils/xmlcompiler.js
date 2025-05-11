/**
 * 将 RootNode 对象转换为格式化的 XML 字符串
 * @param {RootNode} root - 要转换的根节点对象
 * @param {Object} [options] - 格式化选项
 * @param {number} [options.indent=2] - 缩进空格数
 * @param {boolean} [options.pretty=true] - 是否启用美化格式
 * @returns {string} 生成的格式化 XML 字符串
 */
export function compileXML(root, { indent = 2, pretty = true } = {}) {
    if (!pretty) {
        return root.children.map(node => nodeToXml(node, 0, false)).join('');
    }
    return root.children.map(node => nodeToXml(node, 0, true, indent)).join('\n');
}

/**
 * 将单个 Node 对象转换为 XML 字符串
 * @param {Node} node - 要转换的节点对象
 * @param {number} level - 当前缩进层级
 * @param {boolean} pretty - 是否启用美化格式
 * @param {number} [indentSize=2] - 缩进空格数
 * @returns {string} 生成的 XML 片段
 */
function nodeToXml(node, level = 0, pretty = true, indentSize = 2) {
    const indent = pretty ? ' '.repeat(level * indentSize) : '';
    const newLine = pretty ? '\n' : '';
    
    const attributes = Object.entries(node.attributes)
        .map(([key, value]) => ` ${key}="${escapeXml(value)}"`)
        .join('');
    
    const childrenXml = node.children
        .map(child => nodeToXml(child, level + 1, pretty, indentSize))
        .join(pretty ? '\n' : '');
    
    // 自闭合标签处理
    if (!node.content && !node.children.length) {
        return `${indent}<${node.name}${attributes}/>`;
    }
    
    // 有子节点或内容时的处理
    if (pretty && node.children.length) {
        return `${indent}<${node.name}${attributes}>${newLine}` +
               `${childrenXml}${newLine}` +
               `${indent}</${node.name}>`;
    }
    
    // 只有内容时的处理
    return `${indent}<${node.name}${attributes}>${escapeXml(node.content)}${childrenXml}</${node.name}>`;
}

/**
 * 转义 XML 特殊字符
 * @param {string} unsafe - 需要转义的原始字符串
 * @returns {string} 转义后的安全字符串
 */
function escapeXml(unsafe) {
    if (!unsafe) return '';
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
