/**
 * Simple JSX to HTML Server-Side Rendering Polyfill
 * 支持基本的JSX元素渲染为HTML字符串
 */

/**
 * JSX元素对象类型定义
 * @typedef {Object} JSXElement
 * @property {string|Function} type - 元素类型（标签名或组件函数）
 * @property {Object} props - 元素属性
 * @property {Array<JSXElement>} children - 子元素数组
 */

/**
 * HTML自闭合标签列表
 */
const VOID_ELEMENTS = new Set([
    'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
    'link', 'meta', 'param', 'source', 'track', 'wbr'
]);

/**
 * 需要转义的HTML字符
 */
const HTML_ESCAPES = /** @type {Record<string, string>} */ ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
});

/**
 * 转义HTML字符串
 * @param {string} str - 要转义的字符串
 * @returns {string} 转义后的字符串
 */
function escapeHtml(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/[&<>"']/g, (match) => HTML_ESCAPES[match]);
}

/**
 * 将驼峰式属性名转换为kebab-case
 * @param {string} prop - 属性名
 * @returns {string} 转换后的属性名
 */
function toKebabCase(prop) {
    return prop.replace(/[A-Z]/g, (match) => '-' + match.toLowerCase());
}

/**
 * 处理CSS样式对象
 * @param {Object} style - 样式对象
 * @returns {string} CSS字符串
 */
function stringifyStyle(style) {
    if (typeof style === 'string') return style;
    if (!style || typeof style !== 'object') return '';

    return Object.entries(style)
        .map(([key, value]) => `${toKebabCase(key)}: ${value}`)
        .join('; ');
}

/**
 * 渲染HTML属性
 * @param {Object} props - 属性对象
 * @returns {string} 属性字符串
 */
function renderProps(props) {
    if (!props) return '';

    const attributes = [];

    for (const [key, value] of Object.entries(props)) {
        // 跳过children和特殊属性
        if (key === 'children' || key === 'key' || key === 'ref') continue;

        // 跳过undefined, null, false
        if (value == null || value === false) continue;

        // 处理布尔属性
        if (value === true) {
            attributes.push(key);
            continue;
        }

        // 处理className -> class
        const attrName = key === 'className' ? 'class' : key;

        // 处理style对象
        if (key === 'style' && typeof value === 'object') {
            const styleStr = stringifyStyle(value);
            if (styleStr) {
                attributes.push(`style="${escapeHtml(styleStr)}"`);
            }
            continue;
        }

        // 处理事件处理器（SSR中忽略）
        if (key.startsWith('on') && typeof value === 'function') {
            continue;
        }

        // 处理其他属性
        attributes.push(`${attrName}="${escapeHtml(String(value))}"`);
    }

    return attributes.length > 0 ? ' ' + attributes.join(' ') : '';
}

/**
 * 渲染JSX元素为HTML字符串
 * @param {any} element - JSX元素或任意值
 * @returns {string} HTML字符串
 */
function renderToString(element) {
    // 处理null, undefined, boolean
    if (element == null || typeof element === 'boolean') {
        return '';
    }

    // 处理字符串和数字
    if (typeof element === 'string' || typeof element === 'number') {
        return escapeHtml(String(element));
    }

    // 处理数组
    if (Array.isArray(element)) {
        return element.map(renderToString).join('');
    }

    // 处理JSX元素
    if (element && typeof element === 'object' && element.type) {
        const { type, props } = element;

        // 处理函数组件
        if (typeof type === 'function') {
            const result = type(props || {});
            return renderToString(result);
        }

        // 处理DOM元素
        if (typeof type === 'string') {
            const tagName = type.toLowerCase();
            const attributes = renderProps(props);

            // 处理自闭合标签
            if (VOID_ELEMENTS.has(tagName)) {
                return `<${tagName}${attributes} />`;
            }

            // 处理普通标签
            const children = props?.children;
            const childrenHtml = children ? renderToString(children) : '';

            return `<${tagName}${attributes}>${childrenHtml}</${tagName}>`;
        }
    }

    // 其他情况返回空字符串
    return '';
}

/**
 * JSX工厂函数（用于替代React.createElement）
 * @param {string|Function} type - 元素类型
 * @param {JSXElement} props - 属性对象
 * @param {...any} children - 子元素
 * @returns {JSXElement} JSX元素对象
 */
function createElement(type, props, ...children) {
    // 处理props
    const finalProps = /** @type {JSXElement} */ (props || {});

    // 处理children
    if (children.length > 0) {
        finalProps.children = children.length === 1 ? children[0] : children;
    }

    return {
        type,
        props: finalProps,
        children: []
    };
}

/**
 * Fragment组件（用于包装多个子元素）
 * @param {JSXElement} props - 属性对象
 * @returns {any} 子元素
 */
function Fragment(props) {
    return props.children;
}

export { 
    renderToString, createElement, Fragment, 
    createElement as jsx, createElement as jsxs
};