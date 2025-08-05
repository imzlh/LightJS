/**
 * 针对 QuickJS 优化的高性能 Source Map 解析器
 * 
 * 特点：
 * 1. 使用 Map 和 TypedArray 优化查表性能
 * 2. 延迟解析 VLQ 编码（按需解析）
 * 3. 使用二分查找快速定位映射位置
 * 4. 内存高效设计
 * 
 * @typedef {Object} SourceMapPosition
 * @property {string} source - 原始源文件路径
 * @property {number} line - 原始行号 (1-based)
 * @property {number} column - 原始列号 (0-based)
 * @property {string|null} name - 原始变量名
 */

class QuickJSSourceMap {
    /**
     * 创建 Source Map 解析器实例
     * @param {Object} rawSourceMap - 原始 Source Map 对象
     */
    constructor(rawSourceMap) {
        if (rawSourceMap.version !== 3) {
            throw new Error(`不支持 Source Map 版本: v${rawSourceMap.version}`);
        }

        // 基础元数据
        this.sources = rawSourceMap.sources;
        this.names = rawSourceMap.names;
        this.mappings = rawSourceMap.mappings;
        this.sourceRoot = rawSourceMap.sourceRoot || '';

        // 性能优化：预解析行索引
        this.lineOffsets = this.#parseLineOffsets();

        // 缓存解析过的行
        this.parsedLines = new Map();

        // 状态缓存（用于 VLQ 解码）
        this.state = {
            generatedColumn: 0,
            sourceIndex: 0,
            originalLine: 0,
            originalColumn: 0,
            nameIndex: 0
        };

        // VLQ 字符映射表 (Base64)
        this.vlqMap = new Map();
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            .split('')
            .forEach((char, idx) => this.vlqMap.set(char, idx));
    }

    /**
     * 解析行偏移量（快速定位行）
     * @private
     * @returns {Uint32Array} 每行的起始索引
     */
    #parseLineOffsets() {
        const offsets = [];
        let start = 0;

        for (let i = 0; i < this.mappings.length; i++) {
            if (this.mappings[i] === ';') {
                offsets.push(start);
                start = i + 1;
            }
        }
        offsets.push(start); // 最后一行

        return new Uint32Array(offsets);
    }

    /**
     * VLQ 解码 (可变长度量)
     * @private
     * @param {string} str - VLQ 编码字符串
     * @returns {Int32Array} 解码后的整数数组
     */
    #vlqDecode(str) {
        const result = [];
        let shift = 0;
        let value = 0;
        let continuation = true;

        for (let i = 0; i < str.length; i++) {
            const char = str[i];
            const digit = this.vlqMap.get(char);

            if (digit === undefined) {
                throw new Error(`无效的 VLQ 字符: ${char}`);
            }

            continuation = !!(digit & 32);
            value += (digit & 31) << shift;
            shift += 5;

            if (!continuation) {
                // 符号位判断
                const negate = value & 1;
                value >>= 1;
                result.push(negate ? -value : value);
                value = shift = 0;
            }
        }

        return new Int32Array(result);
    }

    /**
     * 解析单行映射
     * @private
     * @param {number} line - 行号 (0-based)
     * @returns {Array} 解析后的段列表
     */
    #parseLine(line) {
        if (this.parsedLines.has(line)) {
            return this.parsedLines.get(line);
        }

        const lineStart = this.lineOffsets[line];
        const lineEnd = line < this.lineOffsets.length - 1
            ? this.lineOffsets[line + 1] - 1
            : this.mappings.length;

        const lineStr = this.mappings.substring(lineStart, lineEnd);
        const segments = [];
        let segmentStart = 0;

        // 重置列状态（行开始时）
        this.state.generatedColumn = 0;

        for (let i = 0; i <= lineStr.length; i++) {
            if (i === lineStr.length || lineStr[i] === ',') {
                const segment = lineStr.substring(segmentStart, i);
                segmentStart = i + 1;

                if (segment) {
                    segments.push(this.#parseSegment(segment));
                }
            }
        }

        // 缓存解析结果
        this.parsedLines.set(line, segments);
        return segments;
    }

    /**
     * 解析单个映射段
     * @private
     * @param {string} segment - 段字符串
     * @returns {Object} 解析后的段对象
     */
    #parseSegment(segment) {
        const values = this.#vlqDecode(segment);
        const result = {};

        // 生成列位置（总是存在）
        this.state.generatedColumn += values[0];
        result.generatedColumn = this.state.generatedColumn;

        if (values.length > 1) {
            // 源文件索引
            this.state.sourceIndex += values[1];
            result.source = this.sources[this.state.sourceIndex];

            // 原始行位置
            this.state.originalLine += values[2];
            result.originalLine = this.state.originalLine + 1; // 转为 1-based

            // 原始列位置
            this.state.originalColumn += values[3];
            result.originalColumn = this.state.originalColumn;

            // 名称索引（如果存在）
            if (values.length > 4) {
                this.state.nameIndex += values[4];
                result.name = this.names[this.state.nameIndex];
            }
        }

        return result;
    }

    /**
     * 在已排序的段列表中执行二分查找
     * @private
     * @param {Array} segments - 段列表
     * @param {number} column - 目标列号
     * @returns {Object|null} 找到的映射段
     */
    #binarySearchSegment(segments, column) {
        let low = 0;
        let high = segments.length - 1;

        while (low <= high) {
            const mid = (low + high) >>> 1;
            const segment = segments[mid];

            if (segment.generatedColumn < column) {
                low = mid + 1;
            } else if (segment.generatedColumn > column) {
                high = mid - 1;
            } else {
                return segment;
            }
        }

        // 返回小于等于目标列的最大段
        return high >= 0 ? segments[high] : null;
    }

    /**
     * 获取原始位置信息
     * @param {Object} position - 目标位置
     * @param {number} position.line - 行号 (1-based)
     * @param {number} position.column - 列号 (0-based)
     * @returns {SourceMapPosition|null} 原始位置信息
     */
    originalPositionFor({ line, column }) {
        // 转换为 0-based 内部行号
        const lineIndex = line - 1;

        // 边界检查
        if (lineIndex < 0 || lineIndex >= this.lineOffsets.length) {
            return null;
        }

        // 获取并解析该行
        const segments = this.#parseLine(lineIndex);

        if (segments.length === 0) {
            return null;
        }

        // 二分查找列
        const segment = this.#binarySearchSegment(segments, column);

        if (!segment || !segment.source) {
            return null;
        }

        return {
            source: this.sourceRoot
                ? `${this.sourceRoot}/${segment.source}`
                : segment.source,
            line: segment.originalLine,
            column: segment.originalColumn,
            name: segment.name || null
        };
    }

    /**
     * 销毁解析器并释放内存
     */
    destroy() {
        this.parsedLines.clear();
        this.lineOffsets = new Uint32Array(0);
        this.state = null;
    }
}

// 使用示例 -----------------------------------------------------
// 模拟 Source Map 数据
const rawSourceMap = {
    version: 3,
    file: "app.min.js",
    sourceRoot: "src",
    sources: ["app.js", "utils.js"],
    names: ["add", "multiply", "result"],
    mappings: "AAAA,SAASA,IAAMC,GACb;AACA,MAAMC;"
};

// 创建解析器实例
const parser = new QuickJSSourceMap(rawSourceMap);

// 查询位置映射
const position = parser.originalPositionFor({
    line: 1,   // 生成代码中的行号 (1-based)
    column: 15 // 生成代码中的列号 (0-based)
});

console.log("映射结果:", position);

// 使用后清理
parser.destroy();