import { deflate } from "compress";
import { basename, resolve } from "./io/path";
import { mergeBuffers } from "./bytes/buffer";

/**
 * @typedef {Object} ZipFile
 * @property {string} path
 * @property {Uint8Array} data
 * @property {Date} [mtime]
 * @property {number} [crc]
 * @property {number} [compressedSize]
 * @property {number} [originalSize]
 * @property {number} [headerOffset]
 */

/**
 * @typedef {Object} ZipOptions
 * @property {number} [level]
 */

/**
 * @typedef {Object} LocalHeaderOptions
 * @property {number} crc
 * @property {number} compressedSize
 * @property {number} originalSize
 * @property {Date} mtime
 */

/**
 * @typedef {Object} CentralDirOptions
 * @property {number} crc
 * @property {number} compressedSize
 * @property {number} originalSize
 * @property {Date} mtime
 * @property {number} headerOffset
 */

/**
 * @typedef {Object} EndRecordOptions
 * @property {number} totalEntries
 * @property {number} cdirSize
 * @property {number} cdirOffset
 */

/**
 * 
 * @param {ZipFile[]} files 
 * @param {ZipOptions} options 
 * @returns {Promise<Uint8Array>}
 */
export async function createZip(files, options = {}) {
    /** @type {{header: Uint8Array, data: Uint8Array, cdir: Uint8Array}[]} */
    const records = await Promise.all(files.map(async file => {
        const crc = calcCRC32(file.data);
        const compressed = deflate(file.data, false, options.level);

        return {
            header: buildLocalHeader(file.path, {
                crc,
                compressedSize: compressed.length,
                originalSize: file.data.length,
                mtime: file.mtime || new Date()
            }),
            data: compressed,
            cdir: buildCentralDir(basename(file.path), {
                crc,
                compressedSize: compressed.length,
                originalSize: file.data.length,
                mtime: file.mtime || new Date(),
                path: file.path,
                data: file.data
            })
        };
    }));

    let offset = 0;
    const chunks = [];

    // 生成文件数据块
    const buf = new Uint8Array(8);
    const bufview = new DataView(buf.buffer);   // uint32
    for (const rec of records) {
        bufview.setUint32(0, offset, true); // 填充头偏移量
        rec.cdir.set(buf, 42);
        chunks.push(rec.header, rec.data);
        offset += rec.header.byteLength + rec.data.byteLength;
    }

    // 构建中央目录
    const cdirBuffers = records.map(r => r.cdir);
    const cdirMerged = /** @type {Uint8Array} */(mergeBuffers.apply(null, cdirBuffers));

    // 生成结束记录
    const endRecord = buildEndRecord({
        totalEntries: files.length,
        cdirSize: cdirMerged.byteLength,
        cdirOffset: offset
    });

    return mergeBuffers(...chunks, cdirMerged, endRecord);
}

/**
 * @param {EndRecordOptions} opts 
 */
function buildEndRecord(opts) {
    const buf = new ArrayBuffer(22);
    const view = new DataView(buf);
    view.setUint32(0, 0x06054b50, true);
    view.setUint16(8, opts.totalEntries, true);
    view.setUint32(16, opts.cdirOffset, true);
    return new Uint8Array(buf);
}

/** @param {Date} date */
function toDosTime(date) {
    return [
        (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >>> 1),
        ((date.getFullYear() - 1980) << 25) | ((date.getMonth() + 1) << 21) | (date.getDate() << 16)
    ];
}

/**
 * 
 * @param {string} filename 
 * @param {ZipFile} opts 
 * @returns 
 */
function buildCentralDir(filename, opts) {
    const [dtime, ddate] = toDosTime(opts.mtime ?? new Date());
    const nameBytes = encodeStr(filename);
    const buf = new ArrayBuffer(46 + nameBytes.length);
    const view = new DataView(buf);

    // Central directory header
    view.setUint32(0, 0x02014b50, true);   // 中央目录签名
    view.setUint16(4, 0x0314, true);       // 版本信息
    view.setUint16(6, 0x0008, true);       // 使用UTF-8标志
    view.setUint16(8, 0x08, true);         // 压缩方法
    view.setUint16(10, dtime, true);       // 修改时间
    view.setUint16(12, ddate, true);       // 修改日期
    view.setUint32(14, opts.crc ?? calcCRC32(opts.data), true);    // CRC32校验
    view.setUint32(18, opts.compressedSize ?? opts.data.byteLength, true); // 压缩后大小
    view.setUint32(22, opts.originalSize ?? 0, true);  // 原始大小
    view.setUint16(26, nameBytes.length, true);    // 文件名长度
    view.setUint16(28, 0, true);          // 扩展字段长度
    view.setUint16(30, 0, true);          // 文件注释长度
    view.setUint16(32, 0, true);          // 磁盘号开始
    view.setUint16(34, 0, true);          // 内部文件属性
    view.setUint32(36, 0, true);          // 外部文件属性
    view.setUint32(40, opts.headerOffset ?? 0, true); // 本地文件头偏移量

    // 写入文件名
    new Uint8Array(buf).set(nameBytes, 46);

    return new Uint8Array(buf);
}


/**
 * CRC32
 * @param {Uint8Array} data 
 * @returns 
 */
function calcCRC32(data) {
    let crc = -1;
    for (let i = 0; i < data.length; i++) {
        crc ^= data[i];
        for (let j = 0; j < 8; j++) {
            crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
        }
    }
    return (crc ^ (-1)) >>> 0; // 转换为无符号
}

/**
 * Convert Date to DOS time
 * @param {Date} date 
 * @returns {[number, number]}
 */
function toDosTime(date) {
    return [
        (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >>> 1),
        ((date.getFullYear() - 1980) << 25) | ((date.getMonth() + 1) << 21) | (date.getDate() << 16)
    ];
}

/**
 * 构建本地文件头
 * @param {string} filename 
 * @param {LocalHeaderOptions} opts 
 * @returns {Uint8Array}
 */
function buildLocalHeader(filename, opts) {
    const [dtime, ddate] = toDosTime(opts.mtime);
    const buf = new ArrayBuffer(30 + filename.length);
    const view = new DataView(buf);

    view.setUint32(0, 0x04034b50, true);  // 签名
    view.setUint16(4, 0x14, true);        // 版本
    view.setUint16(8, 0x08, true);        // 压缩方法
    view.setUint16(10, dtime, true);      // 修改时间
    view.setUint16(12, ddate, true);      // 修改日期
    view.setUint32(14, opts.crc, true);   // CRC32
    view.setUint32(18, opts.compressedSize, true);
    view.setUint32(22, opts.originalSize, true);
    view.setUint16(26, filename.length, true);

    // 使用自定义编码方法
    const nameBytes = encodeStr(filename);
    new Uint8Array(buf).set(nameBytes, 30);

    return new Uint8Array(buf);
}

// 示例用法：
/*
const files = [{
  path: 'test.txt',
  data: encodeStr('Hello World'),
  mtime: new Date()
}];

createZip(files, { level: 6 })
  .then(data => {
    // 处理压缩结果
  });
*/
