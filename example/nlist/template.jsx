// @ts-nocheck
import { scandir, stat, Stat } from "fs";
import { basename, join, normalize } from "../../lib/io/path";

/**
 * 渲染单个文件/目录项
 * @param {Object} props - 组件属性
 * @param {Stat} props.file - 文件状态对象
 * @param {string} props.name - 显示名称
 * @param {string} props.url - 链接地址
 * @returns {JSX.Element}
 */
function FileItem(props) {
    const iconClass = props.file.isFile ? "fa fa-file" : "fa fa-folder";
    const itemClass = props.file.isFile ? "file" : "directory";
    const formattedDate = new Date(Number(props.file.mtime)).toLocaleString();

    return (
        <a className={itemClass} href={props.url}>
            <div className="name">
                <i className={iconClass}></i>
                <span>{props.name}</span>
            </div>
            <div className="size">{props.file.size}</div>
            <div className="mtime">{formattedDate}</div>
        </a>
    );
}

/**
 * 安全渲染文件项，处理可能的错误
 * @param {Object} props - 组件属性
 * @param {string} props.filePath - 文件路径
 * @param {string} props.absPath - 绝对路径
 * @returns {JSX.Element|null}
 */
function SafeFileItem(props) {
    try {
        const fileStats = stat(props.filePath);
        const normalizedName = normalize(props.filePath);
        return <FileItem file={fileStats} name={basename(normalizedName)} url={props.absPath} />;
    } catch (error) {
        console.error('Error rendering file:', props.filePath, error);
        return null;
    }
}

/**
 * 目录列表主组件
 * @param {Object} props - 组件属性
 * @param {string} props.dir - 目录路径
 * @param {string} props.wwwroot - web根目录
 * @returns {JSX.Element}
 */
export default function renderDir(props) {
    const fullPath = join(props.wwwroot, props.dir);
    const files = scandir(fullPath);

    return (
        <html>
            <head>
                <meta charset="UTF-8" />
                <title>Index of {props.dir}</title>
                <link rel="stylesheet" href="/@static/style.css" />
            </head>
            <body>
                <h1>Index of {props.dir}</h1>
                <div className="container">
                    {files.map(file => (
                        <SafeFileItem
                            key={file.name}
                            filePath={join(fullPath, file.name)}
                            absPath={join(props.dir, file.name)}
                        />
                    ))}
                </div>
            </body>
        </html>
    );
}
