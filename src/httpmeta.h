#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

struct __http_status {
    uint16_t status;
    const char* reason;
};

const struct __http_status http_status_codes[] = {
    { 100, "Continue" },
    { 101, "Switching Protocols" },
    { 102, "Processing" },  // WebDAV; RFC 2518
    { 103, "Early Hints" },  // RFC 8297

    { 200, "OK" },
    { 201, "Created" },
    { 202, "Accepted" },
    { 203, "Non-Authoritative Information" },  // since HTTP/1.1
    { 204, "No Content" },
    { 205, "Reset Content" },
    { 206, "Partial Content" },  // RFC 7233
    { 207, "Multi-Status" },  // WebDAV; RFC 4918
    { 208, "Already Reported" },  // WebDAV; RFC 5842
    { 226, "IM Used" },  // RFC 3229

    { 300, "Multiple Choices" },
    { 301, "Moved Permanently" },
    { 302, "Found" },  // Previously "Moved temporarily"
    { 303, "See Other" },  // since HTTP/1.1
    { 304, "Not Modified" },  // RFC 7232
    { 305, "Use Proxy" },  // since HTTP/1.1
    { 306, "Switch Proxy" },
    { 307, "Temporary Redirect" },  // since HTTP/1.1
    { 308, "Permanent Redirect" },  // RFC 7538

    { 400, "Bad Request" },
    { 401, "Unauthorized" },  // RFC 7235
    { 402, "Payment Required" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 405, "Method Not Allowed" },
    { 406, "Not Acceptable" },
    { 407, "Proxy Authentication Required" },  // RFC 7235
    { 408, "Request Timeout" },
    { 409, "Conflict" },
    { 410, "Gone" },
    { 411, "Length Required" },
    { 412, "Precondition Failed" },  // RFC 7232
    { 413, "Payload Too Large" },  // RFC 7231
    { 414, "URI Too Long" },  // RFC 7231
    { 415, "Unsupported Media Type" },  // RFC 7231
    { 416, "Range Not Satisfiable" },  // RFC 7233
    { 417, "Expectation Failed" },
    { 418, "I\"m a teapot" },  // RFC 2324,  RFC 7168
    { 421, "Misdirected Request" },  // RFC 7540
    { 422, "Unprocessable Entity" },  // WebDAV; RFC 4918
    { 423, "Locked" },  // WebDAV; RFC 4918
    { 424, "Failed Dependency" },  // WebDAV; RFC 4918
    { 425, "Too Early" },  // RFC 8470
    { 426, "Upgrade Required" },
    { 428, "Precondition Required" },  // RFC 6585
    { 429, "Too Many Requests" },  // RFC 6585
    { 431, "Request Header Fields Too Large" },  // RFC 6585
    { 451, "Unavailable For Legal Reasons" },  // RFC 7725

    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 504, "Gateway Timeout" },
    { 505, "HTTP Version Not Supported" },
    { 506, "Variant Also Negotiates" },  // RFC 2295
    { 507, "Insufficient Storage" },  // WebDAV; RFC 4918
    { 508, "Loop Detected" },  // WebDAV; RFC 5842
    { 510, "Not Extended" },  // RFC 2774
    { 511, "Network Authentication Required" },  // RFC 6585
};

// 二分法查找
static inline const char* http_get_reason_by_code(uint16_t status) {
    int left = 0, right = countof(http_status_codes) - 1;
    while (left <= right) {
        int mid = (left + right) / 2;
        if (http_status_codes[mid].status == status) {
            return http_status_codes[mid].reason;
        } else if (http_status_codes[mid].status < status) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return "Unknown Status";
}

struct MimeTypeEntry {
    const char *mime_type;
    const char *extensions[10];
};

#pragma GCC diagnostic ignored "-Wmissing-braces"
static const struct MimeTypeEntry mime_types[83] = {
    // 文本类型
    {"text/html", {"html", "htm", "shtml", NULL}},
    {"text/css", {"css", NULL}},
    {"text/xml", {"xml", NULL}},
    {"text/mathml", {"mml", NULL}},
    {"text/plain", {"txt", "log", "cue", "ini", NULL}},
    {"text/vnd.sun.j2me.app-descriptor", {"jad", NULL}},
    {"text/vnd.wap.wml", {"wml", NULL}},
    {"text/x-component", {"htc", NULL}},
    {"text/vtt", {"vtt", NULL}},
    {"text/ass", {"ass", NULL}},

    // 图片类型
    {"image/gif", {"gif", NULL}},
    {"image/jpeg", {"jpeg", "jpg", NULL}},
    {"image/png", {"png", NULL}},
    {"image/tiff", {"tif", "tiff", NULL}},
    {"image/vnd.wap.wbmp", {"wbmp", NULL}},
    {"image/x-icon", {"ico", NULL}},
    {"image/x-jng", {"jng", NULL}},
    {"image/x-ms-bmp", {"bmp", NULL}},
    {"image/svg+xml", {"svg", "svgz", NULL}},
    {"image/webp", {"webp", NULL}},
    {"image/avif", {"avif", NULL}},
    {"image/jpegxl", {"jxl", NULL}},

    // 应用程序类型
    {"application/javascript", {"js", NULL}},
    {"application/atom+xml", {"atom", NULL}},
    {"application/rss+xml", {"rss", NULL}},
    {"application/font-woff", {"woff", NULL}},
    {"application/java-archive", {"jar", "war", "ear", NULL}},
    {"application/json", {"json", NULL}},
    {"application/mac-binhex40", {"hqx", NULL}},
    {"application/msword", {"doc", NULL}},
    {"application/pdf", {"pdf", NULL}},
    {"application/postscript", {"ps", "eps", "ai", NULL}},
    {"application/rtf", {"rtf", NULL}},
    {"application/vnd.apple.mpegurl", {"m3u8", NULL}},
    {"application/vnd.ms-excel", {"xls", NULL}},
    {"application/vnd.ms-fontobject", {"eot", NULL}},
    {"application/vnd.ms-powerpoint", {"ppt", NULL}},
    {"application/vnd.wap.wmlc", {"wmlc", NULL}},
    {"application/vnd.google-earth.kml+xml", {"kml", NULL}},
    {"application/vnd.google-earth.kmz", {"kmz", NULL}},
    {"application/x-7z-compressed", {"7z", NULL}},
    {"application/x-cocoa", {"cco", NULL}},
    {"application/x-java-archive-diff", {"jardiff", NULL}},
    {"application/x-java-jnlp-file", {"jnlp", NULL}},
    {"application/x-makeself", {"run", NULL}},
    {"application/x-perl", {"pl", "pm", NULL}},
    {"application/x-pilot", {"prc", "pdb", NULL}},
    {"application/x-rar-compressed", {"rar", NULL}},
    {"application/x-redhat-package-manager", {"rpm", NULL}},
    {"application/x-sea", {"sea", NULL}},
    {"application/x-shockwave-flash", {"swf", NULL}},
    {"application/x-stuffit", {"sit", NULL}},
    {"application/x-tcl", {"tcl", "tk", NULL}},
    {"application/x-x509-ca-cert", {"der", "pem", "crt", NULL}},
    {"application/x-xpinstall", {"xpi", NULL}},
    {"application/xhtml+xml", {"xhtml", NULL}},
    {"application/xspf+xml", {"xspf", NULL}},
    {"application/zip", {"zip", NULL}},

    // 二进制类型
    {"application/octet-stream", {"bin", "exe", "dll", "deb", "dmg", "iso", "img", "msi", NULL}},

    // Office文档类型
    {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", {"docx", NULL}},
    {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", {"xlsx", NULL}},
    {"application/vnd.openxmlformats-officedocument.presentationml.presentation", {"pptx", NULL}},

    // 音频类型
    {"audio/midi", {"mid", "midi", "kar", NULL}},
    {"audio/mpeg", {"mp3", NULL}},
    {"audio/ogg", {"ogg", "opus", NULL}},
    {"audio/x-m4a", {"m4a", NULL}},
    {"audio/x-realaudio", {"ra", NULL}},
    {"audio/aac", {"aac", NULL}},
    {"audio/x-caf", {"caf", NULL}},
    {"audio/flac", {"flac", NULL}},

    // 视频类型
    {"video/3gpp", {"3gpp", "3gp", NULL}},
    {"video/mp2t", {"ts", "m2ts", NULL}},
    {"video/mp4", {"mp4", NULL}},
    {"video/quicktime", {"mov", NULL}},
    {"video/webm", {"webm", "mkv", NULL}},
    {"video/x-flv", {"flv", NULL}},
    {"video/x-m4v", {"m4v", NULL}},
    {"video/x-mng", {"mng", NULL}},
    {"video/x-ms-asf", {"asx", "asf", NULL}},
    {"video/x-ms-wmv", {"wmv", NULL}},
    {"video/x-msvideo", {"avi", NULL}},
    {"video/ogg", {"ogv", NULL}},

    // 结束标记
    {NULL, NULL}
};

/**
 * 根据文件扩展名查找对应的MIME类型
 * @param ext 文件扩展名(不带点)
 * @return 对应的MIME类型字符串，找不到则返回"application/octet-stream"
 */
const char *get_mime_by_ext(const char *ext) {
    if (!ext || *ext == '\0') return "application/octet-stream";
    size_t ext_len = strlen(ext);

    for (const struct MimeTypeEntry *entry = mime_types; entry -> mime_type != NULL; entry++) {
        for (int i = 0; entry -> extensions[i] != NULL; i++) {
            if (entry -> extensions[i][ext_len] == '\0' && memcmp(entry -> extensions[i], ext, ext_len) == 0) {
                return entry -> mime_type;
            }
        }
    }
    
    return "application/octet-stream";
}