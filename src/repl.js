/*
 * QuickJS Read Eval Print Loop
 *
 * Copyright (c) 2017-2020 Fabrice Bellard
 * Copyright (c) 2017-2020 Charlie Gordon
 * Copyright (c) 2025 iz(LightJS)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

import { exit, self, signals, stdin, stdout } from 'process';
import { read, write } from 'fs';
import { Sandbox } from 'vm';

/**
 * @type {Record<string, string>}
 */
var colors = {
    none: "\x1b[0m",
    black: "\x1b[30m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    blue: "\x1b[34m",
    magenta: "\x1b[35m",
    cyan: "\x1b[36m",
    white: "\x1b[37m",
    gray: "\x1b[30;1m",
    grey: "\x1b[30;1m",
    bright_red: "\x1b[31;1m",
    bright_green: "\x1b[32;1m",
    bright_yellow: "\x1b[33;1m",
    bright_blue: "\x1b[34;1m",
    bright_magenta: "\x1b[35;1m",
    bright_cyan: "\x1b[36;1m",
    bright_white: "\x1b[37;1m",
};

/**
 * @type {Record<string, Record<string, string>>}
 */
var themes = {
    dark: {
        'annotation': 'cyan',
        'boolean': 'bright_white',
        'comment': 'white',
        'date': 'magenta',
        'default': 'bright_green',
        'error': 'bright_red',
        'function': 'bright_yellow',
        'identifier': 'bright_green',
        'keyword': 'bright_white',
        'null': 'bright_white',
        'number': 'green',
        'other': 'white',
        'propname': 'white',
        'regexp': 'cyan',
        'string': 'bright_cyan',
        'symbol': 'bright_white',
        'type': 'bright_magenta',
        'undefined': 'bright_white',
    },
    light: {
        'annotation': 'cyan',
        'boolean': 'bright_magenta',
        'comment': 'grey',
        'date': 'magenta',
        'default': 'black',
        'error': 'red',
        'function': 'bright_yellow',
        'identifier': 'black',
        'keyword': 'bright_magenta',
        'null': 'bright_magenta',
        'number': 'green',
        'other': 'black',
        'propname': 'black',
        'regexp': 'cyan',
        'string': 'bright_cyan',
        'symbol': 'grey',
        'type': 'bright_magenta',
        'undefined': 'bright_magenta',
    },
};
var styles = themes.dark;
var utf8 = true;
var show_time = false;
var show_colors = true;
var show_hidden = false;
var show_depth = 2;
var hex_mode = false;
var use_strict = false;

/** @type {string[]} */ var history = [];
/** @type {number} */ var history_index;
var clip_board = "";
var pstate = "";
var prompt = "";
var plen = 0;
var ps1 = " > ";
var ps2 = "  ... ";
/** @type {number} */ var eval_start_time;
var eval_time = 0;
var mexpr = "";
var level = 0;
var cmd = "";
var cursor_pos = 0;
var last_cmd = "";
var last_cursor_pos = 0;
var /** @type {Function} */ this_fun, /** @type {Function} */ last_fun;
var quote_flag = false;

var utf8_state = 0;
var utf8_val = 0;

/** @type {number} */ var term_width;
/* current X position of the cursor in the terminal */
var term_cursor_x = 0;

var content = new Sandbox();

/**
 * 
 * @param {string} data 
 */
function writeToStdout(data){
    const d = encodeStr(String(data));
    stdout.write(d);
}

function termInit() {
    var tab;

    /* get the terminal size */
    term_width = 80;
    if (stdin.isTTY) {
        tab = stdin.ttySize;
        stdin.ttyRaw(true);
        if (tab)
            term_width = tab[1];
    }

    /* install a Ctrl-C signal handler */
    self.signal(signals.SIGINT, sigint_handler);
}

function sigint_handler() {
    /* send Ctrl-C to readline */
    handle_byte(3);
}

/**
 * 
 * @param {number} c 
 */
function handle_byte(c) {
    if (!utf8) {
        handle_char(c);
    } else if (utf8_state !== 0 && (c >= 0x80 && c < 0xc0)) {
        utf8_val = (utf8_val << 6) | (c & 0x3F);
        utf8_state--;
        if (utf8_state === 0) {
            handle_char(utf8_val);
        }
    } else if (c >= 0xc0 && c < 0xf8) {
        utf8_state = 1 + Number(c >= 0xe0) + Number(c >= 0xf0);
        utf8_val = c & ((1 << (6 - utf8_state)) - 1);
    } else {
        utf8_state = 0;
        handle_char(c);
    }
}

/**
 * 
 * @param {string} c 
 * @returns 
 */
function is_alpha(c) {
    return typeof c === "string" &&
        ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

/**
 * 
 * @param {string} c 
 * @returns 
 */
function is_digit(c) {
    return typeof c === "string" && (c >= '0' && c <= '9');
}

/**
 * 
 * @param {string} c 
 * @returns 
 */
function is_word(c) {
    return typeof c === "string" &&
        (is_alpha(c) || is_digit(c) || c == '_' || c == '$');
}

/**
 * 
 * @param {string} str
 * @returns 
 */
function ucs_length(str) {
    var len, c, i, str_len = str.length;
    len = 0;
    /* we never count the trailing surrogate to have the
     following property: ucs_length(str) =
     ucs_length(str.substring(0, a)) + ucs_length(str.substring(a,
     str.length)) for 0 <= a <= str.length */
    for (i = 0; i < str_len; i++) {
        c = str.charCodeAt(i);
        if (c < 0xdc00 || c >= 0xe000)
            len++;
    }
    return len;
}

/**
 * 
 * @param {string} c 
 * @returns 
 */
function is_trailing_surrogate(c) {
    if (typeof c !== "string")
        return false;
    const d = /** @type {number} */ (c.codePointAt(0)); /* can be NaN if empty string */
    return d >= 0xdc00 && d < 0xe000;
}

/**
 * 
 * @param {string} a
 * @param {string} b
 * @returns 
 */
function is_balanced(a, b) {
    switch (a + b) {
        case "()":
        case "[]":
        case "{}":
            return true;
    }
    return false;
}

/**
 * 
 * @param {string} str 
 * @param {number} start 
 * @param {string[]} style_names 
 */
async function print_color_text(str, start, style_names) {
    var i, j;
    for (j = start; j < str.length;) {
        var style = style_names[i = j];
        while (++j < str.length && style_names[j] == style)
            continue;
        writeToStdout(colors[styles[style] || 'none']);
        writeToStdout(str.substring(i, j));
        writeToStdout(colors['none']);
    }
}

/**
 * 
 * @param {number} n 
 * @param {string} code 
 */
function print_csi(n, code) {
    writeToStdout("\x1b[" + ((n != 1) ? n : "") + code);
}

/* XXX: handle double-width characters */
/**
 * 
 * @param {number} delta 
 */
function move_cursor(delta) {
    var i, l;
    if (delta > 0) {
        while (delta != 0) {
            if (term_cursor_x == (term_width - 1)) {
                writeToStdout("\n"); /* translated to CRLF */
                term_cursor_x = 0;
                delta--;
            } else {
                l = Math.min(term_width - 1 - term_cursor_x, delta);
                print_csi(l, "C"); /* right */
                delta -= l;
                term_cursor_x += l;
            }
        }
    } else {
        delta = -delta;
        while (delta != 0) {
            if (term_cursor_x == 0) {
                print_csi(1, "A"); /* up */
                print_csi(term_width - 1, "C"); /* right */
                delta--;
                term_cursor_x = term_width - 1;
            } else {
                l = Math.min(delta, term_cursor_x);
                print_csi(l, "D"); /* left */
                delta -= l;
                term_cursor_x -= l;
            }
        }
    }
}

function update() {
    var i, cmd_len;
    /* cursor_pos is the position in 16 bit characters inside the
       UTF-16 string 'cmd' */
    if (cmd != last_cmd) {
        if (!show_colors && last_cmd.substring(0, last_cursor_pos) == cmd.substring(0, last_cursor_pos)) {
            /* optimize common case */
            writeToStdout(cmd.substring(last_cursor_pos));
        } else {
            /* goto the start of the line */
            move_cursor(-ucs_length(last_cmd.substring(0, last_cursor_pos)));
            if (show_colors) {
                var str = mexpr ? mexpr + '\n' + cmd : cmd;
                var start = str.length - cmd.length;
                var colorstate = colorize_js(str);
                print_color_text(str, start, colorstate[2]);
            } else {
                writeToStdout(cmd);
            }
        }
        term_cursor_x = (term_cursor_x + ucs_length(cmd)) % term_width;
        if (term_cursor_x == 0) {
            /* show the cursor on the next line */
            writeToStdout(" \x08");
        }
        /* remove the trailing characters */
        writeToStdout("\x1b[J");
        last_cmd = cmd;
        last_cursor_pos = cmd.length;
    }
    if (cursor_pos > last_cursor_pos) {
        move_cursor(ucs_length(cmd.substring(last_cursor_pos, cursor_pos)));
    } else if (cursor_pos < last_cursor_pos) {
        move_cursor(-ucs_length(cmd.substring(cursor_pos, last_cursor_pos)));
    }
    last_cursor_pos = cursor_pos;
    stdout.fflush(); // make output synchronous
}

/**
 * editing commands
 * @param {string} str 
 */
function insert(str) {
    if (str) {
        cmd = cmd.substring(0, cursor_pos) + str + cmd.substring(cursor_pos);
        cursor_pos += str.length;
    }
}

function quoted_insert() {
    quote_flag = true;
}

function abort() {
    cmd = "";
    cursor_pos = 0;
    return -2;
}

function alert() {
}

function beginning_of_line() {
    cursor_pos = 0;
}

function end_of_line() {
    cursor_pos = cmd.length;
}

function forward_char() {
    if (cursor_pos < cmd.length) {
        cursor_pos++;
        while (is_trailing_surrogate(cmd.charAt(cursor_pos)))
            cursor_pos++;
    }
}

function backward_char() {
    if (cursor_pos > 0) {
        cursor_pos--;
        while (is_trailing_surrogate(cmd.charAt(cursor_pos)))
            cursor_pos--;
    }
}

/**
 * 
 * @param {number} pos 
 * @returns 
 */
function skip_word_forward(pos) {
    while (pos < cmd.length && !is_word(cmd.charAt(pos)))
        pos++;
    while (pos < cmd.length && is_word(cmd.charAt(pos)))
        pos++;
    return pos;
}

/**
 * 
 * @param {number} pos 
 * @returns 
 */
function skip_word_backward(pos) {
    while (pos > 0 && !is_word(cmd.charAt(pos - 1)))
        pos--;
    while (pos > 0 && is_word(cmd.charAt(pos - 1)))
        pos--;
    return pos;
}

function forward_word() {
    cursor_pos = skip_word_forward(cursor_pos);
}

function backward_word() {
    cursor_pos = skip_word_backward(cursor_pos);
}

function clear_screen() {
    directives["clear"]();
    return -2;
}

function accept_line() {
    writeToStdout("\n");
    history_add(cmd);
    return -1;
}

/**
 * 
 * @param {string} str 
 */
function history_add(str) {
    str = str.trimRight();
    if (str) {
        while (history.length && !history[history.length - 1])
            history.length--;
        history.push(str);
    }
    history_index = history.length;
}

function previous_history() {
    if (history_index > 0) {
        if (history_index == history.length) {
            history.push(cmd);
        }
        history_index--;
        cmd = history[history_index];
        cursor_pos = cmd.length;
    }
}

function next_history() {
    if (history_index < history.length - 1) {
        history_index++;
        cmd = history[history_index];
        cursor_pos = cmd.length;
    }
}

/**
 * 
 * @param {number} dir 
 * @returns 
 */
function history_search(dir) {
    var pos = cursor_pos;
    for (var i = 1; i <= history.length; i++) {
        var index = (history.length + i * dir + history_index) % history.length;
        if (history[index].substring(0, pos) == cmd.substring(0, pos)) {
            history_index = index;
            cmd = history[index];
            return;
        }
    }
}

function history_search_backward() {
    return history_search(-1);
}

function history_search_forward() {
    return history_search(1);
}

/**
 * 
 * @param {number} dir 
 */
function delete_char_dir(dir) {
    var start, end;

    start = cursor_pos;
    if (dir < 0) {
        start--;
        while (is_trailing_surrogate(cmd.charAt(start)))
            start--;
    }
    end = start + 1;
    while (is_trailing_surrogate(cmd.charAt(end)))
        end++;

    if (start >= 0 && start < cmd.length) {
        if (last_fun === kill_region) {
            kill_region(start, end, dir);
        } else {
            cmd = cmd.substring(0, start) + cmd.substring(end);
            cursor_pos = start;
        }
    }
}

function delete_char() {
    delete_char_dir(1);
}

function control_d() {
    if (cmd.length == 0) {
        writeToStdout("\n");
        return -3; /* exit read eval print loop */
    } else {
        delete_char_dir(1);
    }
}

function backward_delete_char() {
    delete_char_dir(-1);
}

function transpose_chars() {
    var pos = cursor_pos;
    if (cmd.length > 1 && pos > 0) {
        if (pos == cmd.length)
            pos--;
        cmd = cmd.substring(0, pos - 1) + cmd.substring(pos, pos + 1) +
            cmd.substring(pos - 1, pos) + cmd.substring(pos + 1);
        cursor_pos = pos + 1;
    }
}

function transpose_words() {
    var p1 = skip_word_backward(cursor_pos);
    var p2 = skip_word_forward(p1);
    var p4 = skip_word_forward(cursor_pos);
    var p3 = skip_word_backward(p4);

    if (p1 < p2 && p2 <= cursor_pos && cursor_pos <= p3 && p3 < p4) {
        cmd = cmd.substring(0, p1) + cmd.substring(p3, p4) +
            cmd.substring(p2, p3) + cmd.substring(p1, p2);
        cursor_pos = p4;
    }
}

function upcase_word() {
    var end = skip_word_forward(cursor_pos);
    cmd = cmd.substring(0, cursor_pos) +
        cmd.substring(cursor_pos, end).toUpperCase() +
        cmd.substring(end);
}

function downcase_word() {
    var end = skip_word_forward(cursor_pos);
    cmd = cmd.substring(0, cursor_pos) +
        cmd.substring(cursor_pos, end).toLowerCase() +
        cmd.substring(end);
}

/**
 * 
 * @param {number} start 
 * @param {number} end 
 * @param {number} dir 
 */
function kill_region(start, end, dir) {
    var s = cmd.substring(start, end);
    if (last_fun !== kill_region)
        clip_board = s;
    else if (dir < 0)
        clip_board = s + clip_board;
    else
        clip_board = clip_board + s;

    cmd = cmd.substring(0, start) + cmd.substring(end);
    if (cursor_pos > end)
        cursor_pos -= end - start;
    else if (cursor_pos > start)
        cursor_pos = start;
    this_fun = kill_region;
}

function kill_line() {
    kill_region(cursor_pos, cmd.length, 1);
}

function backward_kill_line() {
    kill_region(0, cursor_pos, -1);
}

function kill_word() {
    kill_region(cursor_pos, skip_word_forward(cursor_pos), 1);
}

function backward_kill_word() {
    kill_region(skip_word_backward(cursor_pos), cursor_pos, -1);
}

function yank() {
    insert(clip_board);
}

function control_c() {
    // if (last_fun === control_c) {
    //     writeToStdout("\n");
    //     _exit(0);
    // } else {
    //     writeToStdout("\n(Press Ctrl-C again to quit)\n");
    writeToStdout(colors.red + " ^C" + colors.none + "\n");
    reset();
    readline_print_prompt();
    // }
}

function reset() {
    cmd = "";
    cursor_pos = 0;
}

/**
 * 
 * @param {string} line 
 * @param {number} end 
 * @returns 
 */
function get_context_word(line, end) {
    var pos = end;
    while (pos > 0 && is_word(line[pos - 1]))
        pos--;
    return line.slice(pos, end);
}
/**
 * 
 * @param {string} line 
 * @param {number} pos 
 * @returns {any}
 */
function get_context_object(line, pos) {
    if (pos <= 0)
        return globalThis;
    var c = line[pos - 1];
    if (pos === 1 && (c === '\\' || c === '.'))
        return directives;
    if ("'\"`@#)]}\\".indexOf(c) >= 0)
        return void 0;
    if (c === ".") {
        pos--;
        switch (c = line[pos - 1]) {
            case '\'':
            case '\"':
            case '`':
                return "a";
            case ']':
                return [];  // incorrect for a[b].<TAB>
            case '/':
                return / /;
            default:
                if (is_word(c)) {
                    var base = get_context_word(line, pos);
                    var base_pos = pos - base.length;
                    if (base === 'true' || base === 'false')
                        return true;
                    if (base === 'null')
                        return null;
                    if (base === 'this')
                        return globalThis;
                    if (!isNaN(+base))  // number literal, incorrect for 1.<TAB>
                        return 0;
                    var obj = get_context_object(line, base_pos);
                    if (obj === null || obj === void 0)
                        return obj;
                    if (typeof obj[base] !== 'undefined')
                        return obj[base];
                    // Check if `base` is a set of regexp flags
                    // TODO(chqrlie): this is incorrect for a/i<TAB>...
                    // Should use colorizer to determine the token type
                    if (base_pos >= 3 && line[base_pos - 1] === '/' && base.match(/^[dgimsuvy]+$/))
                        return RegExp(line.substring(base_pos), 'i');
                    // base is a local identifier, complete as generic object
                }
                break;
        }
        return {};
    }
    return globalThis;
}

/**
 * 
 * @param {string} line 
 * @param {number} pos 
 * @returns 
 */
function get_completions(line, pos) {
    var s, obj, ctx_obj, r, i, j, paren;

    s = get_context_word(line, pos);
    ctx_obj = get_context_object(line, pos - s.length);
    r = [];
    /* enumerate properties from object and its prototype chain,
       add non-numeric regular properties with s as e prefix
     */
    for (i = 0, obj = ctx_obj; i < 10 && obj !== null && obj !== void 0; i++) {
        var props = Object.getOwnPropertyNames(obj);
        /* add non-numeric regular properties */
        for (j = 0; j < props.length; j++) {
            var prop = props[j];
            if (typeof prop == "string" && "" + (+prop) != prop && prop.startsWith(s))
                r.push(prop);
        }
        obj = Object.getPrototypeOf(obj);
    }
    if (r.length > 1) {
        /* sort list with internal names last and remove duplicates */
        function symcmp(/** @type {string} */ a, /** @type {string} */ b) {
            if (a[0] != b[0]) {
                if (a[0] == '_')
                    return 1;
                if (b[0] == '_')
                    return -1;
            }
            if (a < b)
                return -1;
            if (a > b)
                return +1;
            return 0;
        }
        r.sort(symcmp);
        for (i = j = 1; i < r.length; i++) {
            if (r[i] != r[i - 1])
                r[j++] = r[i];
        }
        r.length = j;
    }
    /* 'tab' = list of completions, 'pos' = cursor position inside
       the completions */
    return { tab: r, pos: s.length, ctx: ctx_obj };
}

function completion() {
    var tab, res, s, i, j, len, t, max_width, col, n_cols, row, n_rows;
    res = get_completions(cmd, cursor_pos);
    tab = res.tab;
    if (tab.length === 0)
        return;
    s = tab[0];
    len = s.length;
    /* add the chars which are identical in all the completions */
    for (i = 1; i < tab.length; i++) {
        t = tab[i];
        for (j = 0; j < len; j++) {
            if (t[j] !== s[j]) {
                len = j;
                break;
            }
        }
    }
    for (i = res.pos; i < len; i++) {
        insert(s[i]);
    }
    if (last_fun === completion && tab.length == 1) {
        /* append parentheses to function names */
        var m = res.ctx[tab[0]];
        if (typeof m == "function") {
            insert('(');
            if (m.length == 0)
                insert(')');
        } else if (typeof m == "object") {
            insert('.');
        }
    }
    /* show the possible completions */
    if (last_fun === completion && tab.length >= 2) {
        max_width = 0;
        for (i = 0; i < tab.length; i++)
            max_width = Math.max(max_width, tab[i].length);
        max_width += 2;
        n_cols = Math.max(1, Math.floor((term_width + 1) / max_width));
        n_rows = Math.ceil(tab.length / n_cols);
        writeToStdout("\n");
        /* display the sorted list column-wise */
        for (row = 0; row < n_rows; row++) {
            for (col = 0; col < n_cols; col++) {
                i = col * n_rows + row;
                if (i >= tab.length)
                    break;
                s = tab[i];
                if (col != n_cols - 1)
                    s = s.padEnd(max_width);
                writeToStdout(s);
            }
            writeToStdout("\n");
        }
        /* show a new prompt */
        readline_print_prompt();
    }
}

/** @type {Record<string, Function>} */ var commands = {        /* command table */
    "\x01": beginning_of_line,      /* ^A - bol */
    "\x02": backward_char,          /* ^B - backward-char */
    "\x03": control_c,              /* ^C - abort */
    "\x04": control_d,              /* ^D - delete-char or exit */
    "\x05": end_of_line,            /* ^E - eol */
    "\x06": forward_char,           /* ^F - forward-char */
    "\x07": abort,                  /* ^G - bell */
    "\x08": backward_delete_char,   /* ^H - backspace */
    "\x09": completion,             /* ^I - history-search-backward */
    "\x0a": accept_line,            /* ^J - newline */
    "\x0b": kill_line,              /* ^K - delete to end of line */
    "\x0c": clear_screen,           /* ^L - clear screen */
    "\x0d": accept_line,            /* ^M - enter */
    "\x0e": next_history,           /* ^N - down */
    "\x10": previous_history,       /* ^P - up */
    "\x11": quoted_insert,          /* ^Q - quoted-insert */
    "\x12": alert,                  /* ^R - reverse-search */
    "\x13": alert,                  /* ^S - search */
    "\x14": transpose_chars,        /* ^T - transpose */
    "\x17": backward_kill_word,     /* ^W - backward_kill_word */
    "\x18": reset,                  /* ^X - cancel */
    "\x19": yank,                   /* ^Y - yank */
    "\x1bOA": previous_history,       /* ^[OA - up */
    "\x1bOB": next_history,           /* ^[OB - down */
    "\x1bOC": forward_char,           /* ^[OC - right */
    "\x1bOD": backward_char,          /* ^[OD - left */
    "\x1bOF": forward_word,           /* ^[OF - ctrl-right */
    "\x1bOH": backward_word,          /* ^[OH - ctrl-left */
    "\x1b[1;5C": forward_word,          /* ^[[1;5C - ctrl-right */
    "\x1b[1;5D": backward_word,         /* ^[[1;5D - ctrl-left */
    "\x1b[1~": beginning_of_line,      /* ^[[1~ - bol */
    "\x1b[3~": delete_char,            /* ^[[3~ - delete */
    "\x1b[4~": end_of_line,            /* ^[[4~ - eol */
    "\x1b[5~": history_search_backward,/* ^[[5~ - page up */
    "\x1b[6~": history_search_forward, /* ^[[5~ - page down */
    "\x1b[A": previous_history,       /* ^[[A - up */
    "\x1b[B": next_history,           /* ^[[B - down */
    "\x1b[C": forward_char,           /* ^[[C - right */
    "\x1b[D": backward_char,          /* ^[[D - left */
    "\x1b[F": end_of_line,            /* ^[[F - end */
    "\x1b[H": beginning_of_line,      /* ^[[H - home */
    "\x1b\x7f": backward_kill_word,     /* M-C-? - backward_kill_word */
    "\x1bb": backward_word,          /* M-b - backward_word */
    "\x1bd": kill_word,              /* M-d - kill_word */
    "\x1bf": forward_word,           /* M-f - backward_word */
    "\x1bk": backward_kill_line,     /* M-k - backward_kill_line */
    "\x1bl": downcase_word,          /* M-l - downcase_word */
    "\x1bt": transpose_words,        /* M-t - transpose_words */
    "\x1bu": upcase_word,            /* M-u - upcase_word */
    "\x7f": backward_delete_char,   /* ^? - delete */
};

/**
 * 
 * @param {string} str 
 * @param {number} count 
 * @returns 
 */
function dupstr(str, count) {
    var res = "";
    while (count-- > 0)
        res += str;
    return res;
}

/** @type {string} */ var readline_keys;
/** @type {number} */ var readline_state;
/** @type {Function} */ var readline_cb;

function readline_print_prompt() {
    writeToStdout(prompt);
    term_cursor_x = ucs_length(prompt) % term_width;
    last_cmd = "";
    last_cursor_pos = 0;
}

/**
 * 
 * @param {string} defstr 
 * @param {Function} cb 
 */
function readline_start(defstr, cb) {
    cmd = defstr || "";
    cursor_pos = cmd.length;
    history_index = history.length;
    readline_cb = cb;

    prompt = pstate;

    if (mexpr) {
        prompt += dupstr(" ", plen - prompt.length);
        prompt += ps2;
    } else {
        if (show_time) {
            var t = eval_time / 1000;
            prompt += t.toFixed(6) + " ";
        }
        plen = prompt.length;
        prompt += ps1;
    }
    readline_print_prompt();
    update();
    readline_state = 0;
}

/**
 * 
 * @param {number} c1 
 */
function handle_char(c1) {
    var c;
    c = String.fromCodePoint(c1);
    switch (readline_state) {
        case 0:
            if (c == '\x1b') {  /* '^[' - ESC */
                readline_keys = c;
                readline_state = 1;
            } else {
                handle_key(c);
            }
            break;
        case 1: /* '^[ */
            readline_keys += c;
            if (c == '[') {
                readline_state = 2;
            } else if (c == 'O') {
                readline_state = 3;
            } else {
                handle_key(readline_keys);
                readline_state = 0;
            }
            break;
        case 2: /* '^[[' - CSI */
            readline_keys += c;
            if (!(c == ';' || (c >= '0' && c <= '9'))) {
                handle_key(readline_keys);
                readline_state = 0;
            }
            break;
        case 3: /* '^[O' - ESC2 */
            readline_keys += c;
            handle_key(readline_keys);
            readline_state = 0;
            break;
    }
}

/**
 * 
 * @param {string} keys 
 * @returns 
 */
function handle_key(keys) {
    var fun;

    if (quote_flag) {
        if (ucs_length(keys) === 1)
            insert(keys);
        quote_flag = false;
    } else if (fun = commands[keys]) {
        this_fun = fun;
        switch (fun(keys)) {
            case -1:
                readline_cb(cmd);
                return;
            case -2:
                readline_cb(null);
                return;
            case -3:
                /* uninstall a Ctrl-C signal handler */
                self.removeSignal(sigint_handler);
                /* uninstall the stdin read handler */
                // os.setReadHandler(term_fd, null);
                save_history();
                return;
        }
        last_fun = this_fun;
    } else if (ucs_length(keys) === 1 && keys >= ' ') {
        insert(keys);
        last_fun = insert;
    } else {
        alert(); /* beep! */
    }

    cursor_pos = (cursor_pos < 0) ? 0 :
        (cursor_pos > cmd.length) ? cmd.length : cursor_pos;
    update();
}

/**
 * 
 * @param {number} a 
 * @param {number} radix 
 * @returns 
 */
function number_to_string(a, radix) {
    var s;
    if (!isFinite(a)) {
        /* NaN, Infinite */
        return a.toString();
    } else {
        if (a == 0) {
            if (1 / a < 0)
                s = "-0";
            else
                s = "0";
        } else {
            if (radix == 16 && a === Math.floor(a)) {
                var s;
                if (a < 0) {
                    a = -a;
                    s = "-";
                } else {
                    s = "";
                }
                s += "0x" + a.toString(16);
            } else {
                s = a.toString();
            }
        }
        return s;
    }
}

/**
 * 
 * @param {number} a 
 * @param {number} radix 
 * @returns 
 */
function bigint_to_string(a, radix) {
    var s;
    if (radix == 16) {
        var s;
        if (a < 0) {
            a = -a;
            s = "-";
        } else {
            s = "";
        }
        s += "0x" + a.toString(16);
    } else {
        s = a.toString();
    }
    return s + "n";
}

var util = {};
/**
 * 
 * @param {any} val 
 * @param {boolean | Object} show_hidden 
 * @param {number} max_depth 
 * @param {boolean} use_colors 
 * @returns 
 */
util.inspect = function (val, show_hidden, max_depth = 1, use_colors = true) {
    /** @type {Record<string, any>} */ var options = {};
    if (typeof show_hidden === 'object' && show_hidden !== null) {
        options = show_hidden;
        show_hidden = options.showHidden;
        max_depth = options.depth;
        use_colors = options.colors;
    }
    /**
     * 
     * @template T
     * @param {any} opt 
     * @param {T} def 
     * @returns {T | number}
     */
    function set(opt, def) {
        return (typeof opt === 'undefined') ? def : (opt === null) ? Infinity : opt;
    }
    if (typeof show_hidden !== 'boolean')
        show_hidden = false;
    max_depth = set(max_depth, 2);
    // @ts-ignore
    use_colors = set(use_colors, true);
    var breakLength = set(options.breakLength, Math.min(term_width, 80));
    var maxArrayLength = set(options.maxArrayLength, 100);
    var maxObjectLength = set(options.maxObjectLength, maxArrayLength + 10);
    var maxStringLength = set(options.maxStringLength, 78);
    var refs = [{}];    /* list of circular references */
    /** @type {string[]} */ var stack = [];     /* stack of pending objects */
    /** @type {string[]} */ var tokens = [];    /* list of generated tokens */
    /** @type {string[]} */ var output = [];    /* list of output fragments */
    var last_style = 'none';

    /**
     * 
     * @param {string} s 
     * @returns 
     */
    function quote_str(s) {
        if (s.includes("'"))
            return JSON.stringify(s);
        s = JSON.stringify(s).slice(1, -1).replaceAll('\\"', '"');
        return `'${s}'`;
    }
    /**
     * 
     * @param {string} s 
     */
    function push_token(s) {
        tokens.push("" + s);
    }
    /**
     * 
     * @param {string} s 
     */
    function append_token(s) {
        tokens[tokens.length - 1] += s;
    }
    /**
     * 
     * @param {any} o 
     */
    function class_tag(o) {
        // get the class id of an object
        // works for boxed objects, Math, JSON, globalThis...
        return Object.prototype.toString.call(o).slice(8, -1);
    }

    /**
     * 
     * @param {any} a 
     * @param {number} level 
     * @returns 
     */
    function print_rec(a, level) {
        var n, n0, i, k, keys, key, type, isarray, noindex, nokeys, brace, sep;

        switch (type = typeof (a)) {
            case "undefined":
            case "boolean":
                push_token(a);
                break;
            case "number":
                push_token(number_to_string(a, hex_mode ? 16 : 10));
                break;
            case "bigint":
                push_token(bigint_to_string(a, hex_mode ? 16 : 10));
                break;
            case "string":
                if (a.length > maxStringLength)
                    a = a.substring(0, maxStringLength) + "...";
                push_token(quote_str(a));
                break;
            case "symbol":
                push_token(String(a));
                break;
            case "object":
            case "function":
                if (a === null) {
                    push_token(a);
                    break;
                }
                if ((n = refs.indexOf(a)) >= 0) {
                    push_token(`[Circular *${n}]`);
                    break;
                }
                if ((n = stack.indexOf(a)) >= 0) {
                    push_token(`[Circular *${refs.length}]`);
                    refs.push(stack[n]);
                    break;
                }
                var obj_index = tokens.length;
                var tag = class_tag(a);
                stack.push(a);
                // XXX: should have Proxy instances
                if (a instanceof Date) {
                    push_token(`Date ${JSON.stringify(a.toDateString())}`);
                } else if (a instanceof RegExp) {
                    push_token(a.toString());
                } else if (a instanceof Boolean || a instanceof Number || a instanceof BigInt) {
                    push_token(`[${tag}: ${a}]`);
                } else if (a instanceof String) {
                    push_token(`[${tag}: ${quote_str(/** @type {string} */ (a))}]`);
                    len = a.length;
                    noindex = 1;
                } else if (Array.isArray(a)) {
                    push_token("[");
                    isarray = 1;
                } else if (tag.includes('Array') && a instanceof Uint8Array) {
                    push_token(`${tag}(${a.length}) [`);
                    isarray = 1;
                } else if (type === 'function') {
                    if (a.name)
                        push_token(`[Function: ${a.name}]`);
                    else
                        push_token(`[Function (anonymous)]`);
                } else {
                    var cons = (a.constructor && a.constructor.name) || 'Object';
                    if (tag !== 'Object') {
                        push_token(`${cons} [${tag}] {`);
                    } else if (a.__proto__ === null) {
                        push_token(`[${cons}: null prototype] {`);
                    } else if (cons !== 'Object') {
                        push_token(`${cons} {`);
                    } else {
                        push_token("{");
                    }
                    brace = "}";
                }
                keys = null;
                n = 0;
                n0 = 0;
                k = 0;
                if (isarray) {
                    brace = "]";
                    var len = a.length;
                    if (level > max_depth && len) {
                        push_token("...");
                        push_token(brace);
                        return;
                    }
                    for (i = 0; i < len; i++) {
                        k++;
                        if (i in a) {
                            print_rec(a[i], level + 1);
                        } else {
                            var start = i;
                            while (i + 1 < len && !((i + 1) in a))
                                i++;
                            if (i > start)
                                push_token(`<${i - start + 1} empty items>`);
                            else
                                push_token("<empty>");
                        }
                        if (k >= maxArrayLength && len - k > 5) {
                            push_token(`... ${len - k} more items`);
                            break;
                        }
                    }
                    noindex = 1;
                    /* avoid using Object.keys for large arrays */
                    if (i !== len && len > 1000)
                        nokeys = 1;
                }
                if (!nokeys) {
                    keys = show_hidden ? Object.getOwnPropertyNames(a) : Object.keys(a);
                    n = keys.length;
                }
                if (noindex && keys) {
                    /* skip all index properties */
                    for (; n0 < n; n0++) {
                        i = +keys[n0];
                        if (i !== (i >>> 0) || i >= len)
                            break;
                    }
                }
                if (n0 < n && keys) {
                    if (!brace) {
                        append_token(" {");
                        brace = "}";
                    }
                    if (level > max_depth && n0 < n) {
                        push_token("...");
                        push_token(brace);
                        return;
                    }
                    for (i = n0; i < n; i++) {
                        let key = keys[i];
                        var desc = Object.getOwnPropertyDescriptor(a, key);
                        if (!desc)
                            continue;
                        if (!desc.enumerable)
                            push_token(`[${String(key)}]`);
                        else
                            // @ts-ignore i can't understand the following line
                            if (+key === (key >>> 0) || key.match(/^[a-zA-Z_$][0-9a-zA-Z_$]*/))
                                push_token(key);
                            else
                                push_token(quote_str(key));
                        push_token(":");
                        if ('value' in desc) {
                            print_rec(desc.value, level + 1);
                        } else {
                            var fields = [];
                            if (desc.get)
                                fields.push("Getter");
                            if (desc.set)
                                fields.push("Setter");
                            push_token(`[${fields.join('/')}]`);
                        }
                        k++;
                        if (k > maxObjectLength && n - k > 5) {
                            push_token(`... ${n - k} more properties`);
                            break;
                        }
                    }
                }
                if (brace)
                    push_token(brace);
                stack.pop();
                if ((i = refs.indexOf(a)) > 0)
                    tokens[obj_index] = `<ref *${i}> ${tokens[obj_index]}`;
                break;
            default:
                push_token(String(a));
                break;
        }
    };
    /**
     * 
     * @param {string} s 
     * @param {string} style 
     */
    function output_str(s, style = 'none') {
        if (use_colors) {
            if (last_style !== style) {
                output.push(colors.none);
                last_style = style;
            }
            if (style) {
                var color = colors[styles[style]];
                if (color)
                    output.push(color);
            }
        }
        output.push(s);
    }
    /**
     * 
     * @param {string} s 
     */
    function output_propname(s) {
        if (s[0] >= '0' && s[0] <= '9')
            output_str(s, 'number');
        else
            output_str(s, 'propname');
        output_str(": ");
    }
    /**
     * 
     * @param {string} s 
     * @returns 
     */
    function output_pretty(s) {
        if (!use_colors) {
            output_str(s);
            return;
        }
        while (s.length > 0) {
            var style = 'none';
            var chunk = s;
            var len = 0;
            var m = null;
            switch (s[0]) {
                case '"':
                    style = 'string';
                    m = s.match(/^"([^\\"]|\\.)*"/);
                    break;
                case '\'':
                    style = 'string';
                    m = s.match(/^'([^\\']|\\.)*'/);
                    break;
                case '/':
                    style = 'regexp';
                    break;
                case '<':
                    m = s.match(/^\<[^\>]+\>/);
                    if (m)
                        style = 'annotation';
                    break;
                case '[':
                    m = s.match(/^\[[^\]]+\]/);
                    if (m) {
                        style = 'annotation';
                        break;
                    }
                /* fall thru */
                case ']':
                case '}':
                case ',':
                case ' ':
                    style = 'other';
                    len = 1;
                    break;
                case '.':
                    style = 'annotation';
                    break;
                case '0': case '1': case '2': case '3': case '4':
                case '5': case '6': case '7': case '8': case '9':
                    style = 'number';
                    m = s.match(/^[0-9a-z_]+[.]?[0-9a-z_]*[eEpP]?[+-]?[0-9]*/);
                    break;
                case '-':
                    len = 1;
                    break;
                default:
                    if (is_block(s))
                        len = s.length - 1;
                    if (s.startsWith('Date'))
                        style = 'date';
                    else if (s.startsWith('Symbol'))
                        style = 'symbol';
                    else if (s === 'Infinity' || s === 'NaN')
                        style = 'keyword';
                    else if (s === 'true' || s === 'false')
                        style = 'boolean';
                    else if (s === 'null')
                        style = 'null';
                    else if (s === 'undefined')
                        style = 'undefined';
                    break;
            }
            if (m)
                len = m[0].length;
            if (len > 0)
                chunk = s.slice(0, len);
            output_str(chunk, style);
            s = s.slice(chunk.length);
        }
    }
    /**
     * 
     * @param {string} s 
     * @returns 
     */
    function is_block(s) {
        var c = s[s.length - 1];
        return c === '[' || c === '{';
    }
    /**
     * 
     * @param {number} i 
     * @returns 
     */
    function block_width(i) {
        var w = tokens[i].length;
        if (tokens[i + 1] === ":") {
            i += 2;
            w += 2 + tokens[i].length;
        }
        var width = w;
        if (is_block(tokens[i])) {
            var seplen = 1;
            while (++i < tokens.length) {
                width += seplen;
                var s = tokens[i];
                if (s === ']' || s === '}')
                    break;
                [i, w] = block_width(i);
                width += w;
                seplen = 2;
            }
        }
        return [i, width];
    }
    /**
     * 
     * @param {number} i 
     * @param {number} last 
     */
    function output_single(i, last) {
        var sep = "";
        while (i <= last) {
            var s = tokens[i++];
            if (s === ']' || s === '}') {
                if (sep.length > 1)
                    output_str(" ");
            } else {
                output_str(sep);
                if (tokens[i] === ":") {
                    output_propname(s);
                    i++;
                    s = tokens[i++];
                }
            }
            output_pretty(s);
            sep = is_block(s) ? " " : ", ";
        }
    }
    /**
     * 
     * @param {string} s 
     * @param {number} count 
     */
    function output_spaces(s, count) {
        if (count > 0)
            s += " ".repeat(count);
        output_str(s);
    }
    /**
     * 
     * @param {number} indent 
     * @param {number} from 
     * @returns 
     */
    function output_indent(indent, from) {
        var avail_width = breakLength - indent - 2;
        var [last, width] = block_width(from);
        if (width <= avail_width) {
            output_single(from, last);
            return [last, width];
        }
        if (tokens[from + 1] === ":") {
            output_propname(tokens[from]);
            from += 2;
        }
        output_pretty(tokens[from]);
        if (!is_block(tokens[from])) {
            return [from, width];
        }
        indent += 2;
        avail_width -= 2;
        var sep = "";
        var first = from + 1;
        var i, w;
        if (tokens[from].endsWith('[')) {
            /* array: try multiple columns for indexed values */
            var k = 0, col, cols;
            var tab = [];
            for (i = first; i < last; i++) {
                if (tokens[i][0] === '.' || tokens[i + 1] === ':')
                    break;
                [i, w] = block_width(i);
                tab[k++] = w;
            }
            /**
             * @type {Array<number>}
             */
            var colwidth = [];
            for (cols = Math.min(avail_width / 3, tab.length, 16); cols > 1; cols--) {
                colwidth = [];
                col = 0;
                for (k = 0; k < tab.length; k++) {
                    colwidth[col] = Math.max(colwidth[col] || 0, tab[k] + 2);
                    col = (col + 1) % cols;
                }
                w = 0;
                for (col = 0; col < cols; col++) {
                    w += colwidth[col];
                }
                if (w <= avail_width)
                    break;
            }
            if (cols > 1) {
                w = 0;
                col = cols - 1;
                for (i = first; i < last; i++) {
                    if (tokens[i][0] === '.' || tokens[i + 1] === ':')
                        break;
                    w += sep.length;
                    output_str(sep);
                    sep = ",";
                    if (col === cols - 1) {
                        output_spaces("\n", indent);
                        col = 0;
                    } else {
                        output_spaces("", colwidth[col++] - w);
                    }
                    [i, w] = output_indent(indent, i);
                }
                first = i;
            }
        }
        for (i = first; i < last; i++) {
            output_str(sep);
            sep = ",";
            output_spaces("\n", indent);
            [i, w] = output_indent(indent, i);
        }
        output_spaces("\n", indent -= 2);
        output_pretty(tokens[last]);
        return [last, breakLength];
    }
    print_rec(val, 0);
    output_indent(0, 0);
    output_str("");
    return output.join("");
};

/**
 * 
 * @param {string} val 
 */
function print(val) {
    writeToStdout(util.inspect(val, { depth: show_depth, colors: show_colors, showHidden: show_hidden }));
    writeToStdout("\n");
}

/* return true if the string was a directive */
/**
 * 
 * @param {string} a 
 * @returns 
 */
function handle_directive(a) {
    if (a === "?") {
        help();
        return true;
    }
    if (a[0] !== '\\' && a[0] !== '.')
        return false;
    var pos = 1;
    while (pos < a.length && a[pos] !== ' ') {
        pos++;
    }
    var cmd = a.substring(1, pos);
    var partial = 0;
    var fun;
    for (var p in directives) {
        if (p.startsWith(cmd)) {
            fun = directives[p];
            partial++;
            if (p === cmd) {
                partial = 0;
                break;
            }
        }
    }
    if (fun && partial < 2) {
        fun(a.substring(pos).trim());
    } else {
        writeToStdout(`Unknown directive: ${cmd}\n`);
    }
    return true;
}

function help() {
    var sel = (/** @type {boolean} */ n) => n ? "*" : " ";
    writeToStdout(".help    print this help\n" +
        ".x      " + sel(hex_mode) + "hexadecimal number display\n" +
        ".dec    " + sel(!hex_mode) + "decimal number display\n" +
        ".time   " + sel(show_time) + "toggle timing display\n" +
        ".strict " + sel(use_strict) + "toggle strict mode evaluation\n" +
        `.depth   set object depth (current: ${show_depth})\n` +
        ".hidden " + sel(show_hidden) + "toggle hidden properties display\n" +
        ".color  " + sel(show_colors) + "toggle colored output\n" +
        ".dark   " + sel(styles == themes.dark) + "select dark color theme\n" +
        ".light  " + sel(styles == themes.light) + "select light color theme\n" +
        ".clear   clear the terminal\n" +
        ".load    load source code from a file\n" +
        ".import  async import a module and save it globally\n" +
        ".quit    exit\n");
}

/**
 * 
 * @param {string} s 
 */
function load(s) {
    if (s.lastIndexOf(".") <= s.lastIndexOf("/"))
        s += ".js";
    try {
        const data = read(s, true);
        content.eval(data, {
            main: true,
            url: `file://${s}`,
            name: s
        });
    } catch (e) {
        writeToStdout(`${e}\n`);
    }
}

/**
 * 
 * @param {number} e 
 * @returns {never}
 */
function _exit(e) {
    save_history();
    exit(e);
}

/**
 * @template T
 * @param {string} s 
 * @param {T} def 
 * @returns {boolean | T}
 */
function to_bool(s, def) {
    return s ? "1 true yes Yes".includes(s) : def;
}

var directives = Object.setPrototypeOf(/** @type {Record<string, (p: string) => any>} */({
    "help": help,
    "load": load,
    "x": (s) => { hex_mode = to_bool(s, true); },
    "dec": (s) => { hex_mode = !to_bool(s, true); },
    "time": (s) => { show_time = to_bool(s, !show_time); },
    "strict": (s) => { use_strict = to_bool(s, !use_strict); },
    "depth": (s) => { show_depth = +s || 2; },
    "hidden": (s) => { show_hidden = to_bool(s, !show_hidden); },
    "color": (s) => { show_colors = to_bool(s, !show_colors); },
    "dark": () => { styles = themes.dark; },
    "light": () => { styles = themes.light; },
    "clear": () => { writeToStdout("\x1b[H\x1b[J") },
    "quit": () => { _exit(0); },
    "import": (s) => { 
        content.eval(`globalThis['${s.split('/').at(-1)}'] = await import('${s}');\n`, {})
            .catch((/** @type {any} */ e) => { print_eval_error(e); })
    }
}), null);

function cmd_readline_start() {
    readline_start(dupstr("    ", level), readline_handle_cmd);
}

/**
 * 
 * @param {string} expr 
 */
function readline_handle_cmd(expr) {
    if (!handle_cmd(expr)) {
        cmd_readline_start();
    }
}

/* return true if async termination */
/**
 * 
 * @param {string} expr 
 * @returns 
 */
function handle_cmd(expr) {
    if (!expr)
        return false;
    if (mexpr) {
        expr = mexpr + '\n' + expr;
    } else {
        if (handle_directive(expr))
            return false;
    }
    var colorstate = colorize_js(expr);
    pstate = colorstate[0];
    level = colorstate[1];
    if (pstate) {
        mexpr = expr;
        return false;
    }
    mexpr = "";
    eval_and_print(expr);

    return true;
}

/**
 * 
 * @param {string} expr 
 */
function eval_and_print(expr) {
    var result;

    if (use_strict)
        expr = '"use strict"; void 0;' + expr;
    eval_start_time = Date.now();
    /* eval as a script */
    try{
        const res = content.eval(expr);
        (res instanceof Promise) 
            ? res.then(print_eval_result, print_eval_error)
            : print_eval_result(res);
    }catch(e){
        print_eval_error(e);
    }
}

/**
 * 
 * @param {any} result 
 */
function print_eval_result(result) {
    eval_time = Date.now() - eval_start_time;
    print(result);
    /* set the last result */
    // @ts-ignore
    globalThis._ = result;

    handle_cmd_end();
}

/**
 * 
 * @param {any} error 
 */
function print_eval_error(error) {
    if (show_colors) {
        writeToStdout(colors[styles.error]);
    }
    if (error instanceof Error) {
        writeToStdout(String(error));
        writeToStdout('\n');
        if (error.stack) {
            // remove stack in current file
            let eval_and_print = false;
            var stack = error.stack.split('\n').filter(s => {
                if(s.includes('at eval_and_print')){
                    eval_and_print = true;
                    return false;
                }
                return !eval_and_print;
            });
            stack.forEach(s => {
                writeToStdout(s + '\n');
            });
        }
    } else {
        writeToStdout("Throw: ");
        writeToStdout(error);
        writeToStdout('\n');
    }

    if (show_colors) {
        writeToStdout(colors.none);
    }

    handle_cmd_end();
}

function handle_cmd_end() {
    level = 0;

    /* run the garbage collector after each command */
    // std.gc();

    cmd_readline_start();
}

/**
 * 
 * @param {string} str 
 * @returns {[string, number, Array<string>]}
 */
function colorize_js(str) {
    var /** @type {number} */ i, /** @type {string} */ c, /** @type {number} */ start, n = str.length;
    var /** @type {string | null} */ style, state = "", level = 0;
    var can_regex = 1;
    var /** @type {Array<string>} */ r = [];

    function push_state(/** @type {string} */ c) { state += c; }
    function last_state(/** @type {string} */ c) { return state.substring(state.length - 1); }
    function pop_state(/** @type {string} */ c) {
        var c = last_state();
        state = state.substring(0, state.length - 1);
        return c;
    }

    function parse_block_comment() {
        style = 'comment';
        push_state('/');
        for (i++; i < n - 1; i++) {
            if (str[i] == '*' && str[i + 1] == '/') {
                i += 2;
                pop_state('/');
                break;
            }
        }
    }

    function parse_line_comment() {
        style = 'comment';
        for (i++; i < n; i++) {
            if (str[i] == '\n') {
                break;
            }
        }
    }

    function parse_string(/** @type {string} */ delim) {
        style = 'string';
        push_state(delim);
        while (i < n) {
            c = str[i++];
            if (c == '\n') {
                style = 'error';
                continue;
            }
            if (c == '\\') {
                if (i >= n)
                    break;
                i++;
            } else
                if (c == delim) {
                    pop_state();
                    break;
                }
        }
    }

    function parse_regex() {
        style = 'regexp';
        push_state('/');
        while (i < n) {
            c = str[i++];
            if (c == '\n') {
                style = 'error';
                continue;
            }
            if (c == '\\') {
                if (i < n) {
                    i++;
                }
                continue;
            }
            if (last_state() == '[') {
                if (c == ']') {
                    pop_state()
                }
                // ECMA 5: ignore '/' inside char classes
                continue;
            }
            if (c == '[') {
                push_state('[');
                if (str[i] == '[' || str[i] == ']')
                    i++;
                continue;
            }
            if (c == '/') {
                pop_state();
                while (i < n && is_word(str[i]))
                    i++;
                break;
            }
        }
    }

    function parse_number() {
        style = 'number';
        // TODO(chqrlie) parse partial number syntax
        // TODO(chqrlie) special case bignum
        while (i < n && (is_word(str[i]) || (str[i] == '.' && (i == n - 1 || str[i + 1] != '.')))) {
            i++;
        }
    }

    var js_keywords = "|" +
        "break|case|catch|continue|debugger|default|delete|do|" +
        "else|finally|for|function|if|in|instanceof|new|" +
        "return|switch|this|throw|try|typeof|while|with|" +
        "class|const|enum|import|export|extends|super|" +
        "implements|interface|let|package|private|protected|" +
        "public|static|yield|" +
        "undefined|null|true|false|Infinity|NaN|" +
        "eval|arguments|" +
        "await|";

    var js_no_regex = "|this|super|undefined|null|true|false|Infinity|NaN|arguments|";
    var js_types = "|void|var|";

    function parse_identifier() {
        can_regex = 1;

        while (i < n && is_word(str[i]))
            i++;

        var s = str.substring(start, i);
        var w = '|' + s + '|';

        if (js_keywords.indexOf(w) >= 0) {
            style = 'keyword';
            if (s === 'true' || s === 'false')
                style = 'boolean';
            else if (s === 'true' || s === 'false')
                style = 'boolean';
            else if (s === 'null')
                style = 'null';
            else if (s === 'undefined')
                style = 'undefined';
            if (js_no_regex.indexOf(w) >= 0)
                can_regex = 0;
            return;
        }

        var i1 = i;
        while (i1 < n && str[i1] == ' ')
            i1++;

        if (i1 < n && str[i1] == '(') {
            style = 'function';
            return;
        }

        if (js_types.indexOf(w) >= 0) {
            style = 'type';
            return;
        }

        style = 'identifier';
        can_regex = 0;
    }

    /**
     * 
     * @param {number} from 
     * @param {number} to 
     */
    function set_style(from, to) {
        while (r.length < from)
            r.push('default');
        while (r.length < to)
            style && r.push(style);
    }

    for (i = 0; i < n;) {
        style = null;
        start = i;
        switch (c = str[i++]) {
            case ' ':
            case '\t':
            case '\r':
            case '\n':
                continue;
            case '+':
            case '-':
                if (i < n && str[i] == c) {
                    i++;
                    continue;
                }
                can_regex = 1;
                continue;
            case '/':
                if (i < n && str[i] == '*') { // block comment
                    parse_block_comment();
                    break;
                }
                if (i < n && str[i] == '/') { // line comment
                    parse_line_comment();
                    break;
                }
                if (can_regex) {
                    parse_regex();
                    can_regex = 0;
                    break;
                }
                can_regex = 1;
                continue;
            case '\'':
            case '\"':
            case '`':
                parse_string(c);
                can_regex = 0;
                break;
            case '(':
            case '[':
            case '{':
                can_regex = 1;
                level++;
                push_state(c);
                continue;
            case ')':
            case ']':
            case '}':
                can_regex = 0;
                if (level > 0 && is_balanced(last_state(), c)) {
                    level--;
                    pop_state();
                    continue;
                }
                style = 'error';
                break;
            default:
                if (is_digit(c)) {
                    parse_number();
                    can_regex = 0;
                    break;
                }
                if (is_word(c)) {
                    parse_identifier();
                    break;
                }
                can_regex = 1;
                continue;
        }
        if (style)
            set_style(start, i);
    }
    set_style(n, n);
    return [state, level, r];
}

/**
 * 
 * @param {string} s 
 * @returns 
 */
function config_file(s) {
    return (self.env.HOME || self.env.USERPROFILE || ".") + "/" + s;
}
function save_history() {
    var s = history.slice(-1000).join('\n').trim();
    if (s) {
        try {
            write(config_file(".qjs_history"), s + '\n');
        } catch (e) {
        }
    }
}
function load_history() {
    var a = read(config_file(".qjs_history"), true);
    if (a) {
        history = a.trim().split('\n');
        history_index = history.length;
    }
}
function load_config() {
    var m, s = self.env.COLORFGBG;
    if (s && (m = s.match(/(\d+);(\d+)/))) {
        if (+m[2] !== 0) { // light background
            styles = themes.light;
        }
    }
    s = self.env.NO_COLOR; // https://no-color.org/
    if (s && +s[0] !== 0) {
        show_colors = false;
    }
}

load_config();
load_history();
termInit();
cmd_readline_start();

while(true){
    const data = await stdin.read();
    data && data.forEach(c => handle_byte(c));
}