import { exit, self, signals, stdin, stdout } from "process"
import { Sandbox } from "vm";

const ctx = new Sandbox();
let line = /** @type {number[]} */ ([]);
let codeBlock = "";
let cursorPos = 0; // 新增：跟踪光标位置

// 光标控制函数
const moveCursor = {
    left: () => stdout.write(encodeStr('\x1b[D')),  // 左移1格
    right: () => stdout.write(encodeStr('\x1b[C')), // 右移1格
    toStart: () => stdout.write(encodeStr('\x1b[G')), // 行首
    clearLine: () => stdout.write(encodeStr('\x1b[2K')), // 清除整行
};

/**
 * 
 * @param {string} prompt 
 */
async function refreshLine(prompt = ' >> ') {
    await moveCursor.toStart();
    await moveCursor.clearLine();
    await stdout.write(encodeStr(prompt));
    await stdout.write(new Uint8Array(line));
    // 光标位置修正逻辑保持不变
}


/**
 * 
 * @param {string} code 
 * @returns 
 */
function checkBracketsBalance(code) {
    const stack = [];
    let inString = false;
    let stringChar = '';
    const bracketPairs = /** @type {Record<string, string>} */ ({ '{': '}', '[': ']', '(': ')' });

    for (let i = 0; i < code.length; i++) {
        const char = code[i];

        // 处理字符串内的字符
        if (inString) {
            if (char === '\\') { // 跳过转义字符
                i++;
            } else if (char === stringChar) {
                inString = false;
            }
            continue;
        }

        // 检测字符串开始
        if (char === '"' || char === "'" || char === '`') {
            inString = true;
            stringChar = char;
            continue;
        }

        // 处理括号
        if (bracketPairs[char]) {
            stack.push(char);
        } else if (Object.values(bracketPairs).includes(char)) {
            if (stack.length === 0 || bracketPairs[/** @type {string} */ (stack.pop())] !== char) {
                return false;
            }
        }
    }

    return stack.length === 0 && !inString;
}

const interruptHandler = () => {
    if (codeBlock.length === 0) {
        console.log(" <exit>");
        exit(0);
    }

    console.log(" <interrupt: press ctrl+c again to exit>");
    codeBlock = "";
    line = [];
    stdout.write(encodeStr(" >> "));
};
self.signal(signals.SIGINT, interruptHandler);

(async function () {
    stdin.ttyRaw(true);

    loop: while (true) {
        const prompt = codeBlock.length > 0 ? "... " : " >> ";
        
        while (true) {
            await refreshLine(prompt);
            
            const dat = await stdin.read(1);
            if (!dat) continue;

            // 控制字符处理
            if (dat[0] < 32 || dat[0] === 127) {
                switch (dat[0]) {
                    case 13: case 10: // Enter
                        await stdout.write(encodeStr("\n"));
                        const str = decodeStr(new Uint8Array(line));
                        codeBlock += str;

                        if(codeBlock.trim().startsWith('.')){
                            switch(codeBlock.trim()){
                                case '.exit':
                                    exit(0);
                                case '.clear':
                                    console.clear();
                                    break;
                                case '.help':
                                    console.log('   .exit: exit the repl');
                                    console.log('   .clear: clear the console');
                                    break;
                                default:
                                    console.log('Unknown command', codeBlock.trim());
                            }
                            codeBlock = "";
                            line = [];
                            cursorPos = 0;
                            continue loop;
                        }
                        
                        if (!checkBracketsBalance(codeBlock)) {
                            line = [];
                            cursorPos = 0;
                            continue loop;
                        }
                        
                        try {
                            const result = await ctx.eval(codeBlock);
                            console.log("=>", result);
                        } catch (e) {
                            console.error(e);
                        } finally {
                            codeBlock = "";
                            line = [];
                            cursorPos = 0;
                        }
                        continue loop;

                    case 8: case 127: // Backspace/Delete
                        if (cursorPos > 0) {
                            line.splice(cursorPos - 1, 1);
                            cursorPos--;
                        }
                        break;

                    case 27: { // ESC (处理方向键)
                        const escSeq = await stdin.read(3); // 完整读取3字节序列
                        if (escSeq && escSeq[0] === 0x5b) { // 0x5b = [
                        switch (escSeq[1]) {
                                case 68: // 左箭头
                                    if (cursorPos > 0) cursorPos--;
                                    await stdout.write(encodeStr('\x1b[D')); // 光标左移1格
                                    break;
                                case 67: // 右箭头
                                    if (cursorPos < line.length) cursorPos++;
                                    await stdout.write(encodeStr('\x1b[C')); // 光标右移1格
                                    break;
                                case 72: // Home
                                    cursorPos = 0;
                                    await stdout.write(encodeStr('\x1b[G')); // 行首
                                    break;
                                case 70: // End
                                    cursorPos = line.length;
                                    await stdout.write(encodeStr('\x1b[K')); // 行尾
                                    break;
                            }
                        }
                        await refreshLine(prompt);
                        break;
                    }

                    case 9: // TAB
                        line.splice(cursorPos, 0, 9); // 插入制表符
                        cursorPos++;
                        break;

                    default: continue loop;
                }
                continue;
            }

            // 普通字符输入
            line.splice(cursorPos, 0, dat[0]);
            cursorPos++;
        }
    }
})();