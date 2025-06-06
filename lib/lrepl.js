import { exit, self, signals, stdin, stdout } from "process";
import { Sandbox } from "vm";

/**
 * 增强型REPL环境，支持历史记录、语法高亮和高级编辑功能
 */
class EnhancedREPL {
    /**
     * @param {string} data 
     */
    static writeStdout(data){
        return stdout.write(encodeStr(data));
    }

    constructor() {
        /** @type {Sandbox} 代码执行沙箱 */
        this.ctx = new Sandbox();

        /** @type {string[]} 输入缓冲区 */
        this.buffer = [];

        /** @type {number} 当前光标位置 */
        this.cursorPos = 0;

        /** @type {string[]} 命令历史记录 */
        this.history = [];

        /** @type {number} 当前历史记录索引 */
        this.historyIndex = 0;

        /** @type {boolean} 是否处于多行模式 */
        this.multiLineMode = false;

        /** @type {boolean} 是否有待处理输入 */
        this.pendingInput = false;

        /** @type {Object.<string, string>} ANSI颜色代码 */
        this.colors = {
            reset: "\x1b[0m",
            prompt: "\x1b[32m",  // 绿色提示符
            error: "\x1b[31m",   // 红色错误
            result: "\x1b[36m",  // 青色结果
            comment: "\x1b[90m"  // 灰色注释
        };
    }

    /**
     * 启动REPL环境
     * @async
     */
    async start() {
        stdin.ttyRaw(true);
        this.setupExitHandler();

        while (true) {
            try {
                await this.readEvalPrintLoop();
            } catch (err) {
                if(err instanceof Error)
                    this.printError(err);
                else
                    console.error(err);
            }
        }
    }

    /**
     * 读取-求值-打印循环的核心逻辑
     * @async
     * @returns {Promise<void>}
     */
    async readEvalPrintLoop() {
        const input = await this.readLine();
        if (input.trim() === '') return;

        if (input.startsWith('.')) {
            return this.handleCommand(input);
        }

        try {
            const result = await this.ctx.eval(input);
            this.printResult(result);
            this.addHistory(input);
        } catch (err) {
            if(err instanceof Error)
                this.printError(err);
            else
                console.error(err);
        }
    }

    /**
     * 读取一行输入
     * @async
     * @returns {Promise<string>}
     */
    async readLine() {
        this.buffer = [];
        this.cursorPos = 0;
        this.pendingInput = true;

        await this.redraw();

        while (this.pendingInput) {
            const char = await this.readChar();
            if (!char) continue;

            await this.processInput(char);
        }

        return this.buffer.join('');
    }

    /**
     * 处理输入字符
     * @async
     * @param {string} char - 输入的字符
     * @returns {Promise<void>}
     */
    async processInput(char) {
        // 处理回车/换行
        if (char === '\r' || char === '\n') {
            this.pendingInput = false;
            await EnhancedREPL.writeStdout('\n');
            return;
        }

        // 处理退格
        if (char === '\x7f' || char === '\x08') {
            if (this.cursorPos > 0) {
                this.buffer.splice(--this.cursorPos, 1);
            }
            await this.redraw();
            return;
        }

        // 处理ESC序列(方向键等)
        if (char === '\x1b') {
            await this.handleEscapeSequence();
            return;
        }

        // 普通字符输入
        this.buffer.splice(this.cursorPos++, 0, char);
        await this.redraw();
    }

    /**
     * 处理ESC序列(增强方向键支持)
     * @async
     * @returns {Promise<void>}
     */
    async handleEscapeSequence() {
        const seq = await stdin.read(2);
        if (!seq) return;

        // 处理标准方向键序列
        if (seq[0] === 0x5b) { // '['
            switch (seq[1]) {
                case 0x44: // 左箭头
                    this.cursorPos = Math.max(0, this.cursorPos - 1);
                    break;
                case 0x43: // 右箭头
                    this.cursorPos = Math.min(this.buffer.length, this.cursorPos + 1);
                    break;
                case 0x41: // 上箭头
                    this.navigateHistory(-1);
                    break;
                case 0x42: // 下箭头
                    this.navigateHistory(1);
                    break;
                case 0x48: // Home键
                    this.cursorPos = 0;
                    break;
                case 0x46: // End键
                    this.cursorPos = this.buffer.length;
                    break;
                case 0x31: // 可能的功能键开始(如Home/End的扩展序列)
                    await this.handleExtendedEscapeSequence();
                    return;
            }
        }

        await this.redraw();
    }

    /**
     * 处理扩展的ESC序列(如Home/End键的完整序列)
     * @async
     * @returns {Promise<void>}
     */
    async handleExtendedEscapeSequence() {
        const extSeq = await stdin.read(1);
        if (!extSeq) return;

        if (extSeq[0] === 0x7e) { // '~'
            const prevChar = await stdin.read(1);
            if (!prevChar) return;

            switch (prevChar[0]) {
                case 0x31: // Home键完整序列: [1~
                    this.cursorPos = 0;
                    break;
                case 0x34: // End键完整序列: [4~
                    this.cursorPos = this.buffer.length;
                    break;
            }
        }

        await this.redraw();
    }

    /**
     * 在历史记录中导航
     * @param {number} direction - 1: 下一个, -1: 上一个
     */
    navigateHistory(direction) {
        const newIndex = this.historyIndex + direction;

        if (newIndex >= 0 && newIndex < this.history.length) {
            this.historyIndex = newIndex;
            this.buffer = [...this.history[this.historyIndex]];
            this.cursorPos = this.buffer.length;
        } else if (direction > 0 && this.historyIndex === this.history.length - 1) {
            // 到达最新记录后清空缓冲区
            this.buffer = [];
            this.cursorPos = 0;
        }
    }

    /**
     * 重绘当前行
     * @async
     * @returns {Promise<void>}
     */
    async redraw() {
        await EnhancedREPL.writeStdout('\x1b[2K\x1b[0G');
        const prompt = this.multiLineMode ?
            `${this.colors.prompt}... ${this.colors.reset}` :
            `${this.colors.prompt}>> ${this.colors.reset}`;
        await EnhancedREPL.writeStdout(prompt);
        const inputText = this.buffer.join('');
        await EnhancedREPL.writeStdout(inputText);
        const visiblePromptLength = prompt.replace(/\x1b\[[0-9;]*m/g, '').length;
        const targetCursorPos = visiblePromptLength + this.cursorPos;
        await EnhancedREPL.writeStdout(`\x1b[${targetCursorPos + 1}G`);
    }

    /**
     * 打印执行结果
     * @param {*} result - 要打印的结果
     */
    printResult(result) {
        const formatted = typeof result === 'string' ?
            `"${result}"` : String(result);
        console.log(`${this.colors.result}=> ${formatted}${this.colors.reset}`);
    }

    /**
     * 打印错误信息
     * @param {Error} error - 错误对象
     */
    printError(error) {
        console.error(`${this.colors.error}Error: ${error.message}${this.colors.reset}`);
    }

    /**
     * 添加命令到历史记录
     * @param {string} input - 输入的命令
     */
    addHistory(input) {
        this.history.push(input);
        this.historyIndex = this.history.length;
    }

    /**
     * 处理REPL命令
     * @param {string} cmd - 输入的命令
     */
    handleCommand(cmd) {
        const cmds = cmd.split(/\s+/);
        const commands = /** @type {Record<string, (...args: string[]) => void>} */ ({
            '.exit': () => exit(0),
            '.clear': () => console.clear(),
            ".import": (module) => this.ctx.eval(`import * as m from '${module}'; globalThis['${module}'] = m;`, {}),
            '.help': () => {
                console.log('Available commands:');
                console.log('  .exit   - Exit the REPL');
                console.log('  .clear  - Clear the screen');
                console.log('  .help   - Show this help');
                console.log('  .import - Import a module to global objection')
            }
        });

        const handler = commands[cmds[0]];
        if (handler) return handler.apply(this, cmds.slice(1));

        console.log(`${this.colors.error}Unknown command: ${cmd[0]}${this.colors.reset}`);
        console.log(`Type ${this.colors.comment}.help${this.colors.reset} for available commands`);
    }

    /**
     * 设置退出处理程序
     */
    setupExitHandler() {
        self.signal(signals.SIGINT, async () => {
            if (this.pendingInput) {
                await EnhancedREPL.writeStdout('\x1b[0G');
                console.log('^C');
                this.pendingInput = false;
                await this.redraw();
            } else {
                console.log(' <exiting>');
                exit(0);
            }
        });
    }

    /**
     * 读取单个字符
     * @async
     * @returns {Promise<string|null>} 读取的字符或null
     */
    async readChar() {
        const buf = await stdin.read(1);
        return buf ? String.fromCharCode(buf[0]) : null;
    }
}

// 启动REPL
new EnhancedREPL().start().catch(err => {
    console.error('REPL fatal error:', err);
    exit(1);
});