/**
 * LightJS 贪吃蛇 终端程序开发示例
 * 
 * @copyright iz
 * @license MIT
 */

import { stdin, stdout } from "process";

/**
 * 
 * @param {U8Pipe} stdin 
 * @param {U8Pipe} stdout 
 */
async function snakeGame(stdin, stdout) {
    // 终端控制序列
    const ESC = '\x1b';
    const CLEAR = `${ESC}[2J${ESC}[H`;
    const HIDE_CURSOR = `${ESC}[?25l`;
    const SHOW_CURSOR = `${ESC}[?25h`;
    const ALT_SCREEN = `${ESC}[?1049h`;
    const EXIT_ALT_SCREEN = `${ESC}[?1049l`;

    // 确保TTY环境
    if (!(stdin instanceof IOPipe) || !(stdout instanceof IOPipe)) {
        throw new Error('需要TTY终端环境');
    }

    // 设置终端原始模式
    // 此时允许读取单个键盘输入而不是只有回车后才有数据
    stdin.ttyRaw(true);
    stdout.ttyRaw(true);

    // 游戏状态（优化速度系统）
    const state = {
        width: 20,
        height: 10,
        snake: [{ x: 5, y: 5 }],
        food: { x: 10, y: 5 },
        direction: 'right',
        nextDirection: 'right',
        score: 0,
        baseSpeed: 350,       // 基础速度（毫秒/格）
        vertSpeedRatio: 1.8,  // 纵向速度系数
        running: true,
        lastFrameTime: 0,
        inputQueue: /** @type {Array<string>} */ ([])
    };

    // 设置终端尺寸
    // 这个设置不一定会生效，因为许多终端都没有提供这个设置选项
    stdout.ttySize = [state.width + 10, state.height + 5];

    // 绘制游戏界面（优化渲染）
    async function draw() {
        let output = CLEAR + `Score: ${state.score}\n`;
        output += '+' + '-'.repeat(state.width) + '+\n';

        // 预生成行模板提升性能
        const emptyRow = '|' + ' '.repeat(state.width) + '|\n';
        for (let y = 0; y < state.height; y++) {
            const row = [...emptyRow];
            // 标记蛇身
            state.snake.forEach(seg => {
                if (seg.y === y) row[seg.x + 1] = 'O';
            });
            // 标记食物
            if (state.food.y === y) row[state.food.x + 1] = '@';
            output += row.join('');
        }

        output += '+' + '-'.repeat(state.width) + '+\n';
        output += 'WASD/方向键移动，Q退出';
        
        await stdout.write(encodeStr(output));
    }

    // 生成新食物（优化空位检测）
    function spawnFood() {
        const grid = Array(state.height).fill(0).map(() => Array(state.width).fill(true));
        state.snake.forEach(({x, y}) => grid[y][x] = false);
        
        const available = /** @type {Array<{x: number, y: number}>} */ ([]);
        grid.forEach((row, y) => row.forEach((empty, x) => {
            if (empty) available.push({x, y});
        }));
        
        if (available.length) {
            state.food = available[Math.random() * available.length | 0];
        }
    }

    // 输入处理（事件驱动改造）
    async function handleInput() {
        while (state.running) {
            const data = await stdin.read();
            if (!data) continue;
            
            const input = decodeStr(data).toLowerCase();
            // 缓冲输入指令
            if (input === 'q') {
                state.running = false;
            } else {
                state.inputQueue.push(input);
            }
        }
    }

    // 处理缓冲输入（新增函数）
    function processInput() {
        while (state.inputQueue.length) {
            const input = state.inputQueue.shift();
            const current = state.direction;
            
            // 方向优先级处理
            if (input === 'w' && current !== 'down') state.nextDirection = 'up';
            else if (input === 's' && current !== 'up') state.nextDirection = 'down';
            else if (input === 'a' && current !== 'right') state.nextDirection = 'left';
            else if (input === 'd' && current !== 'left') state.nextDirection = 'right';
        }
    }

    // 游戏更新（优化时序控制）
    function update() {
        // 处理缓冲输入
        processInput();
        
        // 计算方向速度
        const isVertical = ['up', 'down'].includes(state.direction);
        const frameInterval = isVertical ? 
            state.baseSpeed * state.vertSpeedRatio : 
            state.baseSpeed;
        
        // 按帧率更新
        const now = performance.now();
        if (now - state.lastFrameTime < frameInterval) return false;
        state.lastFrameTime = now;

        // 应用方向变更
        state.direction = state.nextDirection;

        // 移动蛇头
        const head = { ...state.snake[0] };
        switch (state.direction) {
            case 'up': head.y--; break;
            case 'down': head.y++; break;
            case 'left': head.x--; break;
            case 'right': head.x++; break;
        }

        // 碰撞检测
        if (head.x < 0 || head.x >= state.width || 
            head.y < 0 || head.y >= state.height ||
            state.snake.some(s => s.x === head.x && s.y === head.y)) {
            state.running = false;
            return false;
        }

        // 更新蛇身
        state.snake.unshift(head);
        if (head.x === state.food.x && head.y === state.food.y) {
            state.score++;
            if (state.score % 3 === 0) {
                state.baseSpeed = Math.max(100, state.baseSpeed - 20);
            }
            spawnFood();
        } else {
            state.snake.pop();
        }

        return true;
    }

    // 游戏主循环（微秒级精度）
    async function gameLoop() {
        const frameDuration = 64; // ~15fps
        while (state.running) {
            const updated = update();
            if (updated) await draw();
            await delay(frameDuration);
        }
    }

    // 启动游戏
    try {
        await stdout.write(encodeStr(ALT_SCREEN + HIDE_CURSOR));
        spawnFood();
        
        await Promise.all([
            gameLoop().catch(console.error),
            handleInput().catch(console.error)
        ]);
        
        await stdout.write(encodeStr(`${CLEAR}Game Over! Score: ${state.score}`));
    } finally {
        stdin.ttyRaw(false);
        await stdout.write(encodeStr(EXIT_ALT_SCREEN + SHOW_CURSOR));
    }
}
// 主循环
// 自0.1.1后使用import.meta.main判断是否是主线程，此处不判断是否为Worker
if(import.meta.main) while(true) {
    await snakeGame(stdin, stdout);
    await stdout.write(encodeStr('按任意键再来一局...'));
    await stdin.read();
    await stdout.write(encodeStr("\x1b[2J\x1b[H"));
}
