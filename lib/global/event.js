/**
 * Event polyfill for LJS
 */

import { setEventNotifier } from "vm";

const original = Symbol('event:original');

/**
 * 事件对象
 * @template {string} T - 事件类型
 */
class Event {
    /** @type {T} */ #type;
    /** @type {boolean} */ #cancelable;
    /** @type {boolean} */ #defaultPrevented = false;
    /** @type {any} */ #detail;

    /**
     * 创建新事件
     * @param {T} type - 事件类型
     * @param {Object} [options] - 事件配置
     * @param {boolean} [options.cancelable=false] - 事件是否可取消
     * @param {any} [options.detail] - 事件详细信息
     */
    constructor(type, { cancelable = false, detail } = {}) {
        this.#type = type;
        this.#cancelable = cancelable;
        this.#detail = detail;
    }

    /** 获取事件类型 */
    get type() {
        return this.#type;
    }

    /** 检查事件是否可取消 */
    get cancelable() {
        return this.#cancelable;
    }

    /** 获取事件详细信息 */
    get detail() {
        return this.#detail;
    }

    /** 阻止事件的默认行为（如果可取消） */
    preventDefault() {
        if (this.#cancelable) {
            this.#defaultPrevented = true;
        }
    }

    /** 检查是否已阻止默认行为 */
    get defaultPrevented() {
        return this.#defaultPrevented;
    }
}

/**
 * 事件目标对象
 */
class EventTarget {
  /** @type {Map<string, Set<Function>>} */ #listeners = new Map();

    /**
     * 添加事件监听器
     * @param {string} type - 事件类型
     * @param {Function} listener - 监听函数
     * @param {Object} [options] - 选项
     * @param {boolean} [options.once=false] - 是否只触发一次
     */
    addEventListener(type, listener, { once = false } = {}) {
        if (typeof listener !== 'function') return;

        if (!this.#listeners.has(type)) {
            this.#listeners.set(type, new Set());
        }

        const wrapper = once
            ? (/** @type {Event<any>} */ event) => {
                listener(event);
                this.removeEventListener(type, wrapper);
            }
            : listener;

        // @ts-ignore
        wrapper[original] = listener;
        this.#listeners.get(type)?.add(wrapper);
    }

    /**
     * 移除事件监听器
     * @param {string} type - 事件类型
     * @param {Function} listener - 监听函数
     */
    removeEventListener(type, listener) {
        const listeners = this.#listeners.get(type);
        if (!listeners) return;

        // 处理 once 包装器的情况
        for (const l of listeners) {
            // @ts-ignore
            if (l === listener || l[original] === listener) {
                listeners.delete(l);
                break;
            }
        }
    }

    /**
     * 触发事件
     * @param {Event<any>} event - 要触发的事件对象
     * @returns {boolean} 是否调用了 preventDefault()
     */
    dispatchEvent(event) {
        const listeners = this.#listeners.get(event.type);
        if (listeners) {
            // 使用 Array.from 避免在迭代过程中修改 Set
            Array.from(listeners).forEach(listener => {
                listener.call(this, event);
            });
        }
        return event.defaultPrevented;
    }
}


export function initEvent() {
    // @ts-ignore
    globalThis.Event = Event;
    // @ts-ignore
    globalThis.EventTarget = EventTarget;
    // @ts-ignore
    const gev = globalThis.event = new EventTarget();

    setEventNotifier(function(name, data){
        gev.dispatchEvent(new Event(name, { detail: data }));
    });
}