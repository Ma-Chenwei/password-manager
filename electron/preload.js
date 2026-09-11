"use strict";

/*
 * Password Manager 不需要 Electron
 * 与网页之间的额外 API。
 *
 * 所有功能全部由：
 *
 * Electron
 *     ↓
 * BrowserWindow
 *     ↓
 * http://127.0.0.1:1107
 *     ↓
 * Go
 *
 * 完成。
 */

window.addEventListener(
    "DOMContentLoaded",
    () => {
        console.log(
            "Password Manager Electron shell ready."
        );
    }
);