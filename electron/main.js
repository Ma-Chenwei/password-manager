const {
    app,
    BrowserWindow,
    dialog
} = require("electron");

const {
    spawn
} = require("child_process");

const http = require("http");
const path = require("path");
const fs = require("fs");

const HOST = "127.0.0.1";
const PORT = 1107;

let goProcess = null;
let mainWindow = null;
let shuttingDown = false;


function getGoExecutablePath() {
    if (app.isPackaged) {
        return path.join(
            process.resourcesPath,
            "app.asar.unpacked",
            "backend.exe"
        );
    }

    return path.join(
        __dirname,
        "backend.exe"
    );
}

/*
 * 检查 Go EXE 是否存在
 */
function checkGoExecutable() {
    const executable = getGoExecutablePath();

    return fs.existsSync(executable);
}

/*
 * 启动 Go
 */
function startGoServer() {
    if (goProcess) {
        return;
    }

    const executable = getGoExecutablePath();

    if (!fs.existsSync(executable)) {
        throw new Error(
            "找不到 Go 后端程序：\n\n" +
            executable +
            "\n\n请先在 go 目录编译：\n" +
            "go build -o password-manager.exe ."
        );
    }

    console.log("Starting Go backend:");
    console.log(executable);

    goProcess = spawn(
        executable,
        [],
        {
            cwd: path.dirname(executable),
            windowsHide: true,
            stdio: [
                "ignore",
                "pipe",
                "pipe"
            ]
        }
    );

    goProcess.stdout.on(
        "data",
        (data) => {
            console.log(
                "[Go]",
                data.toString().trim()
            );
        }
    );

    goProcess.stderr.on(
        "data",
        (data) => {
            console.error(
                "[Go]",
                data.toString().trim()
            );
        }
    );

    goProcess.on(
        "error",
        (error) => {
            console.error(
                "Go process error:",
                error
            );

            goProcess = null;
        }
    );

    goProcess.on(
        "exit",
        (code, signal) => {
            console.log(
                `Go backend exited. code=${code}, signal=${signal}`
            );

            goProcess = null;

            if (
                !shuttingDown &&
                mainWindow &&
                !mainWindow.isDestroyed()
            ) {
                dialog.showErrorBox(
                    "密码管理器后端已停止",
                    "Go 加密核心已经停止运行。\n\n" +
                    "请重新启动密码管理器。"
                );
            }
        }
    );
}

/*
 * 检查 127.0.0.1:1107
 */
function checkGoServer() {
    return new Promise((resolve) => {
        const request = http.get(
            {
                hostname: HOST,
                port: PORT,
                path: "/api/status",
                timeout: 500
            },
            (response) => {
                response.resume();

                resolve(
                    response.statusCode >= 200 &&
                    response.statusCode < 500
                );
            }
        );

        request.on(
            "error",
            () => {
                resolve(false);
            }
        );

        request.on(
            "timeout",
            () => {
                request.destroy();
                resolve(false);
            }
        );
    });
}

/*
 * 等待 Go 服务启动
 */
async function waitForGoServer(
    timeout = 3000
) {
    const start = Date.now();

    while (
        Date.now() - start <
        timeout
    ) {
        if (
            await checkGoServer()
        ) {
            return true;
        }

        await new Promise(
            (resolve) =>
                setTimeout(resolve, 100)
        );
    }

    return false;
}

/*
 * 创建 Electron 窗口
 *
 * 注意：
 * 这里没有 renderer。
 *
 * Electron 本身只是把
 *
 * http://127.0.0.1:1107
 *
 * 放进 BrowserWindow。
 */
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1100,
        height: 760,

        minWidth: 900,
        minHeight: 600,

        show: false,

        title: "Password Manager",

        webPreferences: {
            preload: path.join(
                __dirname,
                "preload.js"
            ),

            contextIsolation: true,
            nodeIntegration: false,

            sandbox: true
        }
    });

    /*
     * Go 自己提供完整 HTML。
     *
     * Electron 不负责 UI。
     */
    mainWindow.loadURL(
        `http://${HOST}:${PORT}`,
        {
            extraHeaders:
                "Cache-Control: no-cache\r\n"
        }
    );

    mainWindow.once(
        "ready-to-show",
        () => {
            if (
                mainWindow &&
                !mainWindow.isDestroyed()
            ) {
                mainWindow.show();
            }
        }
    );

    mainWindow.webContents.on(
        "did-fail-load",
        (
            event,
            errorCode,
            errorDescription
        ) => {
            console.error(
                "Page load failed:",
                errorCode,
                errorDescription
            );
        }
    );

    mainWindow.on(
        "closed",
        () => {
            mainWindow = null;
        }
    );
}

/*
 * 关闭 Go
 */
function stopGoServer() {
    if (!goProcess) {
        return;
    }

    try {
        if (
            process.platform ===
            "win32"
        ) {
            /*
             * Windows 下使用 taskkill
             * 确保 Go 进程结束。
             */
            const { exec } =
                require("child_process");

            exec(
                `taskkill /pid ${goProcess.pid} /T /F`,
                (error) => {
                    if (error) {
                        console.error(
                            "Failed to stop Go:",
                            error
                        );
                    }
                }
            );
        } else {
            goProcess.kill("SIGTERM");
        }
    } catch (error) {
        console.error(
            "Error stopping Go:",
            error
        );
    }

    goProcess = null;
}

/*
 * Electron 启动
 */
app.whenReady().then(
    async () => {
        console.log(
            "Password Manager starting..."
        );

        /*
         * 如果 Go 已经自己启动了，
         * Electron 不重复启动。
         */
        const alreadyRunning =
            await checkGoServer();

        if (!alreadyRunning) {
            try {
                startGoServer();
            } catch (error) {
                dialog.showErrorBox(
                    "启动失败",
                    error.message
                );

                app.quit();
                return;
            }
        } else {
            console.log(
                "Go backend is already running."
            );
        }

        /*
         * 等待最多 3 秒
         */
        const ready =
            await waitForGoServer(3000);

        if (!ready) {
            dialog.showErrorBox(
                "加密核心启动异常",
                "无法连接到 127.0.0.1:1107。\n\n" +
                "请检查 Go 后端是否正常运行，" +
                "或者关闭占用 1107 端口的程序后重试。"
            );

            stopGoServer();
            app.quit();
            return;
        }

        createWindow();
    }
);

/*
 * macOS：
 * 点击 Dock 图标重新打开窗口。
 */
app.on(
    "activate",
    () => {
        if (
            BrowserWindow.getAllWindows()
                .length === 0
        ) {
            createWindow();
        }
    }
);

/*
 * 所有窗口关闭
 */
app.on(
    "window-all-closed",
    () => {
        if (
            process.platform !==
            "darwin"
        ) {
            app.quit();
        }
    }
);

/*
 * Electron 即将退出
 */
app.on(
    "before-quit",
    () => {
        shuttingDown = true;

        stopGoServer();
    }
);
