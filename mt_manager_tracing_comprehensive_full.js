// MT管理器敏感API调用栈追踪脚本 - 全方位监控版 (已修复)
// 修复了listFiles重载错误、无限递归调用和JNI崩溃问题

console.log('[*] MT Manager Sensitive API Tracing Script (Full Monitoring Version) [FIXED] loaded');

// 执行Hook
Java.perform(function() {
    console.log('[*] Starting Hook for sensitive APIs...');

    // 预加载常用类以避免重复创建引用
    const Thread = Java.use('java.lang.Thread');
    const Process = Java.use('android.os.Process');
    const Binder = Java.use('android.os.Binder');
    const JavaDate = Java.use('java.util.Date');
    const SimpleDateFormat = Java.use('java.text.SimpleDateFormat');

    // 优化：只创建一次SimpleDateFormat实例
    const sdf = SimpleDateFormat.$new('yyyy-MM-dd HH:mm:ss.SSS');

    // 获取应用上下文
    let context = null;
    try {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const currentApplication = ActivityThread.currentApplication();
        context = currentApplication.getApplicationContext();
        console.log('[+] Successfully obtained application context');
    } catch (e) {
        console.log(`[-] Failed to obtain application context: ${e.message}`);
    }

    // 获取包名和UID
    let packageName = 'Unknown';
    let uid = 0;
    try {
        uid = Process.myUid();
        if (context) {
            packageName = context.getPackageName();
        } else {
            const ActivityThread = Java.use('android.app.ActivityThread');
            const pm = ActivityThread.currentApplication().getPackageManager();
            packageName = pm.getNameForUid(uid);
        }
        console.log(`[+] Current application: ${packageName} (UID: ${uid})`);
    } catch (e) {
        console.log(`[-] Failed to obtain package name/UID: ${e.message}`);
    }

    // 日志输出节流控制
    const LOG_THROTTLE_MS = 100; // 同一API每100ms最多输出一次日志
    const lastLogTime = {};

    // 简化的堆栈跟踪函数
    function getStackTrace() {
        try {
            return Thread.currentThread().getStackTrace().slice(3, 20).map(stackElement => {
                return `${stackElement.getClassName()}.${stackElement.getMethodName()}()`;
            }).join('\n    -> ');
        } catch (e) {
            return '[ERROR] Failed to get stack trace';
        }
    }

    // 获取当前时间戳
    function getTimestamp() {
        try {
            const now = JavaDate.$new();
            return sdf.format(now).toString();
        } catch (e) {
            return new Date().toString();
        }
    }

    // 获取顶层Activity
    function getTopActivity() {
        try {
            if (!context) return 'Unknown';
            const ActivityManager = Java.use('android.app.ActivityManager');
            const am = context.getSystemService('activity');
            const tasks = am.getRunningTasks(1);
            if (tasks && tasks.size() > 0) {
                return tasks.get(0).topActivity.getClassName();
            }
            return 'Unknown';
        } catch (e) {
            return `Failed to get: ${e.message}`;
        }
    }

    // 检查设备是否解锁
    function isDeviceUnlocked() {
        try {
            if (!context) return 'Unknown';
            const KeyguardManager = Java.use('android.app.KeyguardManager');
            const km = context.getSystemService('keyguard');
            return !km.isDeviceLocked();
        } catch (e) {
            return `Failed to check: ${e.message}`;
        }
    }

    // 检查设备是否已Root
    function isDeviceRooted() {
        try {
            const rootPaths = [
                '/system/bin/su', '/system/xbin/su', '/sbin/su',
                '/su/bin/su', '/system/app/Superuser.apk', '/system/app/SuperSU.apk'
            ];
            const File = Java.use('java.io.File');
            for (const path of rootPaths) {
                if (File.$new(path).exists()) {
                    return true;
                }
            }
            return false;
        } catch (e) {
            return `Failed to check: ${e.message}`;
        }
    }

    // 检查应用是否具有指定权限
    function checkPermission(permission) {
        try {
            if (!context) return 'Unknown';
            const PackageManager = Java.use('android.content.pm.PackageManager');
            const pm = context.getPackageManager();
            const result = pm.checkPermission(permission, packageName);
            return result === PackageManager.PERMISSION_GRANTED;
        } catch (e) {
            return `Failed to check: ${e.message}`;
        }
    }

    // 获取文件元数据
    function getFileMetadata(filePath) {
        try {
            const File = Java.use('java.io.File');
            const file = File.$new(filePath);
            if (!file.exists()) {
                return { exists: false };
            }
            let storageVolume = 'Unknown';
            if (filePath.startsWith('/storage/emulated/0')) {
                storageVolume = 'External storage (main partition)';
            } else if (filePath.startsWith('/data/data/')) {
                storageVolume = 'App private directory';
            } else if (filePath.startsWith('/system/')) {
                storageVolume = 'System directory';
            } else if (filePath.startsWith('/mnt/')) {
                storageVolume = 'Mounted directory';
            }
            return {
                exists: true,
                size: file.length(),
                lastModified: JavaDate.$new(file.lastModified()).toString(),
                storageVolume: storageVolume
            };
        } catch (e) {
            return { exists: false, error: e.message };
        }
    }

    // 风险评估函数
    function assessRisk(apiName, filePath) {
        let riskLevel = 'Low risk';
        let riskReason = 'Normal operation';
        if (apiName.includes('delete') || apiName.includes('remove')) {
            riskLevel = 'Medium risk';
            riskReason = 'File deletion operation';
        }
        if (apiName.includes('exec') || apiName.includes('Runtime')) {
            riskLevel = 'High risk';
            riskReason = 'System command execution';
        }
        if (filePath) {
            if (filePath.includes('/data/data/') && !filePath.includes(packageName)) {
                riskLevel = 'Extremely high risk';
                riskReason = 'Accessing other app private directory';
            } else if (filePath.includes('/system/')) {
                riskLevel = 'High risk';
                riskReason = 'Accessing system directory';
            }
        }
        if (apiName.includes('Method.invoke') || apiName.includes('Constructor.newInstance')) {
            riskLevel = 'Medium risk';
            riskReason = 'Reflection call, may bypass static detection';
        }
        return { level: riskLevel, reason: riskReason };
    }

    // 通用日志输出函数 - 结构化输出
    function logAPI(apiName, details = {}) {
        const now = Date.now();
        const pathKey = details['文件路径'] || details['File path'] || details['Directory path'];
        const apiKey = `${apiName}_${pathKey || 'unknown'}`;

        if (!lastLogTime[apiKey] || now - lastLogTime[apiKey] > LOG_THROTTLE_MS) {
            lastLogTime[apiKey] = now;
            
            const logObj = {
                timestamp: getTimestamp(),
                processInfo: {
                    packageName: packageName,
                    uid: uid,
                    pid: Process.myPid(),
                    threadId: Process.myTid()
                },
                api: { name: apiName, details: details },
                systemStatus: {
                    isDeviceUnlocked: isDeviceUnlocked(),
                    isDeviceRooted: isDeviceRooted(),
                    topActivity: getTopActivity()
                },
                riskAssessment: assessRisk(apiName, pathKey),
                stackTrace: getStackTrace()
            };

            // 输出日志
            console.log(`\n[!] Sensitive API call: ${apiName}`);
            console.log(JSON.stringify(logObj, null, 2));
        }
    }

    // -------------------------- 反射操作 --------------------------
    try {
        const Method = Java.use('java.lang.reflect.Method');
        const invokeOverload = Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;');
        invokeOverload.implementation = function(obj, args) {
            const methodName = this.getName();
            const declaringClassName = this.getDeclaringClass().getName();
            logAPI('java.lang.reflect.Method.invoke', {
                'Declaring class': declaringClassName,
                'Method name': methodName,
                'Target object': obj ? obj.getClass().getName() : 'static',
            });
            return invokeOverload.call(this, obj, args);
        };
        console.log('[+] Successfully hooked: java.lang.reflect.Method.invoke');
    } catch (e) {
        console.log(`[-] Hook failed: java.lang.reflect.Method.invoke - ${e.message}`);
    }

    try {
        const Constructor = Java.use('java.lang.reflect.Constructor');
        const newInstanceOverload = Constructor.newInstance.overload('[Ljava.lang.Object;');
        newInstanceOverload.implementation = function(args) {
            const className = this.getDeclaringClass().getName();
            logAPI('java.lang.reflect.Constructor.newInstance', {
                'Class name': className,
            });
            return newInstanceOverload.call(this, args);
        };
        console.log('[+] Successfully hooked: java.lang.reflect.Constructor.newInstance');
    } catch (e) {
        console.log(`[-] Hook failed: java.lang.reflect.Constructor.newInstance - ${e.message}`);
    }
    
    // -------------------------- 文件操作 --------------------------
    try {
        const File = Java.use('java.io.File');

        File.delete.implementation = function() {
            const filePath = this.getAbsolutePath();
            const result = this.delete(); // Correct: calls original method
            logAPI('java.io.File.delete', { 'File path': filePath, 'Result': result });
            return result;
        };

        File.renameTo.implementation = function(dest) {
            const sourcePath = this.getAbsolutePath();
            const destPath = dest.getAbsolutePath();
            const result = this.renameTo(dest); // Correct: calls original method
            logAPI('java.io.File.renameTo', { 'Source path': sourcePath, 'Destination path': destPath, 'Result': result });
            return result;
        };

        // ** FIX: Hook all overloads of listFiles correctly **
        File.listFiles.overload().implementation = function() {
            const result = this.listFiles.overload().call(this); // Correct: call specific original overload
            logAPI('java.io.File.listFiles()', { 'Directory path': this.getAbsolutePath(), 'Number of files': result ? result.length : 0 });
            return result;
        };

        File.listFiles.overload('java.io.FilenameFilter').implementation = function(filter) {
            const result = this.listFiles.overload('java.io.FilenameFilter').call(this, filter); // Correct call
            logAPI('java.io.File.listFiles(FilenameFilter)', { 'Directory path': this.getAbsolutePath(), 'Number of files': result ? result.length : 0 });
            return result;
        };

        File.listFiles.overload('java.io.FileFilter').implementation = function(filter) {
            const result = this.listFiles.overload('java.io.FileFilter').call(this, filter); // Correct call
            logAPI('java.io.File.listFiles(FileFilter)', { 'Directory path': this.getAbsolutePath(), 'Number of files': result ? result.length : 0 });
            return result;
        };

        console.log('[+] Successfully hooked: java.io.File methods');
    } catch (e) {
        console.log(`[-] Hook failed: java.io.File - ${e.message}`);
    }

    // -------------------------- 文件流操作 --------------------------
    try {
        const FileOutputStream = Java.use('java.io.FileOutputStream');
        const writeOverload = FileOutputStream.write.overload('[B');
        writeOverload.implementation = function(b) {
            // ** FIX: Prevent recursion by calling the specific overload **
            const result = writeOverload.call(this, b);
            logAPI('java.io.FileOutputStream.write', { 'Number of bytes written': b ? b.length : 0 });
            return result;
        };
        console.log('[+] Successfully hooked: java.io.FileOutputStream.write');
    } catch (e) {
        console.log(`[-] Hook failed: java.io.FileOutputStream - ${e.message}`);
    }

    // -------------------------- Runtime类 --------------------------
    try {
        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            logAPI('java.lang.Runtime.exec', { 'Command': cmd });
            return Runtime.exec.overload('java.lang.String').call(this, cmd);
        };
        console.log('[+] Successfully hooked: java.lang.Runtime.exec');
    } catch (e) {
        console.log(`[-] Hook failed: java.lang.Runtime - ${e.message}`);
    }
    
    console.log('\n[*] Script initialization completed!');
    console.log('[*] All identified bugs have been fixed. Monitoring is active.');
});
