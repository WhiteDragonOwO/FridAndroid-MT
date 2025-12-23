// MT管理器敏感API调用堆栈追踪脚本 - 优化版

console.log('[*] MT管理器敏感API追踪脚本已加载');

// 定义要追踪的敏感API列表
const sensitiveAPIs = [
    // 文件系统操作
    {
        className: 'java.io.File',
        methods: ['delete', 'renameTo', 'createNewFile', 'mkdir', 'mkdirs', 'deleteOnExit']
    },
    {
        className: 'java.io.FileOutputStream',
        methods: ['write', 'close', 'flush']
    },
    {
        className: 'java.io.FileInputStream',
        methods: ['read', 'close']
    },
    {
        className: 'java.io.RandomAccessFile',
        methods: ['write', 'read', 'close', 'seek']
    },
    {
        className: 'java.nio.file.Files',
        methods: ['delete', 'copy', 'move', 'write', 'readAllBytes', 'readAllLines']
    },
    {
        className: 'java.io.FileWriter',
        methods: ['write', 'close', 'flush']
    },
    {
        className: 'java.io.FileReader',
        methods: ['read', 'close']
    },
    {
        className: 'java.util.zip.ZipFile',
        methods: ['open', 'close', 'entries']
    },
    {
        className: 'java.util.zip.ZipOutputStream',
        methods: ['putNextEntry', 'closeEntry', 'close']
    },
    // 网络操作
    {
        className: 'java.net.HttpURLConnection',
        methods: ['connect', 'getInputStream', 'getOutputStream', 'disconnect']
    },
    {
        className: 'okhttp3.OkHttpClient',
        methods: ['newCall']
    },
    {
        className: 'okhttp3.Call',
        methods: ['execute', 'enqueue']
    },
    {
        className: 'okhttp3.Response',
        methods: ['body', 'close']
    },
    {
        className: 'android.net.http.HttpResponseCache',
        methods: ['flush', 'close']
    },
    // 权限相关
    {
        className: 'android.content.pm.PackageManager',
        methods: ['checkPermission', 'requestPermissions', 'getInstalledPackages']
    },
    {
        className: 'android.app.Activity',
        methods: ['requestPermissions', 'onRequestPermissionsResult']
    },
    {
        className: 'android.content.Context',
        methods: ['checkPermission', 'checkSelfPermission']
    },
    // 进程管理
    {
        className: 'android.os.Process',
        methods: ['exec', 'start', 'killProcess']
    },
    {
        className: 'java.lang.Runtime',
        methods: ['exec', 'getRuntime']
    },
    {
        className: 'android.app.ApplicationPackageManager',
        methods: ['installPackage', 'deletePackage']
    },
    {
        className: 'android.content.pm.PackageInstaller',
        methods: ['sessionParams', 'newSession', 'openSession']
    },
    // 系统服务
    {
        className: 'android.content.Context',
        methods: ['getSystemService']
    },
    {
        className: 'android.os.ServiceManager',
        methods: ['getService']
    },
    // 反射相关
    {
        className: 'java.lang.Class',
        methods: ['forName', 'getMethod', 'getDeclaredMethod', 'getField', 'getDeclaredField']
    },
    {
        className: 'java.lang.reflect.Method',
        methods: ['invoke']
    },
    {
        className: 'java.lang.reflect.Field',
        methods: ['get', 'set']
    },
    // MT管理器特有的敏感操作 - 基于包名前缀
    {
        className: 'bin.mt.plus',
        methods: [],
        isPrefix: true
    }
];

// 为每个API创建Hook
function hookSensitiveAPIs() {
    console.log('[*] 开始Hook敏感API...');
    let totalHooks = 0;
    let successfulHooks = 0;
    let failedHooks = 0;
    
    sensitiveAPIs.forEach(api => {
        try {
            if (api.isPrefix) {
                // 处理前缀匹配的类名
                console.log(`[*] 开始Hook前缀为 ${api.className} 的所有类...`);
                const allClasses = Java.enumerateLoadedClassesSync();
                const matchingClasses = allClasses.filter(clsName => clsName.startsWith(api.className));
                console.log(`[+] 找到 ${matchingClasses.length} 个匹配的类`);
                
                matchingClasses.forEach(clsName => {
                    try {
                        const cls = Java.use(clsName);
                        const methods = Object.getOwnPropertyNames(cls.__proto__).filter(name => {
                            return typeof cls[name] === 'function' && !name.startsWith('$') && !name.startsWith('__');
                        });
                        
                        methods.forEach(method => {
                            try {
                                const overloads = cls[method].overloads;
                                if (overloads && overloads.length > 0) {
                                    overloads.forEach(overload => {
                                        overload.implementation = function() {
                                            console.log(`\n[!] 调用MT特有API: ${clsName}.${method}`);
                                            console.log(`    参数: ${JSON.stringify(arguments)}`);
                                            
                                            // 获取调用堆栈
                                            const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                                            console.log('[*] 调用堆栈:');
                                            for (let i = 3; i < stackTrace.length && i < 20; i++) {
                                                console.log(`    ${i-2}. ${stackTrace[i].toString()}`);
                                            }
                                            
                                            // 调用原始方法
                                            const result = this[method].apply(this, arguments);
                                            
                                            // 打印返回结果
                                            if (result !== undefined && result !== null) {
                                                console.log(`    返回值: ${result}`);
                                            }
                                            
                                            return result;
                                        };
                                    });
                                    successfulHooks++;
                                }
                                totalHooks++;
                            } catch (e) {
                                // 忽略无法Hook的方法
                                failedHooks++;
                            }
                        });
                    } catch (e) {
                        // 忽略无法Hook的类
                        failedHooks++;
                    }
                });
            } else {
                // 处理精确匹配的类名
                const cls = Java.use(api.className);
                
                api.methods.forEach(method => {
                    try {
                        const overloads = cls[method].overloads;
                        if (overloads && overloads.length > 0) {
                            overloads.forEach(overload => {
                                overload.implementation = function() {
                                    console.log(`\n[!] 调用敏感API: ${api.className}.${method}`);
                                    console.log(`    参数: ${JSON.stringify(arguments)}`);
                                    
                                    // 获取调用堆栈
                                    const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                                    console.log('[*] 调用堆栈:');
                                    for (let i = 3; i < stackTrace.length && i < 20; i++) {
                                        console.log(`    ${i-2}. ${stackTrace[i].toString()}`);
                                    }
                                    
                                    // 调用原始方法
                                    const result = this[method].apply(this, arguments);
                                    
                                    // 打印返回结果
                                    if (result !== undefined && result !== null) {
                                        console.log(`    返回值: ${result}`);
                                    }
                                    
                                    return result;
                                };
                            });
                            console.log(`[+] 成功Hook: ${api.className}.${method}`);
                            successfulHooks++;
                        } else {
                            console.log(`[-] Hook失败: ${api.className}.${method} - 没有找到重载方法`);
                            failedHooks++;
                        }
                        totalHooks++;
                    } catch (e) {
                        console.log(`[-] Hook失败: ${api.className}.${method} - ${e.message}`);
                        failedHooks++;
                        totalHooks++;
                    }
                });
            }
        } catch (e) {
            if (api.isPrefix) {
                console.log(`[-] 无法Hook前缀为 ${api.className} 的类 - ${e.message}`);
            } else {
                console.log(`[-] 无法找到类: ${api.className} - ${e.message}`);
            }
            failedHooks++;
            totalHooks++;
        }
    });
    
    console.log(`\n[*] 敏感API Hook完成!`);
    console.log(`[*] 总Hook数: ${totalHooks}`);
    console.log(`[*] 成功Hook数: ${successfulHooks}`);
    console.log(`[*] 失败Hook数: ${failedHooks}`);
    console.log(`[*] Hook成功率: ${Math.round((successfulHooks / totalHooks) * 100)}%`);
}

// 执行Hook
Java.perform(function() {
    hookSensitiveAPIs();
});
