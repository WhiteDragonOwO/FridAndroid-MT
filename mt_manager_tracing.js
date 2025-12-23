// MT管理器敏感API调用堆栈追踪脚本

// 定义要追踪的敏感API列表
const sensitiveAPIs = [
    // 文件系统操作
    {
        className: 'java.io.File',
        methods: ['delete', 'renameTo', 'createNewFile', 'mkdir', 'mkdirs']
    },
    {
        className: 'java.io.FileOutputStream',
        methods: ['write', 'close']
    },
    {
        className: 'java.io.FileInputStream',
        methods: ['read', 'close']
    },
    {
        className: 'java.io.RandomAccessFile',
        methods: ['write', 'read', 'close']
    },
    {
        className: 'java.nio.file.Files',
        methods: ['delete', 'copy', 'move', 'write', 'readAllBytes']
    },
    // 网络操作
    {
        className: 'java.net.HttpURLConnection',
        methods: ['connect', 'getInputStream', 'getOutputStream']
    },
    {
        className: 'okhttp3.OkHttpClient',
        methods: ['newCall']
    },
    {
        className: 'okhttp3.Call',
        methods: ['execute', 'enqueue']
    },
    // 权限相关
    {
        className: 'android.content.pm.PackageManager',
        methods: ['checkPermission', 'requestPermissions']
    },
    {
        className: 'android.app.Activity',
        methods: ['requestPermissions']
    },
    // 进程管理
    {
        className: 'android.os.Process',
        methods: ['exec', 'start']
    },
    {
        className: 'java.lang.Runtime',
        methods: ['exec']
    },
    // MT管理器特有的敏感操作
    {
        className: 'bin.mt.plus.base.BaseActivity',
        methods: ['onCreate', 'onResume']
    },
    {
        className: 'bin.mt.plus.file.FileManager',
        methods: ['deleteFile', 'copyFile', 'moveFile', 'renameFile']
    }
];

// 为每个API创建Hook
function hookSensitiveAPIs() {
    console.log('[*] 开始Hook敏感API...');
    
    sensitiveAPIs.forEach(api => {
        try {
            const cls = Java.use(api.className);
            
            api.methods.forEach(method => {
                try {
                    // 查找所有重载方法
                    const overloads = cls[method].overloads;
                    
                    overloads.forEach(overload => {
                        overload.implementation = function() {
                            console.log(`\n[!] 调用敏感API: ${api.className}.${method}`);
                            console.log(`    参数: ${JSON.stringify(arguments)}`);
                            
                            // 获取调用堆栈
                            const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                            console.log('[*] 调用堆栈:');
                            for (let i = 3; i < stackTrace.length; i++) {
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
                } catch (e) {
                    console.log(`[-] Hook失败: ${api.className}.${method} - ${e.message}`);
                }
            });
        } catch (e) {
            console.log(`[-] 无法找到类: ${api.className} - ${e.message}`);
        }
    });
    
    console.log('[*] 敏感API Hook完成!');
}

// 执行Hook
Java.perform(function() {
    console.log('[*] MT管理器敏感API追踪脚本已加载');
    console.log('[*] 开始Hook敏感API...');
    hookSensitiveAPIs();
});
