// MT管理器敏感API调用堆栈追踪脚本 - 修复版
// 修复JNI全局引用表溢出问题
// 优化资源使用，减少对象创建

console.log('[*] MT管理器敏感API追踪脚本(修复版)已加载');

// 执行Hook
Java.perform(function() {
    console.log('[*] 开始Hook最基本的敏感API...');
    
    // 预加载常用类，避免重复创建引用
    const Thread = Java.use('java.lang.Thread');
    
    // 日志输出节流控制
    const LOG_THROTTLE_MS = 100; // 每100ms最多输出一次相同API的日志
    const lastLogTime = {};
    
    // 简化的堆栈跟踪获取函数
    function getStackTrace() {
        try {
            // 获取当前线程堆栈
            const stackTrace = Thread.currentThread().getStackTrace();
            const result = [];
            
            // 从第3层开始，跳过当前方法和Hook框架相关
            for (let i = 3; i < stackTrace.length && i < 20; i++) { // 限制最大深度为20
                const stackElement = stackTrace[i];
                
                // 直接获取类名和方法名，避免完整字符串处理
                const className = stackElement.getClassName();
                const methodName = stackElement.getMethodName();
                
                // 只保留简单的堆栈信息
                result.push(`${className}.${methodName}()`);
            }
            
            return result;
        } catch (e) {
            return ['[ERROR] 无法获取堆栈跟踪'];
        }
    }
    
    // Hook 文件系统操作 - 只Hook最常用的方法
    try {
        const File = Java.use('java.io.File');
        
        // Hook File.delete
        File.delete.implementation = function() {
            const now = Date.now();
            const apiKey = 'java.io.File.delete';
            
            // 日志节流：避免频繁输出相同API的日志
            if (!lastLogTime[apiKey] || now - lastLogTime[apiKey] > LOG_THROTTLE_MS) {
                lastLogTime[apiKey] = now;
                
                console.log(`\n[!] 调用敏感API: ${apiKey}`);
                console.log(`    文件路径: ${this.getAbsolutePath()}`);
                
                // 获取并显示堆栈跟踪
                const stackTrace = getStackTrace();
                if (stackTrace.length > 0) {
                    console.log('[*] 调用堆栈:');
                    for (let i = 0; i < stackTrace.length; i++) {
                        const indent = '    '.repeat(i + 1);
                        console.log(`${indent}└── ${stackTrace[i]}`);
                    }
                }
            }
            
            // 调用原始方法
            const result = this.delete();
            
            // 只在节流时间外或结果为false时输出结果
            if (!lastLogTime[apiKey] || now - lastLogTime[apiKey] > LOG_THROTTLE_MS || !result) {
                console.log(`    结果: ${result}`);
            }
            
            return result;
        };
        
        console.log('[+] 成功Hook: java.io.File.delete');
    } catch (e) {
        console.log(`[-] Hook失败: java.io.File.delete - ${e.message}`);
    }
    
    // Hook FileOutputStream.write - 优化版
    try {
        const FileOutputStream = Java.use('java.io.FileOutputStream');
        
        // Hook 所有write重载方法
        const writeOverloads = FileOutputStream.write.overloads;
        writeOverloads.forEach((overload, index) => {
            overload.implementation = function() {
                const now = Date.now();
                const apiKey = `java.io.FileOutputStream.write#${index}`;
                
                // 日志节流
                if (!lastLogTime[apiKey] || now - lastLogTime[apiKey] > LOG_THROTTLE_MS) {
                    lastLogTime[apiKey] = now;
                    
                    console.log(`\n[!] 调用敏感API: java.io.FileOutputStream.write (重载${index+1})`);
                    console.log(`    参数数量: ${arguments.length}`);
                    
                    // 只在非频繁调用时获取堆栈
                    const stackTrace = getStackTrace();
                    if (stackTrace.length > 0) {
                        console.log('[*] 调用堆栈:');
                        for (let i = 0; i < stackTrace.length; i++) {
                            const indent = '    '.repeat(i + 1);
                            console.log(`${indent}└── ${stackTrace[i]}`);
                        }
                    }
                }
                
                // 调用原始方法
                return this.write.apply(this, arguments);
            };
        });
        
        console.log('[+] 成功Hook: java.io.FileOutputStream.write');
    } catch (e) {
        console.log(`[-] Hook失败: java.io.FileOutputStream.write - ${e.message}`);
    }
    
    // Hook FileInputStream.read - 优化版
    try {
        const FileInputStream = Java.use('java.io.FileInputStream');
        
        // Hook 所有read重载方法
        const readOverloads = FileInputStream.read.overloads;
        readOverloads.forEach((overload, index) => {
            overload.implementation = function() {
                const now = Date.now();
                const apiKey = `java.io.FileInputStream.read#${index}`;
                
                // 日志节流
                if (!lastLogTime[apiKey] || now - lastLogTime[apiKey] > LOG_THROTTLE_MS) {
                    lastLogTime[apiKey] = now;
                    
                    console.log(`\n[!] 调用敏感API: java.io.FileInputStream.read (重载${index+1})`);
                    console.log(`    参数数量: ${arguments.length}`);
                    
                    // 只在非频繁调用时获取堆栈
                    const stackTrace = getStackTrace();
                    if (stackTrace.length > 0) {
                        console.log('[*] 调用堆栈:');
                        for (let i = 0; i < stackTrace.length; i++) {
                            const indent = '    '.repeat(i + 1);
                            console.log(`${indent}└── ${stackTrace[i]}`);
                        }
                    }
                }
                
                // 调用原始方法
                return this.read.apply(this, arguments);
            };
        });
        
        console.log('[+] 成功Hook: java.io.FileInputStream.read');
    } catch (e) {
        console.log(`[-] Hook失败: java.io.FileInputStream.read - ${e.message}`);
    }
    
    // Hook 网络连接 - 优化版
    try {
        const HttpURLConnection = Java.use('java.net.HttpURLConnection');
        
        HttpURLConnection.connect.implementation = function() {
            const now = Date.now();
            const apiKey = 'java.net.HttpURLConnection.connect';
            
            // 日志节流
            if (!lastLogTime[apiKey] || now - lastLogTime[apiKey] > LOG_THROTTLE_MS) {
                lastLogTime[apiKey] = now;
                
                console.log(`\n[!] 调用敏感API: ${apiKey}`);
                
                // 安全获取URL，避免异常
                let url = 'Unknown';
                try {
                    url = this.getURL().toString();
                } catch (e) {
                    url = '获取URL失败';
                }
                console.log(`    URL: ${url}`);
                
                // 获取堆栈跟踪
                const stackTrace = getStackTrace();
                if (stackTrace.length > 0) {
                    console.log('[*] 调用堆栈:');
                    for (let i = 0; i < stackTrace.length; i++) {
                        const indent = '    '.repeat(i + 1);
                        console.log(`${indent}└── ${stackTrace[i]}`);
                    }
                }
            }
            
            // 调用原始方法
            return this.connect();
        };
        
        console.log('[+] 成功Hook: java.net.HttpURLConnection.connect');
    } catch (e) {
        console.log(`[-] Hook失败: java.net.HttpURLConnection.connect - ${e.message}`);
    }
    
    // Hook 反射调用 - 优化版
    try {
        const Method = Java.use('java.lang.reflect.Method');
        
        Method.invoke.implementation = function(obj, args) {
            const now = Date.now();
            const apiKey = 'java.lang.reflect.Method.invoke';
            
            // 日志节流
            if (!lastLogTime[apiKey] || now - lastLogTime[apiKey] > LOG_THROTTLE_MS) {
                lastLogTime[apiKey] = now;
                
                console.log(`\n[!] 调用敏感API: ${apiKey}`);
                
                // 安全获取方法名
                let methodName = 'Unknown';
                try {
                    methodName = this.getName();
                } catch (e) {
                    methodName = '获取方法名失败';
                }
                
                console.log(`    方法名: ${methodName}`);
                console.log(`    目标对象: ${obj}`);
                
                // 获取堆栈跟踪
                const stackTrace = getStackTrace();
                if (stackTrace.length > 0) {
                    console.log('[*] 调用堆栈:');
                    for (let i = 0; i < stackTrace.length; i++) {
                        const indent = '    '.repeat(i + 1);
                        console.log(`${indent}└── ${stackTrace[i]}`);
                    }
                }
            }
            
            // 调用原始方法
            return this.invoke(obj, args);
        };
        
        console.log('[+] 成功Hook: java.lang.reflect.Method.invoke');
    } catch (e) {
        console.log(`[-] Hook失败: java.lang.reflect.Method.invoke - ${e.message}`);
    }
    
    console.log('[*] 修复版敏感API Hook完成!');
    console.log('[*] 脚本初始化完成!');
});
