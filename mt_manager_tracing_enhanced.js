// MT管理器敏感API调用堆栈追踪脚本 - 增强版
// 显示更详细的调用堆栈，按树形结构输出

console.log('[*] MT管理器敏感API追踪脚本(增强版)已加载');

// 执行Hook
Java.perform(function() {
    console.log('[*] 开始Hook最基本的敏感API...');
    
    // Hook 文件系统操作 - 只Hook最常用的方法
    try {
        const File = Java.use('java.io.File');
        
        // Hook File.delete
        File.delete.implementation = function() {
            console.log(`\n[!] 调用敏感API: java.io.File.delete`);
            console.log(`    文件路径: ${this.getAbsolutePath()}`);
            
            // 获取完整调用堆栈
            const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
            console.log('[*] 调用堆栈 (树形结构):');
            
            // 从第3层开始显示（跳过当前方法和Hook框架相关）
            for (let i = 3; i < stackTrace.length; i++) {
                // 树形结构缩进
                let indent = '    '.repeat(i - 2);
                let stackInfo = stackTrace[i].toString();
                
                // 简化堆栈信息，只保留类名和方法名
                const simplified = stackInfo.replace(/\([^)]*\)/g, '()');
                
                console.log(`${indent}└── ${simplified}`);
            }
            
            // 调用原始方法
            const result = this.delete();
            console.log(`    结果: ${result}`);
            
            return result;
        };
        
        console.log('[+] 成功Hook: java.io.File.delete');
    } catch (e) {
        console.log(`[-] Hook失败: java.io.File.delete - ${e.message}`);
    }
    
    // Hook FileOutputStream.write
    try {
        const FileOutputStream = Java.use('java.io.FileOutputStream');
        
        // Hook 所有write重载方法
        const writeOverloads = FileOutputStream.write.overloads;
        writeOverloads.forEach((overload, index) => {
            overload.implementation = function() {
                console.log(`\n[!] 调用敏感API: java.io.FileOutputStream.write (重载${index+1})`);
                console.log(`    参数数量: ${arguments.length}`);
                
                // 获取完整调用堆栈
                const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                console.log('[*] 调用堆栈 (树形结构):');
                
                for (let i = 3; i < stackTrace.length; i++) {
                    let indent = '    '.repeat(i - 2);
                    let stackInfo = stackTrace[i].toString();
                    const simplified = stackInfo.replace(/\([^)]*\)/g, '()');
                    console.log(`${indent}└── ${simplified}`);
                }
                
                // 调用原始方法
                return this.write.apply(this, arguments);
            };
        });
        
        console.log('[+] 成功Hook: java.io.FileOutputStream.write');
    } catch (e) {
        console.log(`[-] Hook失败: java.io.FileOutputStream.write - ${e.message}`);
    }
    
    // Hook FileInputStream.read
    try {
        const FileInputStream = Java.use('java.io.FileInputStream');
        
        // Hook 所有read重载方法
        const readOverloads = FileInputStream.read.overloads;
        readOverloads.forEach((overload, index) => {
            overload.implementation = function() {
                console.log(`\n[!] 调用敏感API: java.io.FileInputStream.read (重载${index+1})`);
                console.log(`    参数数量: ${arguments.length}`);
                
                // 获取完整调用堆栈
                const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                console.log('[*] 调用堆栈 (树形结构):');
                
                for (let i = 3; i < stackTrace.length; i++) {
                    let indent = '    '.repeat(i - 2);
                    let stackInfo = stackTrace[i].toString();
                    const simplified = stackInfo.replace(/\([^)]*\)/g, '()');
                    console.log(`${indent}└── ${simplified}`);
                }
                
                // 调用原始方法
                return this.read.apply(this, arguments);
            };
        });
        
        console.log('[+] 成功Hook: java.io.FileInputStream.read');
    } catch (e) {
        console.log(`[-] Hook失败: java.io.FileInputStream.read - ${e.message}`);
    }
    
    // Hook 网络连接
    try {
        const HttpURLConnection = Java.use('java.net.HttpURLConnection');
        
        HttpURLConnection.connect.implementation = function() {
            console.log(`\n[!] 调用敏感API: java.net.HttpURLConnection.connect`);
            console.log(`    URL: ${this.getURL()}`);
            
            // 获取完整调用堆栈
            const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
            console.log('[*] 调用堆栈 (树形结构):');
            
            for (let i = 3; i < stackTrace.length; i++) {
                let indent = '    '.repeat(i - 2);
                let stackInfo = stackTrace[i].toString();
                const simplified = stackInfo.replace(/\([^)]*\)/g, '()');
                console.log(`${indent}└── ${simplified}`);
            }
            
            // 调用原始方法
            return this.connect();
        };
        
        console.log('[+] 成功Hook: java.net.HttpURLConnection.connect');
    } catch (e) {
        console.log(`[-] Hook失败: java.net.HttpURLConnection.connect - ${e.message}`);
    }
    
    // Hook 反射调用
    try {
        const Method = Java.use('java.lang.reflect.Method');
        
        Method.invoke.implementation = function(obj, args) {
            console.log(`\n[!] 调用敏感API: java.lang.reflect.Method.invoke`);
            console.log(`    方法名: ${this.getName()}`);
            console.log(`    目标对象: ${obj}`);
            
            // 获取完整调用堆栈
            const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
            console.log('[*] 调用堆栈 (树形结构):');
            
            for (let i = 3; i < stackTrace.length; i++) {
                let indent = '    '.repeat(i - 2);
                let stackInfo = stackTrace[i].toString();
                const simplified = stackInfo.replace(/\([^)]*\)/g, '()');
                console.log(`${indent}└── ${simplified}`);
            }
            
            // 调用原始方法
            return this.invoke(obj, args);
        };
        
        console.log('[+] 成功Hook: java.lang.reflect.Method.invoke');
    } catch (e) {
        console.log(`[-] Hook失败: java.lang.reflect.Method.invoke - ${e.message}`);
    }
    
    console.log('[*] 增强版敏感API Hook完成!');
    console.log('[*] 脚本初始化完成!');
});
