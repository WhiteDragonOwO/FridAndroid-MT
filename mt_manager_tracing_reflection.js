// MT管理器敏感API调用栈追踪脚本 - 反射监控版
// 修复JNI堆栈溢出问题，优化资源使用
// 实现智能日志节流、风险评估和结构化输出

console.log('[*] MT Manager Sensitive API Tracing Script (Optimized Version) loaded');

// 执行Hook
Java.perform(function() {
    console.log('[*] Starting Hook for sensitive APIs...');
    
    // 预加载常用类以避免重复创建引用
    const Thread = Java.use('java.lang.Thread');
    
    // 日志输出节流控制
    const LOG_THROTTLE_MS = 100; // 每100ms最多输出一次相同操作的日志
    const lastLogTime = {};
    
    // 简单哈希函数，用于生成API+上下文的唯一标识
    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // 转换为32位整数
        }
        return hash;
    }
    
    // 优化的堆栈跟踪函数 - 减少JNI调用
    function getStackTrace() {
        try {
            // 获取当前线程堆栈 - 这是主要的JNI调用
            const stackTrace = Thread.currentThread().getStackTrace();
            const result = [];
            
            // 从第3层开始，跳过当前方法和Hook框架相关内容
            // 限制最大深度为15，减少JNI调用次数
            const maxDepth = Math.min(stackTrace.length, 15);
            for (let i = 3; i < maxDepth; i++) {
                try {
                    const stackElement = stackTrace[i];
                    // 批量获取类名和方法名，减少JNI调用
                    const className = stackElement.getClassName();
                    const methodName = stackElement.getMethodName();
                    
                    // 只保留简单的堆栈信息，避免复杂字符串处理
                    result.push(`${className}.${methodName}()`);
                } catch (e) {
                    // 单个堆栈元素获取失败时继续，避免整个函数失败
                    continue;
                }
            }
            
            return result;
        } catch (e) {
            return ['[ERROR] Failed to get stack trace'];
        }
    }
    
    // 风险评估函数
    function assessRisk(apiName, details) {
        let riskLevel = 'LOW';
        let riskReason = 'Normal operation';
        
        // 基于API名称的风险评估
        if (apiName.includes('delete') || apiName.includes('unlink')) {
            riskLevel = 'MEDIUM';
            riskReason = 'File deletion operation';
        } else if (apiName.includes('exec') || apiName.includes('Runtime')) {
            riskLevel = 'HIGH';
            riskReason = 'Code execution operation';
        } else if (apiName.includes('connect') && apiName.includes('URL')) {
            riskLevel = 'MEDIUM';
            riskReason = 'Network connection operation';
        }
        
        // 基于文件路径的风险评估
        if (details['file_path'] || details['File path']) {
            const filePath = details['file_path'] || details['File path'];
            if (filePath.includes('/data/data/') || filePath.includes('/data/user/')) {
                riskLevel = 'HIGH';
                riskReason = 'Access to other apps private directories';
            } else if (filePath.includes('/system/') || filePath.includes('/vendor/')) {
                riskLevel = 'HIGH';
                riskReason = 'Access to system directories';
            } else if (filePath.includes('DCIM') || filePath.includes('Download')) {
                riskLevel = 'MEDIUM';
                riskReason = 'Access to media directories';
            }
        }
        
        // 基于反射的风险评估
        if (apiName.includes('reflect') || apiName.includes('Method.invoke') || apiName.includes('Constructor.newInstance')) {
            riskLevel = 'MEDIUM';
            riskReason = 'Reflection operation detected';
        }
        
        return { riskLevel, riskReason };
    }
    
    // 通用日志输出函数 - 输出结构化JSON
    function logAPI(apiName, details = {}) {
        const now = Date.now();
        
        // 生成唯一日志标识：API名 + 关键上下文信息哈希
        let logKey = apiName;
        if (details['file_path'] || details['File path'] || details['URL']) {
            const context = details['file_path'] || details['File path'] || details['URL'];
            logKey = `${apiName}_${simpleHash(context)}`;
        }
        
        // 日志节流：避免相同操作频繁输出
        if (!lastLogTime[logKey] || now - lastLogTime[logKey] > LOG_THROTTLE_MS) {
            lastLogTime[logKey] = now;
            
            // 获取堆栈跟踪
            const stackTrace = getStackTrace();
            
            // 风险评估
            const risk = assessRisk(apiName, details);
            
            // 构建结构化日志
            const structuredLog = {
                timestamp: new Date().toISOString(),
                apiName: apiName,
                details: details,
                stackTrace: stackTrace,
                riskLevel: risk.riskLevel,
                riskReason: risk.riskReason
            };
            
            // 输出结构化JSON日志
            console.log(JSON.stringify(structuredLog));
        }
    }
    
    // -------------------------- 反射操作 --------------------------
    
    // Hook Method.invoke 以查看反射调用上下文信息
    try {
        const Method = Java.use('java.lang.reflect.Method');
        
        Method.invoke.implementation = function(obj, args) {
            // 获取方法名和声明类 - 减少JNI调用次数
            let methodName = 'Unknown';
            let declaringClassName = 'Unknown';
            let targetClassName = 'Unknown';
            
            try {
                // 只获取关键信息，避免复杂的参数处理
                methodName = this.getName();
                declaringClassName = this.getDeclaringClass().getName();
                
                // 获取目标对象类名
                if (obj) {
                    targetClassName = obj.getClass().getName();
                } else {
                    targetClassName = 'static';
                }
            } catch (e) {
                // 捕获异常以确保脚本不会崩溃
            }
            
            // 使用优化后的logAPI函数
            logAPI('java.lang.reflect.Method.invoke', {
                declaringClassName: declaringClassName,
                methodName: methodName,
                targetClassName: targetClassName
            });
            
            // 调用原始方法
            return this.invoke(obj, args);
        };
        
        console.log('[+] Successfully hooked: java.lang.reflect.Method.invoke');
    } catch (e) {
        console.log(`[-] Hook failed: java.lang.reflect.Method - ${e.message}`);
    }
    
    // -------------------------- 构造函数反射 --------------------------
    
    // Hook Constructor.newInstance 以查看构造函数反射调用
    try {
        const Constructor = Java.use('java.lang.reflect.Constructor');
        
        Constructor.newInstance.implementation = function(args) {
            // 获取构造函数信息 - 减少JNI调用
            let className = 'Unknown';
            
            try {
                className = this.getDeclaringClass().getName();
            } catch (e) {
                // 捕获异常以确保脚本不会崩溃
            }
            
            // 使用优化后的logAPI函数
            logAPI('java.lang.reflect.Constructor.newInstance', {
                className: className
            });
            
            // 调用原始方法
            return this.newInstance(args);
        };
        
        console.log('[+] Successfully hooked: java.lang.reflect.Constructor.newInstance');
    } catch (e) {
        console.log(`[-] Hook failed: java.lang.reflect.Constructor - ${e.message}`);
    }
    
    // -------------------------- 类加载反射 --------------------------
    
    // Hook Class.forName 以查看类加载反射调用
    try {
        const Class = Java.use('java.lang.Class');
        
        // Hook Class.forName 静态方法
        const forNameOverloads = Class.forName.overloads;
        forNameOverloads.forEach((overload, index) => {
            overload.implementation = function() {
                // 根据不同的重载版本处理参数
                let name, initialize, loader;
                
                // 1个参数版本: forName(String name)
                if (arguments.length === 1) {
                    name = arguments[0];
                    initialize = true; // 默认值
                    loader = null; // 默认值
                }
                // 3个参数版本: forName(String name, boolean initialize, ClassLoader loader)
                else if (arguments.length === 3) {
                    name = arguments[0];
                    initialize = arguments[1];
                    loader = arguments[2];
                }
                
                // 使用优化后的logAPI函数
                logAPI('java.lang.Class.forName', {
                    className: name,
                    initialize: initialize
                });
                
                // 调用原始方法 - 使用apply传递所有参数
                return this.forName.apply(this, arguments);
            };
        });
        
        console.log('[+] Successfully hooked: java.lang.Class.forName');
    } catch (e) {
        console.log(`[-] Hook failed: java.lang.Class.forName - ${e.message}`);
    }
    
    // -------------------------- 现代文件操作API (DocumentsContract) --------------------------
    
    // Hook DocumentsContract API - Android 11+ 现代文件操作核心
    try {
        const DocumentsContract = Java.use('android.provider.DocumentsContract');
        
        // Hook createDocument
        if (DocumentsContract.createDocument) {
            DocumentsContract.createDocument.implementation = function(contentResolver, documentUri, mimeType, displayName) {
                logAPI('android.provider.DocumentsContract.createDocument', {
                    documentUri: documentUri ? documentUri.toString() : 'null',
                    mimeType: mimeType,
                    displayName: displayName
                });
                
                return this.createDocument(contentResolver, documentUri, mimeType, displayName);
            };
            console.log('[+] Successfully hooked: DocumentsContract.createDocument');
        }
        
        // Hook deleteDocument
        if (DocumentsContract.deleteDocument) {
            DocumentsContract.deleteDocument.implementation = function(contentResolver, documentUri) {
                logAPI('android.provider.DocumentsContract.deleteDocument', {
                    documentUri: documentUri ? documentUri.toString() : 'null'
                });
                
                return this.deleteDocument(contentResolver, documentUri);
            };
            console.log('[+] Successfully hooked: DocumentsContract.deleteDocument');
        }
        
        // Hook renameDocument
        if (DocumentsContract.renameDocument) {
            DocumentsContract.renameDocument.implementation = function(contentResolver, documentUri, displayName) {
                logAPI('android.provider.DocumentsContract.renameDocument', {
                    documentUri: documentUri ? documentUri.toString() : 'null',
                    displayName: displayName
                });
                
                return this.renameDocument(contentResolver, documentUri, displayName);
            };
            console.log('[+] Successfully hooked: DocumentsContract.renameDocument');
        }
        
    } catch (e) {
        console.log(`[-] Hook failed: DocumentsContract - ${e.message}`);
    }
    
    // -------------------------- 基础文件操作API --------------------------
    
    // Hook File.delete 作为基础敏感API监控
    try {
        const File = Java.use('java.io.File');
        
        File.delete.implementation = function() {
            logAPI('java.io.File.delete', {
                file_path: this.getAbsolutePath()
            });
            
            const result = this.delete();
            return result;
        };
        
        // Hook File.listFiles - 监控文件树遍历
        File.listFiles.implementation = function(filter) {
            logAPI('java.io.File.listFiles', {
                directory_path: this.getAbsolutePath()
            });
            
            return this.listFiles(filter);
        };
        
        // Hook File.list - 监控文件列表获取
        File.list.implementation = function(filter) {
            logAPI('java.io.File.list', {
                directory_path: this.getAbsolutePath()
            });
            
            return this.list(filter);
        };
        
        // Hook File.createNewFile - 监控文件创建
        File.createNewFile.implementation = function() {
            logAPI('java.io.File.createNewFile', {
                file_path: this.getAbsolutePath()
            });
            
            return this.createNewFile();
        };
        
        console.log('[+] Successfully hooked: File.delete, File.listFiles, File.list, File.createNewFile');
    } catch (e) {
        console.log(`[-] Hook failed: java.io.File - ${e.message}`);
    }
    
    // -------------------------- 网络操作API --------------------------
    
    // Hook HttpURLConnection.connect 作为基础敏感API监控
    try {
        const HttpURLConnection = Java.use('java.net.HttpURLConnection');
        
        HttpURLConnection.connect.implementation = function() {
            let url = 'Unknown';
            try {
                url = this.getURL().toString();
            } catch (e) {
                url = 'Failed to get URL';
            }
            
            logAPI('java.net.HttpURLConnection.connect', {
                URL: url
            });
            
            return this.connect();
        };
        
        console.log('[+] Successfully hooked: java.net.HttpURLConnection.connect');
    } catch (e) {
        console.log(`[-] Hook failed: java.net.HttpURLConnection - ${e.message}`);
    }
    
    // -------------------------- ZIP/解压缩操作API --------------------------
    
    // Hook ZIP相关操作
    try {
        // Hook ZipFile构造函数
        const ZipFile = Java.use('java.util.zip.ZipFile');
        
        ZipFile.$init.overloads.forEach((overload, index) => {
            overload.implementation = function(file, mode) {
                let filePath = 'Unknown';
                try {
                    if (file) {
                        if (typeof file === 'string') {
                            filePath = file;
                        } else {
                            filePath = file.toString();
                        }
                    }
                } catch (e) {
                    filePath = 'Failed to get file path';
                }
                
                logAPI('java.util.zip.ZipFile.<init>', {
                    file_path: filePath
                });
                
                return this.$init(file, mode);
            };
        });
        
        console.log('[+] Successfully hooked: java.util.zip.ZipFile.<init>');
    } catch (e) {
        console.log(`[-] Hook failed: java.util.zip.ZipFile - ${e.message}`);
    }
    
    // -------------------------- 剪切板操作API --------------------------
    
    // Hook ClipboardManager相关操作
    try {
        const ClipboardManager = Java.use('android.content.ClipboardManager');
        
        // Hook setPrimaryClip
        if (ClipboardManager.setPrimaryClip) {
            ClipboardManager.setPrimaryClip.implementation = function(clipData) {
                logAPI('android.content.ClipboardManager.setPrimaryClip', {
                    clipData: clipData ? clipData.toString() : 'null'
                });
                
                return this.setPrimaryClip(clipData);
            };
            console.log('[+] Successfully hooked: ClipboardManager.setPrimaryClip');
        }
        
    } catch (e) {
        console.log(`[-] Hook failed: ClipboardManager - ${e.message}`);
    }
    
    console.log('[*] Optimized sensitive API Hook completed!');
    console.log('[*] Script initialization completed!');
    console.log('[*] Currently monitored APIs include:');
    console.log('[*] - Reflection operations: Method.invoke, Constructor.newInstance, Class.forName');
    console.log('[*] - Modern file operations: DocumentsContract API (create, delete, rename)');
    console.log('[*] - Basic file operations: File.delete, listFiles, list, createNewFile');
    console.log('[*] - Network connections: HttpURLConnection.connect');
    console.log('[*] - ZIP operations: ZipFile constructor');
    console.log('[*] - Clipboard operations: ClipboardManager.setPrimaryClip');
    console.log('[*] JNI stack overflow protection enabled with optimized resource usage!');

});
