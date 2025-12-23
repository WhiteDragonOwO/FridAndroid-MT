# mt_manager_tracing_comprehensive_full.js - 说明文档

## 1. 脚本概述

### 1.1 基本信息
- **脚本名称**: MT Manager Sensitive API Tracing Script (Full Monitoring Version) [FIXED]
- **版本**: v1.2
- **语言**: JavaScript
- **运行环境**: Frida 17.5.1
- **适用平台**: Android
- **监控目标**: MT管理器 (bin.mt.plus)

### 1.2 主要功能
- 全方位监控MT管理器的敏感API调用
- 实时记录API调用的上下文信息和堆栈跟踪
- 实现了风险评估机制，基于API类型、文件路径和反射调用进行风险评级
- 提供结构化的JSON格式日志输出
- 支持日志节流控制，避免频繁输出相同API的日志
- 监控系统状态，包括设备解锁状态、Root状态和顶层Activity
- 自动获取应用上下文和包信息

### 1.3 已修复问题
- **listFiles重载错误**: 修复了不同重载版本的调用问题
- **无限递归调用**: 解决了Hook方法中错误调用导致的无限递归
- **JNI崩溃问题**: 优化了JNI调用，减少崩溃风险

## 2. 脚本架构

### 2.1 核心组件

```
┌─────────────────────────────────────────────────────────┐
│                      初始化阶段                         │
├─────────────┬─────────────┬─────────────────────────────┤
│ 预加载类    │ 获取上下文  │ 初始化辅助函数              │
└─────┬───────┴─────────────┴─────────────────┬───────────┘
      │                                       │
      │                                       │
      ▼                                       ▼
┌─────────────────────────────────────────────────────────┐
│                      Hook阶段                          │
├─────────────┬─────────────────────────────────────────┤
│ 反射操作Hook│ 文件操作Hook                           │
│             ├─────────────────────────────────────────┤
│             │ 文件流操作Hook                         │
│             ├─────────────────────────────────────────┤
│             │ Runtime类Hook                          │
└─────┬───────┴─────────────┬─────────────────┬───────────┘
      │                     │                 │
      ▼                     ▼                 ▼
┌─────────────────────────────────────────────────────────┐
│                      日志输出阶段                       │
├─────────────┬─────────────┬─────────────────────────────┤
│ 结构化日志  │ 风险评估    │ 系统状态监控              │
└─────────────┴─────────────┴─────────────────────────────┘
```

### 2.2 关键技术点
- **日志节流**: 同一API每100ms最多输出一次日志，避免日志风暴
- **结构化日志**: 输出包含完整上下文信息的JSON格式日志
- **风险评估**: 基于API类型、文件路径和反射调用进行风险评级
- **堆栈跟踪**: 获取并输出API调用的堆栈信息，便于分析调用链
- **系统监控**: 监控设备解锁状态、Root状态和顶层Activity

## 3. 监控范围

### 3.1 反射操作
- `java.lang.reflect.Method.invoke` - 反射方法调用
- `java.lang.reflect.Constructor.newInstance` - 反射构造函数调用

### 3.2 文件操作
- `java.io.File.delete` - 文件删除
- `java.io.File.renameTo` - 文件重命名
- `java.io.File.listFiles()` - 文件列表获取（无参数）
- `java.io.File.listFiles(FilenameFilter)` - 文件列表获取（带过滤器）
- `java.io.File.listFiles(FileFilter)` - 文件列表获取（带文件过滤器）

### 3.3 文件流操作
- `java.io.FileOutputStream.write` - 文件写入

### 3.4 Runtime操作
- `java.lang.Runtime.exec` - 系统命令执行

## 4. 使用方法

### 4.1 直接运行

```bash
# 启动应用并附加脚本
frida -U -f bin.mt.plus --no-pause -l mt_manager_tracing_comprehensive_full.js

# 附加到已运行的进程
frida -U -p <PID> -l mt_manager_tracing_comprehensive_full.js
```

### 4.2 通过GUI应用运行

1. 运行GUI应用：
   ```bash
   python mt_manager_tracing_ui.py
   ```

2. 在GUI界面中：
   - 选择执行模式
   - 选择此脚本文件
   - 点击"执行全部步骤"或单独步骤

## 5. 日志格式

### 5.1 控制台输出格式

```
[!] Sensitive API call: java.io.File.delete
{
  "timestamp": "2025-12-24 10:30:45.123",
  "processInfo": {
    "packageName": "bin.mt.plus",
    "uid": 1000,
    "pid": 12345,
    "threadId": 12346
  },
  "api": {
    "name": "java.io.File.delete",
    "details": {
      "File path": "/storage/emulated/0/test.txt",
      "Result": true
    }
  },
  "systemStatus": {
    "isDeviceUnlocked": true,
    "isDeviceRooted": false,
    "topActivity": "bin.mt.plus.activity.MainActivity"
  },
  "riskAssessment": {
    "level": "Medium risk",
    "reason": "File deletion operation"
  },
  "stackTrace": "bin.mt.plus.FileManager.deleteFile()\n    -> bin.mt.plus.activity.MainActivity.onClick()"
}
```

### 5.2 风险等级说明
- **Low risk**: 正常操作，风险较低
- **Medium risk**: 敏感操作，需要关注
- **High risk**: 高风险操作，可能存在安全问题
- **Extremely high risk**: 极高风险操作，如访问其他应用私有目录

## 6. 脚本执行流程

### 6.1 初始化阶段
1. 预加载常用类：Thread、Process、Binder、Date、SimpleDateFormat
2. 创建SimpleDateFormat实例，用于生成时间戳
3. 获取应用上下文和包信息
4. 初始化日志节流控制
5. 实现辅助函数：
   - `getStackTrace()`: 获取堆栈跟踪
   - `getTimestamp()`: 获取格式化时间戳
   - `getTopActivity()`: 获取顶层Activity
   - `isDeviceUnlocked()`: 检查设备解锁状态
   - `isDeviceRooted()`: 检查设备Root状态
   - `checkPermission()`: 检查应用权限
   - `getFileMetadata()`: 获取文件元数据
   - `assessRisk()`: 进行风险评估
   - `logAPI()`: 输出结构化日志

### 6.2 Hook阶段
1. **反射操作Hook**：Hook Method.invoke和Constructor.newInstance
2. **文件操作Hook**：Hook File类的delete、renameTo和listFiles方法
3. **文件流操作Hook**：Hook FileOutputStream.write方法
4. **Runtime操作Hook**：Hook Runtime.exec方法

### 6.3 日志输出阶段
1. 当监控的API被调用时，触发相应的Hook函数
2. 收集API调用的上下文信息
3. 进行风险评估
4. 生成结构化日志
5. 应用日志节流机制
6. 输出JSON格式日志

## 7. 性能优化

### 7.1 资源优化
- 预加载常用类，避免重复创建引用
- 只创建一次SimpleDateFormat实例，减少对象创建开销
- 优化堆栈跟踪获取，只保留第3-20层的堆栈信息

### 7.2 日志优化
- 实现日志节流控制，同一API每100ms最多输出一次
- 使用API名称+路径作为日志节流的唯一标识
- 结构化日志输出，便于后续分析

### 7.3 JNI优化
- 减少JNI调用次数，优化堆栈跟踪获取
- 避免在Hook函数中进行复杂的JNI操作

## 8. 注意事项

### 8.1 安全注意事项
- 仅在测试设备上运行此脚本
- 避免在生产环境中使用
- 妥善保存日志文件，避免泄露敏感信息

### 8.2 性能注意事项
- 脚本运行会带来一定的性能开销
- 长时间运行可能导致内存占用增加
- 建议定期重启脚本以释放资源

### 8.3 兼容性注意事项
- 适用于Android 7.0+版本
- 需要Frida 17.5.1及以上版本
- 依赖设备具有Root权限或Frida服务器具有合适的权限

## 9. 部署与调试

### 9.1 部署步骤
1. 确保Android设备已连接到PC
2. 确保Frida服务器已在设备上启动：
   ```bash
   adb shell su -c "/data/local/tmp/frida-server &"
   ```
3. 运行脚本：
   ```bash
   frida -U -f bin.mt.plus --no-pause -l mt_manager_tracing_comprehensive_full.js
   ```

### 9.2 调试技巧
- 查看ADB日志：`adb logcat -d | grep -i frida`
- 在脚本中添加`console.log()`输出调试信息
- 检查设备上的Frida服务器状态：`frida-ps -U`

## 10. 版本历史

### v1.2 (2025-12-24)
- 将所有脚本日志从中文改为英文
- 优化了日志输出格式
- 改进了风险评估机制
- 更新了开发文档

### v1.1 (2025-12-24)
- 修复了listFiles重载错误
- 解决了无限递归调用问题
- 优化了JNI调用，减少崩溃风险
- 增加了系统状态监控
- 实现了风险评估功能

### v1.0 (2025-12-16)
- 初始版本
- 实现了基本的敏感API监控
- 支持结构化日志输出

## 11. 扩展建议

### 11.1 功能扩展
- 增加更多敏感API的监控
- 实现日志过滤和搜索功能
- 支持远程日志传输
- 增加实时告警功能

### 11.2 性能优化
- 进一步优化JNI调用
- 实现更智能的日志节流机制
- 支持按需Hook，减少资源消耗

### 11.3 兼容性改进
- 支持更多Android版本
- 适配不同架构的设备
- 支持更多文件管理器应用

## 12. 联系方式

- **项目地址**: https://github.com/yourusername/FridAndroidre
- **作者**: Your Name
- **邮箱**: your.email@example.com

---

**版权声明**: © 2025 Your Name. All rights reserved.
**最后更新**: 2025-12-24
