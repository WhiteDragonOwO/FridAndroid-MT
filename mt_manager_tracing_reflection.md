# mt_manager_tracing_reflection.js - 说明文档

## 1. 脚本概述

### 1.1 基本信息
- **脚本名称**: MT Manager Sensitive API Tracing Script (Optimized Version)
- **版本**: v1.2
- **语言**: JavaScript
- **运行环境**: Frida 17.5.1
- **适用平台**: Android
- **监控目标**: MT管理器 (bin.mt.plus)

### 1.2 主要功能
- 优化版本的敏感API追踪，特别关注反射操作
- 修复了JNI堆栈溢出问题，优化了资源使用
- 实现智能日志节流，避免频繁输出相同操作的日志
- 基于API类型、文件路径和反射调用进行风险评估
- 提供结构化的JSON格式日志输出
- 支持多种敏感API的监控，包括反射、文件操作、网络操作等
- 优化的堆栈跟踪获取，减少JNI调用次数

### 1.3 已修复问题
- **JNI堆栈溢出**: 优化了堆栈跟踪获取，限制最大深度为15层
- **频繁日志输出**: 实现了智能日志节流，每100ms最多输出一次相同操作的日志
- **资源消耗过大**: 预加载常用类，减少对象创建开销
- **Class.forName参数类型不匹配**: 支持1个和3个参数的重载版本

## 2. 脚本架构

### 2.1 核心组件

```
┌─────────────────────────────────────────────────────────┐
│                      初始化阶段                         │
├─────────────┬─────────────┬─────────────────────────────┤
│ 预加载类    │ 初始化工具函数 │ 配置日志节流              │
└─────┬───────┴─────────────┴─────────────────┬───────────┘
      │                                       │
      │                                       │
      ▼                                       ▼
┌─────────────────────────────────────────────────────────┐
│                      Hook阶段                          │
├─────────────┬─────────────────────────────────────────┤
│ 反射操作Hook│ 文件操作Hook                           │
│             ├─────────────────────────────────────────┤
│             │ 现代文件操作Hook (DocumentsContract)   │
│             ├─────────────────────────────────────────┤
│             │ 网络操作Hook                           │
│             ├─────────────────────────────────────────┤
│             │ ZIP操作Hook                            │
│             ├─────────────────────────────────────────┤
│             │ 剪切板操作Hook                         │
└─────┬───────┴─────────────┬─────────────────┬───────────┘
      │                     │                 │
      ▼                     ▼                 ▼
┌─────────────────────────────────────────────────────────┐
│                      日志输出阶段                       │
├─────────────┬─────────────┬─────────────────────────────┤
│ 结构化日志  │ 风险评估    │ 日志节流控制              │
└─────────────┴─────────────┴─────────────────────────────┘
```

### 2.2 关键技术点
- **日志节流**: 基于API名称和关键上下文信息的哈希值，每100ms最多输出一次相同操作的日志
- **风险评估**: 基于API类型、文件路径和反射调用进行风险评级（LOW/MEDIUM/HIGH）
- **优化的堆栈跟踪**: 限制最大深度为15层，减少JNI调用次数
- **结构化日志**: 输出包含完整上下文信息的JSON格式日志
- **智能异常处理**: 单个堆栈元素获取失败时继续执行，避免整个函数崩溃
- **支持多种重载版本**: 适配不同参数版本的API调用

## 3. 监控范围

### 3.1 反射操作
- `java.lang.reflect.Method.invoke` - 反射方法调用
- `java.lang.reflect.Constructor.newInstance` - 反射构造函数调用
- `java.lang.Class.forName` - 类加载反射调用（支持1个和3个参数版本）

### 3.2 现代文件操作 (DocumentsContract)
- `android.provider.DocumentsContract.createDocument` - 创建文档
- `android.provider.DocumentsContract.deleteDocument` - 删除文档
- `android.provider.DocumentsContract.renameDocument` - 重命名文档

### 3.3 基础文件操作
- `java.io.File.delete` - 文件删除
- `java.io.File.listFiles` - 文件列表获取
- `java.io.File.list` - 文件列表获取
- `java.io.File.createNewFile` - 文件创建

### 3.4 网络操作
- `java.net.HttpURLConnection.connect` - HTTP连接

### 3.5 ZIP/解压缩操作
- `java.util.zip.ZipFile.<init>` - 压缩包访问

### 3.6 剪切板操作
- `android.content.ClipboardManager.setPrimaryClip` - 设置剪切板内容

## 4. 使用方法

### 4.1 直接运行

```bash
# 启动应用并附加脚本
frida -U -f bin.mt.plus --no-pause -l mt_manager_tracing_reflection.js

# 附加到已运行的进程
frida -U -p <PID> -l mt_manager_tracing_reflection.js
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

```json
{
  "timestamp": "2025-12-24T10:30:45.123Z",
  "apiName": "java.lang.reflect.Method.invoke",
  "details": {
    "declaringClassName": "java.lang.String",
    "methodName": "substring",
    "targetClassName": "java.lang.String"
  },
  "stackTrace": [
    "com.example.Class1.method1()",
    "com.example.Class2.method2()"
  ],
  "riskLevel": "MEDIUM",
  "riskReason": "Reflection operation detected"
}
```

### 5.2 风险等级说明
- **LOW**: 正常操作，风险较低
- **MEDIUM**: 敏感操作，需要关注
- **HIGH**: 高风险操作，可能存在安全问题

## 6. 执行流程

### 6.1 初始化阶段
1. 预加载常用类：Thread
2. 初始化日志节流控制参数
3. 实现辅助函数：
   - `simpleHash()`: 生成唯一日志标识
   - `getStackTrace()`: 获取优化的堆栈跟踪
   - `assessRisk()`: 进行风险评估
   - `logAPI()`: 输出结构化日志

### 6.2 Hook阶段
1. **反射操作Hook**：
   - Hook Method.invoke
   - Hook Constructor.newInstance
   - Hook Class.forName（所有重载版本）

2. **现代文件操作Hook**：
   - Hook DocumentsContract API（createDocument, deleteDocument, renameDocument）

3. **基础文件操作Hook**：
   - Hook File.delete, listFiles, list, createNewFile

4. **网络操作Hook**：
   - Hook HttpURLConnection.connect

5. **ZIP操作Hook**：
   - Hook ZipFile构造函数

6. **剪切板操作Hook**：
   - Hook ClipboardManager.setPrimaryClip

### 6.3 日志输出阶段
1. 当监控的API被调用时，触发相应的Hook函数
2. 收集API调用的上下文信息
3. 生成唯一日志标识，应用日志节流机制
4. 获取优化的堆栈跟踪
5. 进行风险评估
6. 生成结构化JSON日志
7. 输出日志到控制台

## 7. 性能优化

### 7.1 资源优化
- **预加载常用类**：避免重复创建引用
- **优化的堆栈跟踪**：限制最大深度为15层，减少JNI调用次数
- **批量获取堆栈信息**：减少JNI调用次数
- **智能异常处理**：单个堆栈元素获取失败时继续执行

### 7.2 日志优化
- **智能日志节流**：每100ms最多输出一次相同操作的日志
- **唯一日志标识**：基于API名和关键上下文信息的哈希值
- **结构化JSON输出**：便于后续分析
- **风险评估**：帮助区分不同风险级别的操作

### 7.3 JNI优化
- **减少JNI调用**：优化堆栈跟踪获取，减少JNI调用次数
- **批量处理**：批量获取堆栈信息，减少JNI往返次数
- **异常处理**：捕获并处理JNI调用异常，避免脚本崩溃

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
   frida -U -f bin.mt.plus --no-pause -l mt_manager_tracing_reflection.js
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
- 修复了JNI堆栈溢出问题
- 实现了智能日志节流机制
- 优化了堆栈跟踪获取方法
- 增加了风险评估功能
- 支持多种敏感API的监控

### v1.0 (2025-12-16)
- 初始版本
- 实现了基本的敏感API监控
- 支持反射操作的监控

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
