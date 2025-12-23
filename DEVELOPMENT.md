# MT管理器敏感API追踪项目开发文档

## 1. 项目概述

### 1.1 项目背景
随着移动应用的普及，Android文件管理器作为重要的系统工具，其安全性日益受到关注。MT管理器作为一款功能强大的Android文件管理器，具有广泛的用户基础。本项目旨在通过Frida框架对MT管理器进行动态插桩，监控其敏感API调用，分析其运行时行为，为应用安全分析提供有力支持。

### 1.2 项目目标
- 监控MT管理器的敏感API调用
- 记录API调用的上下文信息，包括调用堆栈、参数等
- 特别关注反射调用，查看被反射调用的目标类、方法名和参数
- 提供友好的GUI界面，方便用户操作
- 支持日志记录和导出，便于后续分析

### 1.3 技术栈
- **语言**：Python 3.12, JavaScript
- **框架**：Frida 17.5.1, PyQt5 5.15.10
- **工具**：ADB, Android模拟器
- **核心功能**：动态插桩、JNI资源管理、智能日志节流、风险评估、结构化日志输出

## 2. 项目架构

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                     客户端 (PC)                          │
├─────────────┬─────────────┬─────────────────────────────┤
│  GUI应用    │ Frida工具   │ 日志分析工具                │
│  (PyQt5)    │             │                             │
└─────┬───────┴─────────────┴─────────────────┬───────────┘
      │                                       │
      │                                       │
      ▼                                       ▼
┌─────────────────────────────────────────────────────────┐
│                     服务端 (Android设备)                  │
├─────────────┬─────────────────────────────────────────┤
│ Frida服务器  │ 被监控应用 (MT管理器)                     │
│             ├─────────────────────────────────────────┤
│             │ 插桩点1: File操作                        │
│             │ 插桩点2: Network操作                     │
│             │ 插桩点3: Reflection操作                  │
│             │ 插桩点4: 其他敏感API                     │
└─────────────┴─────────────────────────────────────────┘
```

## 3. 代码结构

```
├── .idea/                   # IDE配置文件
├── Old_version/             # 旧版本脚本
│   ├── mt_manager_tracing.js
│   ├── mt_manager_tracing_enhanced.js
│   ├── mt_manager_tracing_fixed.js
│   ├── mt_manager_tracing_minimal.js
│   └── mt_manager_tracing_optimized.js
├── __pycache__/             # Python编译缓存
├── docs/                    # 文档
│   └── 对话.txt
├── logs/                    # 日志文件
│   └── *.json               # 导出的JSON格式日志
├── scripts/                 # Frida脚本
│   ├── mt_manager_tracing_comprehensive_full.js  # 完整监控脚本
│   └── mt_manager_tracing_reflection.js          # 反射监控脚本
├── server/                  # Frida服务器
│   └── frida-server-17.5.1-android-x86_64
├── utils/                   # 工具脚本
│   └── extract_docx.py      # 从docx提取文本
├── DEVELOPMENT.md           # 开发文档
└── mt_manager_tracing_ui.py # PyQt5 GUI主文件
```

## 4. 功能模块

### 4.1 Frida脚本模块

#### 4.1.1 基础脚本架构
所有Frida脚本都基于以下架构：

```javascript
Java.perform(function() {
    // 预加载常用类
    // 实现日志输出函数
    // Hook各种敏感API
    // 输出调用信息和堆栈跟踪
});
```

#### 4.1.2 脚本类型

| 脚本名称 | 功能描述 | 适用场景 |
|---------|---------|----------|
| mt_manager_tracing_comprehensive.js | 全面监控敏感API | 基础监控，适合长时间运行 |
| mt_manager_tracing_comprehensive_full.js | 完整监控敏感API | 深度监控，包含所有敏感API |
| mt_manager_tracing_reflection.js | 重点监控反射调用 | 反射调用分析，查看反射上下文 |

#### 4.1.3 监控的API

1. **反射相关API**
   - `java.lang.reflect.Method.invoke`
   - `java.lang.reflect.Constructor.newInstance`
   - `java.lang.Class.forName` (支持1个和3个参数重载版本)

2. **现代文件操作API (DocumentsContract)**
   - `android.provider.DocumentsContract.createDocument`
   - `android.provider.DocumentsContract.deleteDocument`
   - `android.provider.DocumentsContract.renameDocument`

3. **基础文件操作API**
   - `java.io.File.delete`
   - `java.io.File.createNewFile`
   - `java.io.File.renameTo`
   - `java.io.File.mkdir`
   - `java.io.File.mkdirs`
   - `java.io.File.listFiles` (文件树遍历监控)
   - `java.io.File.list` (文件列表获取监控)

4. **文件流API**
   - `java.io.FileInputStream.read`
   - `java.io.FileOutputStream.write`
   - `java.io.FileReader.read`
   - `java.io.FileWriter.write`

5. **网络操作API**
   - `java.net.HttpURLConnection.connect`
   - `java.net.HttpURLConnection.getInputStream`
   - `java.net.HttpURLConnection.getOutputStream`
   - `java.net.URL.openConnection`

6. **ZIP/解压缩操作API**
   - `java.util.zip.ZipFile.<init>` (压缩包访问监控)

7. **剪切板操作API**
   - `android.content.ClipboardManager.setPrimaryClip`

### 4.2 GUI应用模块

#### 4.2.1 核心功能

1. **步骤化执行**
   - 检查ADB连接
   - 启动Frida服务器
   - 验证Frida连接
   - 运行MT管理器
   - 执行Frida脚本

2. **执行模式**
   - 智能模式：自动检测应用状态
   - 附加到已运行进程：仅当应用已运行时执行
   - 启动新进程：强制启动新的应用进程

3. **日志功能**
   - 实时显示执行日志
   - 支持彩色显示不同类型的日志
   - 结构化日志解析与实时保存
   - JSON格式日志导出（包含完整堆栈信息）
   - 基于风险等级的日志分类显示（高/中/低风险）
   - 智能日志格式化（自动缩短长堆栈，保留关键信息）

4. **配置管理**
   - 应用包名配置
   - Frida脚本选择
   - 执行模式选择

5. **性能优化**
   - JNI资源管理优化
   - 智能日志节流机制（基于API名+文件路径哈希）
   - 减少JNI调用次数
   - 堆栈深度限制（最大15层）

6. **风险评估**
   - 基于API类型的风险评估
   - 基于文件路径的风险评估
   - 基于反射操作的风险评估
   - 风险等级分类（HIGH/MEDIUM/LOW）

#### 4.2.2 类结构

```
┌───────────────────┐
│   MTManagerGUI    │
├───────────────────┤
│ - initUI()        │
│ - execute_step()  │
│ - run_all_steps() │
│ - run_command()   │
│ - process_output()│
│ - command_finished() │
│ - get_app_pid()   │
│ - export_logs()   │
└─────────────┬─────┘
              │
┌─────────────▼─────┐
│   CommandRunner   │
├───────────────────┤
│ - run()           │
│ - stop()          │
│ - build_command_list() │
│ - is_package_running() │
└───────────────────┘
```

## 5. 开发流程

### 5.1 环境搭建

1. **安装Frida**
   ```bash
   pip install frida-tools frida
   ```

2. **配置Android设备**
   - 启用开发者选项
   - 启用USB调试
   - 连接设备到PC

3. **运行Frida服务器**
   ```bash
   # 推送Frida服务器到设备
   adb push server/frida-server-17.5.1-android-x86_64 /data/local/tmp/
   
   # 赋予执行权限
   adb shell chmod 755 /data/local/tmp/frida-server
   
   # 启动Frida服务器
   adb shell su -c "/data/local/tmp/frida-server &"
   ```

### 5.2 开发流程

1. **设计阶段**
   - 确定监控的API列表
   - 设计脚本架构和日志格式
   - 设计GUI界面布局

2. **编码阶段**
   - 编写Frida脚本，Hook敏感API
   - 实现GUI应用，提供用户界面
   - 编写测试脚本，验证功能

3. **测试阶段**
   - 测试脚本语法正确性
   - 测试API调用监控效果
   - 测试GUI应用功能完整性
   - 测试日志输出和导出功能

4. **部署阶段**
   - 打包应用和脚本
   - 编写使用说明
   - 更新开发文档

## 6. 开发规范

### 6.1 代码风格

1. **Python代码风格**
   - 遵循PEP 8规范
   - 类名使用大驼峰命名法
   - 函数和变量使用小驼峰命名法
   - 注释清晰，说明功能和参数

2. **JavaScript代码风格**
   - 遵循ES6规范
   - 函数和变量使用小驼峰命名法
   - 注释清晰，说明Hook的API和功能

### 6.2 命名规范

1. **文件命名**
   - 使用小写字母和下划线
   - 清晰描述文件功能
   - 例如：`mt_manager_tracing_reflection.js`

2. **类和函数命名**
   - 类名使用大驼峰命名法
   - 函数和变量使用小驼峰命名法
   - 例如：`CommandRunner`类，`build_command_list`函数

### 6.3 日志规范

1. **日志格式**
   ```
   [HH:MM:SS] [标识] 消息内容
   ```

2. **标识含义**
   - `[!]`：警告或错误
   - `[+]`：成功
   - `[*]`：信息
   - `[-]`：失败

3. **堆栈跟踪格式**
   ```
   [*] 调用堆栈:
       └── com.example.Class1.method1()
       └── com.example.Class2.method2()
       └── com.example.Class3.method3()
   ```

## 7. 测试与调试

### 7.1 测试策略

1. **单元测试**
   - 测试命令构建功能
   - 测试脚本语法正确性
   - 测试API调用监控效果

2. **集成测试**
   - 测试GUI应用与Frida脚本的交互
   - 测试步骤化执行流程
   - 测试日志输出和导出功能

3. **系统测试**
   - 测试完整的监控流程
   - 测试不同设备和Android版本的兼容性
   - 测试长时间运行的稳定性

### 7.2 调试技巧

1. **使用ADB日志**
   ```bash
   adb logcat -d | grep -i frida
   ```

2. **使用Frida日志**
   - 在脚本中添加调试信息
   - 使用`console.log()`输出调试信息

3. **使用GUI日志**
   - 查看GUI应用的实时日志
   - 导出JSON日志进行分析

### 7.3 常见问题与解决方案

| 问题 | 解决方案 |
|------|----------|
| 脚本执行失败，返回码2 | 检查脚本路径是否正确，确保使用绝对路径 |
| Frida服务器连接失败 | 确保Frida服务器已启动，设备已连接 |
| 应用崩溃 | 减少Hook的API数量，优化脚本性能 |
| 日志输出不完整 | 调整日志节流参数，增加日志输出频率 |
| JNI堆栈溢出 | 优化堆栈跟踪获取方法，减少JNI调用次数，实现智能日志节流，限制堆栈深度为15层 |
| Class.forName参数类型不匹配 | 使用arguments对象和apply方法处理不同重载版本，支持1个和3个参数版本 |
| 日志导出为空或不完整 | 实现实时日志解析和保存，直接将JSON对象添加到结构化日志列表中 |

## 8. 部署与使用

### 8.1 部署方式

1. **直接运行**
   ```bash
   # 运行GUI应用
   python mt_manager_tracing_ui.py
   
   # 直接运行Frida脚本
   frida -U -f bin.mt.plus --no-pause -l scripts/mt_manager_tracing_reflection.js
   ```

2. **使用快捷方式**
   - 创建桌面快捷方式，指向GUI应用
   - 添加到系统PATH，方便命令行调用

### 8.2 使用说明

1. **GUI应用使用**
   - 启动GUI应用
   - 选择执行模式
   - 选择Frida脚本
   - 点击"执行全部步骤"或单独步骤
   - 查看实时日志
   - 导出日志进行分析

2. **命令行使用**
   - 连接设备
   - 启动Frida服务器
   - 运行Frida脚本
   - 查看控制台输出

## 9. 未来规划

### 9.1 功能增强

1. **支持更多反射API**
   - 监控`Field.set/get`等反射操作
   - 支持`Method.getDeclaredMethods`等方法
   - 增加对`Method.setAccessible`等敏感反射操作的监控

2. **高级风险评估**
   - 实现基于机器学习的风险评估模型
   - 支持自定义风险规则
   - 增加风险告警功能

3. **可视化输出**
   - 提供图形化的调用关系图
   - 支持实时可视化监控
   - 实现日志分析仪表板

4. **动态配置**
   - 支持通过配置文件调整监控级别
   - 支持动态加载和卸载监控模块
   - 实现远程配置更新

5. **API调用序列分析**
   - 识别敏感操作序列
   - 检测异常行为模式
   - 实现操作链可视化

### 9.2 性能优化

1. **高级Hook性能优化**
   - 实现基于优先级的Hook管理
   - 支持按需Hook，减少资源消耗
   - 实现Hook缓存机制

2. **内存优化**
   - 实现更智能的对象复用
   - 增加自动内存清理机制
   - 实现内存使用监控

3. **日志系统优化**
   - 实现分级日志系统
   - 支持日志压缩和归档
   - 增加日志过滤和搜索功能

### 9.3 兼容性增强

1. **跨平台支持**
   - 支持Windows、macOS和Linux
   - 实现平台适配层

2. **Android版本兼容性**
   - 测试并支持Android 15.0
   - 实现API版本适配

3. **设备兼容性**
   - 支持更多CPU架构（arm64-v8a, armeabi-v7a, x86）
   - 支持更多设备类型（手机、平板、TV）

### 9.4 安全增强

1. **加密通信**
   - 实现Frida通信加密
   - 支持安全日志传输

2. **反检测机制**
   - 实现反Frida检测绕过
   - 支持动态代码注入

3. **隐私保护**
   - 实现日志脱敏功能
   - 支持敏感数据过滤

## 10. 注意事项

### 10.1 安全注意事项

1. **设备安全**
   - 仅在测试设备上运行
   - 避免在生产环境中使用

2. **数据安全**
   - 妥善保存日志文件
   - 避免泄露敏感信息

3. **法律合规**
   - 仅在合法授权的情况下使用
   - 遵守相关法律法规

### 10.2 性能注意事项

1. **资源消耗**
   - 反射监控会带来一定的性能开销
   - 建议仅在分析阶段使用

2. **长时间运行**
   - 长时间运行可能导致内存泄漏
   - 定期重启应用和脚本

### 10.3 开发注意事项

1. **版本兼容性**
   - 确保Frida版本与设备兼容
   - 定期更新Frida框架

2. **代码维护**
   - 定期更新脚本，适配新的Android版本
   - 保持代码结构清晰，便于维护

3. **文档更新**
   - 及时更新开发文档
   - 记录所有重大变更

## 11. 贡献指南

### 11.1 贡献流程

1. **Fork仓库**
2. **创建分支**
3. **开发功能**
4. **提交代码**
5. **创建Pull Request**
6. **代码审查**
7. **合并分支**

### 11.2 代码审查标准

1. **功能完整性**
   - 实现的功能符合需求
   - 代码能够正常运行

2. **代码质量**
   - 代码风格符合规范
   - 注释清晰，说明功能
   - 没有明显的性能问题

3. **测试覆盖**
   - 包含必要的测试用例
   - 测试结果符合预期

4. **文档更新**
   - 更新开发文档
   - 记录功能变更

## 12. 参考文献

1. **Frida官方文档**
   - https://frida.re/docs/
   - https://frida.re/docs/javascript-api/

2. **PyQt5官方文档**
   - https://www.riverbankcomputing.com/static/Docs/PyQt5/

3. **Android开发文档**
   - https://developer.android.com/docs

4. **ADB命令参考**
   - https://developer.android.com/studio/command-line/adb

## 13. 附录

### 13.1 常用命令

| 命令 | 功能描述 |
|------|----------|
| `adb devices` | 查看连接的设备 |
| `frida-ps -U` | 查看设备上的进程 |
| `frida --version` | 查看Frida版本 |
| `adb shell pidof bin.mt.plus` | 获取MT管理器PID |
| `adb logcat -d` | 查看设备日志 |

### 13.2 术语表

| 术语 | 解释 |
|------|------|
| Frida | 一款动态插桩工具，用于Android应用分析 |
| Hook | 钩子，用于拦截和修改函数调用 |
| 插桩 | 在应用运行时注入代码，监控其行为 |
| ADB | Android Debug Bridge，用于与Android设备通信 |
| PID | Process ID，进程标识符 |
| APK | Android应用安装包 |
| JNI | Java Native Interface，Java本地接口 |

### 13.3 联系方式

- **项目地址**：https://github.com/yourusername/FridAndroidre
- **作者**：Your Name
- **邮箱**：your.email@example.com

---

## 14. 变更日志

### v1.2 (2025-12-24)

#### 国际化改进
- 将所有Python和JavaScript脚本的中文日志和提示信息转换为英文
- 包括GUI界面文本、注释、日志输出等所有中文内容
- 保持原有功能不变，仅更新语言为英文
- 支持在英文环境下正常使用

#### 代码结构优化
- 统一了日志格式和输出规范
- 优化了注释和文档结构
- 确保所有日志输出符合英文语法和表达习惯

---

### v1.1 (2025-12-24)

#### 核心优化
- 修复了JNI堆栈溢出问题，优化了JNI资源管理
- 实现了基于API名+文件路径哈希的智能日志节流机制
- 优化了堆栈跟踪获取方法，减少JNI调用次数（限制最大深度为15层）
- 修复了Class.forName Hook的参数类型不匹配问题（支持1个和3个参数重载版本）

#### 功能增强
- 增加了DocumentsContract API监控（Android 11+现代文件操作核心）
- 增加了文件树遍历监控（listFiles, File.list）
- 增加了ZIP/解压缩操作监控（ZipFile构造函数）
- 增加了剪切板操作监控（ClipboardManager.setPrimaryClip）
- 实现了风险评估规则引擎，支持风险等级分类（HIGH/MEDIUM/LOW）
- 实现了结构化JSON日志输出，便于后续分析

#### GUI优化
- 实现了实时JSON日志解析和保存，确保日志导出完整
- 优化了日志显示格式，根据风险等级显示不同颜色
- 优化了堆栈跟踪显示，只显示前8层，便于阅读
- 修复了日志导出不完整的问题
- 增加了日志解析结果的反馈信息

#### 其他改进
- 更新了开发文档，反映最新的功能和架构
- 增加了常见问题与解决方案
- 优化了代码结构，提高了可维护性

---

**版本**：v1.2
**最后更新**：2025-12-24
**版权**：© 2025 Your Name. All rights reserved.