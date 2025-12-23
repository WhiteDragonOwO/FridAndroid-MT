#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MT管理器敏感API追踪 - PyQt5 GUI界面
功能：使用Frida框架对MT管理器的敏感API进行调用堆栈追踪
"""

import sys
import os
import subprocess
import time
import re
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QProgressBar, QGroupBox,
    QComboBox, QLineEdit, QSplitter, QTabWidget, QMessageBox, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont

class CommandRunner(QThread):
    """命令执行线程，用于异步执行命令"""
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int)
    progress_signal = pyqtSignal(int)
    
    def __init__(self, command, cwd=None, package_name=None):
        super().__init__()
        self.command = command
        self.cwd = cwd if cwd else os.getcwd()
        self.package_name = package_name
        self.process = None
        self.running = True
        # 编码配置 - 优先使用UTF-8，失败时使用GBK
        self.encoding = 'utf-8'
    
    def stream_reader(self, stream, signal, is_stderr=False):
        """读取流，处理编码问题"""
        while self.running:
            try:
                # 读取原始字节
                raw_line = stream.readline()
                if not raw_line:  # 流已结束
                    break
                
                # 尝试多种编码解码
                decoded_line = None
                for encoding in ['utf-8', 'gbk', 'latin-1']:
                    try:
                        decoded_line = raw_line.decode(encoding, errors='strict')
                        break
                    except UnicodeDecodeError:
                        continue
                
                # 如果所有编码都失败，使用替换策略
                if decoded_line is None:
                    decoded_line = raw_line.decode('utf-8', errors='replace')
                
                # 移除尾部的换行符
                cleaned_line = decoded_line.rstrip('\n\r')
                if cleaned_line:  # 只发送非空行
                    signal.emit(cleaned_line)
                    if self.package_name:  # 仅在Frida脚本执行时更新进度
                        self.progress_signal.emit(1)
                        
            except (IOError, ValueError, AttributeError) as e:
                if "closed" in str(e) or "invalid" in str(e):
                    break
                time.sleep(0.01)
            except Exception as e:
                error_msg = f"流读取异常: {str(e)}"
                if is_stderr:
                    self.error_signal.emit(error_msg)
                break
    
    def run(self):
        """执行命令"""
        try:
            # 构建命令列表
            command_list = self.build_command_list(self.command)
            
            # 启动子进程 - 使用二进制模式读取
            self.process = subprocess.Popen(
                command_list,
                shell=False,
                cwd=self.cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,  # 行缓冲
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            
            # 创建读取线程
            stdout_thread = threading.Thread(
                target=self.stream_reader,
                args=(self.process.stdout, self.output_signal, False)
            )
            stderr_thread = threading.Thread(
                target=self.stream_reader,
                args=(self.process.stderr, self.error_signal, True)
            )
            
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()
            
            # 监控进程状态
            check_interval = 2
            last_check_time = time.time()
            
            while self.running and self.process.poll() is None:
                current_time = time.time()
                
                # 检查目标应用是否仍在运行
                if self.package_name and current_time - last_check_time > check_interval:
                    if not self.is_package_running(self.package_name):
                        self.output_signal.emit(f"[!] 检测到应用 {self.package_name} 已关闭")
                        self.stop()
                        break
                    last_check_time = current_time
                
                time.sleep(0.1)
            
            # 等待读取线程结束
            if stdout_thread.is_alive():
                stdout_thread.join(timeout=1.0)
            if stderr_thread.is_alive():
                stderr_thread.join(timeout=1.0)
            
            # 确保进程已结束
            if self.process and self.process.poll() is None:
                self.stop()
            
            # 获取返回码
            returncode = self.process.wait(timeout=2) if self.process else -1
            self.finished_signal.emit(returncode)
            
        except Exception as e:
            if self.running:
                self.error_signal.emit(f"执行命令时出错: {str(e)}")
                self.finished_signal.emit(1)
    
    def build_command_list(self, command_str):
        """构建命令列表"""
        import shlex
        try:
            return shlex.split(command_str)
        except:
            # 如果shlex解析失败，使用简单空格分割
            return command_str.split()
    
    def is_package_running(self, package_name):
        """检查应用是否在运行"""
        try:
            result = subprocess.run(
                ['adb', 'shell', 'pidof', package_name],
                shell=False,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=2,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            return result.returncode == 0 and result.stdout.strip()
        except Exception:
            return False
    
    def stop(self):
        """停止命令执行"""
        self.running = False
        if self.process and self.process.poll() is None:
            try:
                # 尝试正常终止
                self.process.terminate()
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    # 如果超时，强制结束
                    self.process.kill()
                    self.process.wait(timeout=1)
            except Exception:
                pass

class MTManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.steps = [
            "检查ADB连接",
            "启动Frida服务器",
            "验证Frida连接",
            "运行MT管理器",
            "执行Frida脚本"
        ]
        self.current_step_index = -1
        self.is_running_all = False
        self.command_thread = None
        self.logs = []
        # 初始化结构化日志列表，用于存储所有解析过的JSON日志
        self.structured_logs = []
        self.pid_cache = None
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("MT管理器敏感API追踪 - PyQt5 GUI")
        self.setGeometry(100, 100, 1200, 800)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        
        left_layout = QVBoxLayout()
        
        title_label = QLabel("MT管理器敏感API追踪")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setStyleSheet("color: #0066cc; padding: 10px;")
        left_layout.addWidget(title_label)
        
        config_group = QGroupBox("配置选项")
        config_layout = QVBoxLayout(config_group)
        
        package_layout = QHBoxLayout()
        package_layout.addWidget(QLabel("应用包名:"))
        self.package_input = QLineEdit("bin.mt.plus")
        self.package_input.setStyleSheet("padding: 5px;")
        package_layout.addWidget(self.package_input)
        
        self.check_status_button = QPushButton("检测状态")
        self.check_status_button.clicked.connect(self.check_app_status)
        self.check_status_button.setStyleSheet("padding: 5px;")
        package_layout.addWidget(self.check_status_button)
        config_layout.addLayout(package_layout)
        
        script_layout = QHBoxLayout()
        script_layout.addWidget(QLabel("Frida脚本:"))
        self.script_input = QLineEdit("scripts/mt_manager_tracing_reflection.js")
        self.script_input.setStyleSheet("padding: 5px;")
        script_layout.addWidget(self.script_input)
        
        self.browse_button = QPushButton("浏览")
        self.browse_button.clicked.connect(self.browse_script)
        self.browse_button.setStyleSheet("padding: 5px;")
        script_layout.addWidget(self.browse_button)
        config_layout.addLayout(script_layout)
        
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("执行模式:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["智能模式", "附加到已运行进程", "启动新进程"])
        self.mode_combo.setCurrentText("智能模式")
        mode_layout.addWidget(self.mode_combo)
        config_layout.addLayout(mode_layout)
        
        left_layout.addWidget(config_group)
        
        control_layout = QHBoxLayout()
        
        self.start_button = QPushButton("开始执行")
        self.start_button.clicked.connect(self.start_execution)
        self.start_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px; font-weight: bold;")
        control_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("停止")
        self.stop_button.clicked.connect(self.stop_execution)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; padding: 8px;")
        control_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton("清空日志")
        self.clear_button.clicked.connect(self.clear_logs)
        self.clear_button.setStyleSheet("padding: 8px;")
        control_layout.addWidget(self.clear_button)
        
        self.export_button = QPushButton("导出日志")
        self.export_button.clicked.connect(self.export_logs)
        self.export_button.setStyleSheet("background-color: #FF9800; color: white; padding: 8px;")
        control_layout.addWidget(self.export_button)
        
        left_layout.addLayout(control_layout)
        
        status_group = QGroupBox("状态信息")
        status_layout = QHBoxLayout(status_group)
        
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        status_layout.addWidget(self.status_label)
        
        self.pid_label = QLabel("应用PID: 未检测")
        self.pid_label.setStyleSheet("color: #666; font-style: italic;")
        status_layout.addWidget(self.pid_label)
        
        left_layout.addWidget(status_group)
        
        self.tab_widget = QTabWidget()
        
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            background-color: #f5f5f5; 
            font-family: Consolas, Monaco, monospace; 
            font-size: 10pt;
            border: 1px solid #ddd;
        """)
        log_layout.addWidget(self.log_text)
        self.tab_widget.addTab(log_widget, "执行日志")
        
        exported_logs_widget = QWidget()
        exported_logs_layout = QVBoxLayout(exported_logs_widget)
        self.exported_logs_text = QTextEdit()
        self.exported_logs_text.setReadOnly(True)
        self.exported_logs_text.setStyleSheet("""
            background-color: #f5f5f5; 
            font-family: Consolas, Monaco, monospace; 
            font-size: 10pt;
            border: 1px solid #ddd;
        """)
        exported_logs_layout.addWidget(self.exported_logs_text)
        self.tab_widget.addTab(exported_logs_widget, "导出日志数据")
        
        left_layout.addWidget(self.tab_widget)
        
        right_layout = QVBoxLayout()
        
        steps_group = QGroupBox("启动功能区")
        steps_layout = QVBoxLayout(steps_group)
        
        steps_label = QLabel("选择要执行的步骤:")
        steps_label.setFont(QFont("Arial", 12, QFont.Bold))
        steps_layout.addWidget(steps_label)
        
        self.step_buttons = []
        for i, step in enumerate(self.steps):
            button = QPushButton(f"{i+1}. {step}")
            button.clicked.connect(lambda checked, idx=i: self.execute_step(idx))
            button.setStyleSheet("padding: 10px; margin: 5px 0; text-align: left;")
            self.step_buttons.append(button)
            steps_layout.addWidget(button)
        
        self.run_all_button = QPushButton("执行全部步骤")
        self.run_all_button.clicked.connect(self.run_all_steps)
        self.run_all_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px; font-weight: bold; margin-top: 10px;")
        steps_layout.addWidget(self.run_all_button)
        
        right_layout.addWidget(steps_group)
        
        progress_group = QGroupBox("执行进度")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(self.steps) * 20)
        progress_layout.addWidget(self.progress_bar)
        
        self.step_status_label = QLabel("当前状态: 就绪")
        self.step_status_label.setFont(QFont("Arial", 12))
        progress_layout.addWidget(self.step_status_label)
        
        right_layout.addWidget(progress_group)
        right_layout.addStretch()
        
        main_layout.addLayout(left_layout, 3)
        main_layout.addLayout(right_layout, 1)
    
    def log(self, message, is_error=False, is_success=False):
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        
        if is_error:
            html = f'<span style="color: #ff0000;">{log_entry}</span>'
        elif is_success:
            html = f'<span style="color: #00aa00;">{log_entry}</span>'
        else:
            html = f'<span style="color: #0000aa;">{log_entry}</span>'
        
        self.log_text.append(html)
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )
    
    def browse_script(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择Frida脚本", "./scripts", "JavaScript文件 (*.js);;所有文件 (*.*)"
        )
        if file_path:
            self.script_input.setText(file_path)
    
    def clear_logs(self):
        self.log_text.clear()
        self.logs = []
        self.log("日志已清空", is_success=True)
    
    def start_execution(self):
        self.log("开始执行MT管理器敏感API追踪流程", is_success=True)
        self.run_all_steps()
    
    def check_app_status(self):
        package = self.package_input.text()
        if not package:
            self.log("请输入应用包名后再检测", is_error=True)
            return
        self.log(f"正在检测应用 [{package}] 的运行状态...")
        pid = self.get_app_pid(package)
        if pid:
            self.log(f"检测到应用正在运行，PID: {pid}", is_success=True)
        else:
            self.log("检测到应用未在运行", is_error=True)

    def execute_step(self, idx):
        if idx < 0 or idx >= len(self.steps):
            self.log(f"无效的步骤索引: {idx}", is_error=True)
            return
        
        if self.command_thread and self.command_thread.isRunning():
            self.log("已有命令正在执行，请先停止或等待完成", is_error=True)
            return
        
        self.current_step_index = idx
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue((idx + 1) * 20)
        self.step_status_label.setText(f"当前状态: 执行步骤 {idx+1}/{len(self.steps)} - {self.steps[idx]}")
        self.status_label.setText("执行中...")
        
        self.log(f"执行步骤 {idx+1}: {self.steps[idx]}")
        
        if idx == 0:
            self.check_adb_connection()
        elif idx == 1:
            self.start_frida_server()
        elif idx == 2:
            self.verify_frida_connection()
        elif idx == 3:
            self.run_mt_manager()
        elif idx == 4:
            self.run_frida_script()
    
    def run_all_steps(self):
        self.log("开始执行全部步骤", is_success=True)
        self.is_running_all = True
        self.stop_button.setEnabled(True)
        self.execute_step(0)
    
    def stop_execution(self):
        self.log("停止执行", is_error=True)
        if self.command_thread and self.command_thread.isRunning():
            self.command_thread.stop()
        self.is_running_all = False
        self.stop_button.setEnabled(False)
        self.status_label.setText("已停止")
        self.step_status_label.setText("当前状态: 已停止")
    
    def check_adb_connection(self):
        self.run_command("adb devices", "检查ADB连接")
    
    def start_frida_server(self):
        # 检查Frida服务器是否已在运行
        check_command = 'adb shell "su -c ps -A | grep frida-server"'
        try:
            result = subprocess.run(check_command, shell=True, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and "frida-server" in result.stdout:
                self.log("Frida服务器已经在运行，跳过启动步骤", is_success=True)
                self.command_finished(0)
                return
        except Exception as e:
            self.log(f"检查Frida服务器状态时出错: {str(e)}", is_error=True)
        
        command = 'adb shell "su -c /data/local/tmp/frida-server &"'
        self.run_command(command, "启动Frida服务器")
    
    def verify_frida_connection(self):
        self.run_command("frida-ps -U", "验证Frida连接")
    
    def run_mt_manager(self):
        package = self.package_input.text()
        command = f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1"
        self.run_command(command, "运行MT管理器")
    
    def run_frida_script(self):
        package = self.package_input.text()
        script = self.script_input.text()
        
        if not os.path.exists(script):
            self.log(f"脚本文件不存在: {script}", is_error=True)
            self.command_finished(-1)
            return

        # 使用绝对路径，并用引号包裹处理空格
        script_path = os.path.abspath(script)
        script_with_quotes = f'"{script_path}"'
        
        mode = self.mode_combo.currentText()
        command = ""
        pid = None
        
        if mode == "智能模式":
            pid = self.get_app_pid(package)
            if pid:
                self.log(f"智能模式：检测到应用已运行，将附加到进程 (PID: {pid})", is_success=True)
                # 关键修复：使用正确的frida命令格式
                command = f'frida -U -p {pid} -l {script_with_quotes}'
            else:
                self.log("智能模式：应用未运行，将启动新进程", is_success=True)
                command = f'frida -U -f {package} -l {script_with_quotes}'
        elif mode == "附加到已运行进程":
            pid = self.get_app_pid(package)
            if pid:
                command = f'frida -U -p {pid} -l {script_with_quotes}'
            else:
                self.log("应用未运行，无法附加", is_error=True)
                self.command_finished(-1)
                return
        elif mode == "启动新进程":
            command = f'frida -U -f {package} -l {script_with_quotes}'
        
        if command:
            self.log(f"Frida命令: {command}", is_success=True)
            self.run_command(command, "执行Frida脚本")
        else:
            self.log("未能构建Frida命令", is_error=True)
            self.command_finished(-1)

    def run_command(self, command_str, description):
        self.log(f"准备执行命令: {command_str}")
        package_name = self.package_input.text() if "Frida脚本" in description else None
        self.command_thread = CommandRunner(command_str, package_name=package_name)
        self.command_thread.output_signal.connect(self.process_output)
        self.command_thread.error_signal.connect(lambda x: self.log(f"错误: {x}", is_error=True))
        self.command_thread.finished_signal.connect(self.command_finished)
        self.command_thread.progress_signal.connect(self.update_progress)
        self.command_thread.start()
    
    def process_output(self, output):
        # 处理各种可能的输出格式
        
        # 检查是否为JSON格式的日志
        if output.strip().startswith('{') and output.strip().endswith('}'):
            try:
                import json
                # 解析JSON日志
                parsed = json.loads(output.strip())
                
                # 直接记录原始JSON日志到self.structured_logs，确保不丢失
                self.structured_logs.append(parsed)
                
                # 同时在UI中显示格式化的日志，便于阅读
                # 根据风险等级设置不同的颜色
                if parsed.get('riskLevel') == 'HIGH':
                    self.log(f"[高风险] {parsed.get('apiName')} - {parsed.get('riskReason')}", is_error=True)
                elif parsed.get('riskLevel') == 'MEDIUM':
                    self.log(f"[中风险] {parsed.get('apiName')} - {parsed.get('riskReason')}")
                else:
                    self.log(f"[低风险] {parsed.get('apiName')} - {parsed.get('riskReason')}", is_success=True)
                
                # 添加API详情
                if parsed.get('details'):
                    self.log("API详情:")
                    for key, value in parsed['details'].items():
                        self.log(f"  {key}: {value}")
                
                # 添加堆栈跟踪（只显示前8层）
                if parsed.get('stackTrace'):
                    self.log("调用堆栈:")
                    for i, stack_line in enumerate(parsed['stackTrace'][:8]):
                        self.log(f"  {i+1}. {stack_line}")
                    if len(parsed['stackTrace']) > 8:
                        self.log(f"  ... 以及 {len(parsed['stackTrace']) - 8} 层更多")
                
                self.log("-" * 50)
            except json.JSONDecodeError:
                # 如果JSON解析失败，作为普通日志输出
                self.log(output)
        # 处理带有时间戳前缀的JSON日志
        elif '{' in output and '}' in output:
            # 直接记录原始日志，parse_logs函数会处理解析
            self.log(output)
        # 处理传统格式的日志
        elif "[!]" in output and ("调用敏感API:" in output or "Sensitive API Called:" in output):
            self.log(output, is_error=True)
        elif "└──" in output:
            self.log(output)
        elif "[+]" in output or "[*]" in output:
            self.log(output, is_success=True)
        elif "[-]" in output:
            self.log(output, is_error=True)
        else:
            self.log(output)
    
    def command_finished(self, returncode):
        if returncode == 0:
            self.log("命令执行成功", is_success=True)
            if self.is_running_all and self.current_step_index < len(self.steps) - 1:
                QTimer.singleShot(1000, lambda: self.execute_step(self.current_step_index + 1))
            elif self.is_running_all and self.current_step_index == len(self.steps) - 1:
                self.log("所有步骤执行完成", is_success=True)
                self.is_running_all = False
                self.stop_button.setEnabled(False)
                self.status_label.setText("执行完成")
                self.step_status_label.setText("当前状态: 执行完成")
            else:
                self.stop_button.setEnabled(False)
                self.status_label.setText("执行完成")
                self.step_status_label.setText("当前状态: 执行完成")
        else:
            self.log(f"命令执行失败，返回码: {returncode}", is_error=True)
            self.is_running_all = False
            self.stop_button.setEnabled(False)
            self.status_label.setText("执行失败")
            self.step_status_label.setText("当前状态: 执行失败")
    
    def update_progress(self, value):
        current_value = self.progress_bar.value()
        self.progress_bar.setValue(min(current_value + value, self.progress_bar.maximum()))
    
    def get_app_pid(self, package_name):
        try:
            result = subprocess.run(
                ['adb', 'shell', 'pidof', package_name],
                shell=False,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=2,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            if result.returncode == 0 and result.stdout.strip():
                pid = result.stdout.strip().split()[0]
                self.pid_label.setText(f"应用PID: {pid}")
                self.pid_cache = pid
                return pid
            else:
                self.pid_label.setText("应用PID: 未运行")
                self.pid_cache = None
        except Exception as e:
            self.log(f"获取PID时出错: {str(e)}", is_error=True)
        return None
    
    def export_logs(self):
        import json
        
        # 解析所有日志
        self.parse_logs()
        
        if not self.structured_logs:
            QMessageBox.information(self, "信息", "没有可导出的日志数据")
            return
        
        # 获取保存路径
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出日志", f"mt_manager_logs_{time.strftime('%Y%m%d_%H%M%S')}.json", "JSON文件 (*.json);;所有文件 (*.*)"
        )
        
        if file_path:
            try:
                # 导出完整的结构化日志
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.structured_logs, f, ensure_ascii=False, indent=2)
                QMessageBox.information(self, "成功", f"日志已成功导出到: {file_path}")
                
                # 显示导出的日志数量
                self.log(f"已导出 {len(self.structured_logs)} 条结构化日志", is_success=True)
                
                # 更新显示的导出日志
                self.display_structured_logs()
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出日志时出错: {str(e)}")
                self.log(f"导出日志失败: {str(e)}", is_error=True)
    
    def display_structured_logs(self):
        import json
        structured_logs_str = json.dumps(self.structured_logs, ensure_ascii=False, indent=2)
        self.exported_logs_text.setPlainText(structured_logs_str)
        self.tab_widget.setCurrentIndex(1)
    
    def parse_logs(self):
        self.structured_logs = []
        
        # 遍历所有日志条目
        for log_entry in self.logs:
            # 检查是否包含JSON格式的日志（可能带有时间戳前缀）
            json_start = log_entry.find('{')
            json_end = log_entry.rfind('}')
            
            if json_start != -1 and json_end != -1:
                # 提取JSON部分
                json_str = log_entry[json_start:json_end+1].strip()
                try:
                    # 直接解析JSON格式的日志
                    import json
                    structured_log = json.loads(json_str)
                    # 确保保留完整的堆栈跟踪
                    if 'stackTrace' in structured_log:
                        # 不修改原始堆栈跟踪，保留完整信息
                        pass
                    self.structured_logs.append(structured_log)
                except json.JSONDecodeError as e:
                    # 如果JSON解析失败，记录错误但继续处理其他日志
                    self.log(f"JSON解析失败: {e}", is_error=True)
                    self._parse_old_format_log(log_entry)
            else:
                # 使用旧的日志格式解析
                self._parse_old_format_log(log_entry)
        
        # 记录解析结果
        self.log(f"成功解析 {len(self.structured_logs)} 条结构化日志", is_success=True)
    
    def _parse_old_format_log(self, log_entry):
        """解析旧格式的日志"""
        timestamp_match = re.match(r'\[(\d{2}:\d{2}:\d{2})\] (.*)', log_entry)
        if not timestamp_match:
            return
        
        timestamp = timestamp_match.group(1)
        message = timestamp_match.group(2)
        
        # 匹配中英文两种格式的API调用
        api_match = re.match(r'\[!\] (?:调用敏感API:|Sensitive API Called:) (.+)', message)
        if api_match:
            # 兼容旧格式，转换为新的结构化格式
            old_format_log = {
                'timestamp': timestamp,
                'api_name': api_match.group(1),
                'details': {},
                'stack_trace': [],
                'riskLevel': 'LOW',
                'riskReason': 'Legacy format log'
            }
            self.structured_logs.append(old_format_log)
    
    def closeEvent(self, event):
        if self.command_thread and self.command_thread.isRunning():
            self.command_thread.stop()
            self.command_thread.wait()
        event.accept()

if __name__ == "__main__":
    # 强制设置UTF-8编码
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    
    print("[*] MT管理器敏感API追踪GUI启动中...")
    app = QApplication(sys.argv)
    print("[*] 创建主窗口...")
    gui = MTManagerGUI()
    print("[*] 显示主窗口...")
    gui.show()
    print("[*] 进入事件循环...")
    sys.exit(app.exec_())