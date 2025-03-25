import subprocess
import tempfile
import os
import json
from typing import List, Dict, Union, Optional, Literal

class R2:
    def __init__(self, timeout: int = 60):
        """
        Initialize the radare2 executor
        :param timeout: Command execution timeout(in seconds)
        """
        self.timeout = timeout
        self._verify_r2()

    def _verify_r2(self):
        """Verify radare2 installation"""
        try:
            subprocess.run(['r2', '-qv'], check=True, 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE)
        except (FileNotFoundError, subprocess.CalledProcessError):
            raise RuntimeError("radare2 is not installed or the version is too low, v5.8.0+ is required.")

    def _create_script(self, commands: List[str], output_format: str) -> str:
        """
        生成r2批处理脚本
        :param commands: 要执行的r2命令列表
        :param output_format: 输出格式要求（json/text）
        """
        script = [
            "e scr.color=0",
            "e bin.demangle=true"
        ]

        # 自动添加输出格式控制
        if output_format == 'json':
            script.append("e cmd.json=true")
        elif output_format == 'text':
            script.append("e cmd.json=false")

        script += commands
        return '\n'.join(script)

    def execute(self, 
               file_path: str,
               commands: str,
               output_format: Literal['raw', 'json', 'text'] = 'raw',
               input_args: Optional[List[str]] = None) -> Union[str, dict]:
        """
        Execute radare2 commands and return structured results
        :param file_path: Path to the target file
        :param commands: r2 commands to execute (string or list)
        :param output_format: Return format requirements
        - raw: Raw output
        - json: Automatically parsed JSON
        - text: Cleaned text
        :param input_args: Command-line arguments passed to the program
        """
        # Parameter standardization.
        commands = "aaa;"+commands
        cmd_list = [commands] if isinstance(commands, str) else commands
        script = self._create_script(cmd_list, output_format)
        
        with tempfile.NamedTemporaryFile('w', delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            # Build execution command
            base_cmd = ['r2', '-e', 'bin.cache=true', '-q']
            if input_args:
                base_cmd += ['-d', '--']  # Debug mode allows passing parameters.
            else:
                base_cmd += []  # No execution mode.
            
            full_cmd = base_cmd + ['-i', script_path, file_path]
            if input_args:
                full_cmd += input_args

            result = subprocess.run(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=True
            )

            # Process the output.
            raw_output = result.stdout.decode('utf-8', errors='ignore')
            if commands == "aaa;aaa":
                raw_output = "success execute aaa"
            

            if output_format == 'json':
                return self._parse_json_output(raw_output)
            elif output_format == 'text':
                return self._clean_text_output(raw_output)
            
            return raw_output

        except subprocess.CalledProcessError as e:
            error_msg = f"Command execution failed: {e.stderr.decode()}"
            raise RuntimeError(error_msg)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Analysis timeout{self.timeout}second）")
        finally:
            os.remove(script_path)

    def _parse_json_output(self, raw: str) -> dict:
        """Intelligently parse mixed JSON output"""
        json_objects = []
        decoder = json.JSONDecoder()
        
        buffer = raw.strip()
        while buffer:
            try:
                obj, idx = decoder.raw_decode(buffer)
                json_objects.append(obj)
                buffer = buffer[idx:].lstrip()
            except json.JSONDecodeError:
                break
                
        if not json_objects:
            raise ValueError("No valid JSON data found.")
            
        # Merge multiple JSON objects
        if len(json_objects) == 1:
            return json_objects[0]
        return {'results': json_objects}

    def _clean_text_output(self, raw: str) -> str:
        """Clean text output."""
        lines = []
        for line in raw.split('\n'):
            # Filter r2 log messages.
            if line.startswith(('[0x', 'Cannot find', 'WARNING')):
                continue
            lines.append(line.strip())
        return '\n'.join(filter(None, lines))


''' 

# 使用示例
if __name__ == "__main__":
    r2 = R2(timeout=60)

   

    # 示例2：反汇编函数（文本）
    disasm = r2.execute(
        "code/vuln",
        commands="aaa;afl; pdf @sym.process_input",
        output_format='text'
    )
    print(disasm)  # 输出前500字符



    # 示例3：动态分析（带参数）
    try:
        dynamic = r2.execute(
            "./code/vuln_server",
            commands=["ood", "dc", "dr"],
            input_args=["test_input"],
            output_format='raw'
        )
        print("\n=== 寄存器状态 ===")
        print(dynamic)
    except Exception as e:
        print(f"动态分析失败: {str(e)}")
''' 