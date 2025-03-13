import ast
import json
import os
from collections import defaultdict
from typing import Dict, List, Union
from tqdm import tqdm

def extract_key_ast_features(code: str) -> Dict[str, List]:
    """
    提取代码的关键 AST 特征，用于增强 LLM 分析。
    """
    features = defaultdict(list)

    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                features["imports"].append(
                    {
                        "module": node.module,
                        "names": [{"name": n.name, "asname": n.asname} for n in node.names],
                        "line": node.lineno,
                    }
                )
            elif isinstance(node, ast.Import):
                features["imports"].append(
                    {
                        "names": [{"name": n.name, "asname": n.asname} for n in node.names],
                        "line": node.lineno,
                    }
                )
            elif isinstance(node, ast.Call):
                # 安全获取函数名称
                try:
                    func_name = ast.unparse(node.func)
                except:
                    func_name = "UnparsableFunction"

                # 提取参数信息
                args = [ast.unparse(arg) for arg in node.args]
                keywords = [
                    {"keyword": k.arg, "value": ast.unparse(k.value)}
                    for k in node.keywords
                    if k.arg  # 过滤无关键字的参数
                ]

                features["calls"].append({
                    "func": func_name,
                    "args": args,
                    "keywords": keywords,
                    "line": node.lineno,
                })
                
            elif isinstance(node, ast.Assign):
                # 提取赋值语句中的变量名
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        features["variables"].append(
                            {"name": target.id, "line": node.lineno}
                        )
            elif isinstance(node, ast.Constant):
                # 提取常量（包括字符串、数字、布尔值、None）
                features["constants"].append(
                    {
                        "type": type(node.value).__name__,
                        "value": node.value,
                        "line": node.lineno,
                    }
                )
    except SyntaxError as e:
        print(f"代码解析错误（AST）：{e}")

    return dict(features)

def generate_enhanced_ast_report(bandit_report_path: str, output_dir: str):
    """生成增强的AST报告，包含Bandit信息"""
    os.makedirs(output_dir, exist_ok=True)
    try:
        with open(bandit_report_path, 'r', encoding='utf-8') as f:
            bandit_report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"读取或解析Bandit报告失败: {e}")
        return

    if 'vulnerabilities' not in bandit_report:
        print("Bandit报告中缺少'vulnerabilities'字段。")
        return

    enhanced_report = {}
    for vulnerability in tqdm(bandit_report['vulnerabilities'], desc="生成增强AST报告"):
        file_path = vulnerability['file_path']
        if file_path not in enhanced_report:
            try:
                with open(file_path, 'r', encoding='utf-8') as code_file:
                    code = code_file.read()
                    ast_features = extract_key_ast_features(code)  # 提取AST特征
                    enhanced_report[file_path] = {
                        "vulnerabilities": [],
                        "ast_features": ast_features,  # 添加AST特征
                    }
            except FileNotFoundError:
                print(f"文件未找到: {file_path}")
                continue
            except UnicodeDecodeError:
                print(f"文件解码错误: {file_path}, 请检查文件编码")
                continue

        # 添加Bandit漏洞信息,简化处理
        enhanced_report[file_path]["vulnerabilities"].append({
            "line": vulnerability['line_number'],
            "test_id": vulnerability['test_id'],
            "test_name": vulnerability['test_name'],
            "severity": vulnerability['severity'],
            "confidence": vulnerability['confidence'],
            "context": vulnerability.get('code_snippet', "代码片段缺失")  # 简化处理
        })

    output_path = os.path.join(output_dir, "enhanced_ast_report.json")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(enhanced_report, f, indent=4, ensure_ascii=False)
        print(f"增强的AST报告已生成: {output_path}")
    except Exception as e:
        print(f"写入增强AST报告时出错: {e}")
def get_file_context(file_path: str, lines: List[int]) -> str:
    """获取文件的多处上下文"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code_lines = f.readlines()
    except Exception as e:
        return f"无法读取文件: {str(e)}"

    context = []
    for line_num in sorted(set(lines)):  # 去重并排序
        start = max(0, line_num - 3)
        end = min(len(code_lines), line_num + 2)
        context.append(f"===== 行号 {line_num} 上下文 =====")
        context.extend(f"{i+1}: {code_lines[i].strip()}" for i in range(start, end))
    
    return '\n'.join(context)

def build_file_based_prompts(bandit_report_path: str, output_dir: str) -> List[Dict]:
    """以文件为单位生成聚合prompt，包含格式示例"""
    os.makedirs(output_dir, exist_ok=True)
    
    
    try:
        with open(bandit_report_path, "r", encoding="utf-8") as f:
            bandit_data = json.load(f).get("vulnerabilities", [])
    except Exception as e:
        print(f"报告读取失败: {str(e)}")
        return []

    # 按文件分组漏洞
    file_vulns = defaultdict(list)
    for vuln in bandit_data:
        file_vulns[vuln["file_path"]].append(vuln)

    prompts = []
    for file_path, vulns in tqdm(file_vulns.items(), desc="处理文件"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code_content = f.read()
        except Exception as e:
            print(f"文件读取失败 {file_path}: {str(e)}")
            continue

        # 提取关键AST特征
        ast_features = extract_key_ast_features(code_content)
        
        # 收集漏洞信息
        vuln_info = []
        line_numbers = []
        for v in vulns:
            line_num = v["line_number"]
            line_numbers.append(line_num)
            vuln_info.append({
                "test_id": v["test_id"],
                "test_name": v["test_name"],
                "severity": v["severity"],
                "confidence": v["confidence"],
                "line_number": line_num
            })

        # 构建包含格式示例的system prompt
        system_prompt = (
        "您是一位资深代码安全审计专家，请分析以下文件中所有安全漏洞。注意：\n"
        "1. 对每个漏洞进行独立的分析。\n"
        "2. 为每个漏洞生成一个JSON对象，包含漏洞类型、严重程度、描述和建议。\n"
        "3. 输出一个JSON数组，数组中的每个元素对应一个漏洞的分析结果。\n\n"
        "输出格式要求：\n"
        "[\n"
        "  {\n"
        "    \"vulnerability_type\": \"漏洞类型（如 CWE-89: SQL注入）\",\n"
        "    \"severity\": \"严重程度（高危/中危/低危）\",\n"
        "    \"description\": \"漏洞描述，需指明具体行号和问题\",\n"
        "    \"recommendations\": [\n"
        "      {\"action\": \"具体修复建议\", \"priority\": \"紧急/高/中/低\"}\n"
        "    ],\n"
        "    \"confidence\": \"置信度（0-100的整数）\"\n"
        "  },\n"
        "  ...\n"
        "]\n\n"
        "示例：\n"
        "[\n"
        "  {\n"
        "    \"vulnerability_type\": \"CWE-89: SQL注入\",\n"
        "    \"severity\": \"高危\",\n"
        "    \"description\": \"在行38发现使用字符串拼接构造SQL语句\",\n"
        "    \"recommendations\": [\n"
        "      {\"action\": \"使用参数化查询\", \"priority\": \"紧急\"}\n"
        "    ],\n"
        "    \"confidence\": 95\n"
        "  },\n"
        "  {\n"
        "    \"vulnerability_type\": \"CWE-79: 跨站脚本\",\n"
        "    \"severity\": \"中危\",\n"
        "    \"description\": \"在行44发现未转义的用户输入\",\n"
        "    \"recommendations\": [\n"
        "      {\"action\": \"对用户输入进行转义\", \"priority\": \"高\"}\n"
        "    ],\n"
        "    \"confidence\": 80\n"
        "  }\n"
        "]"
    )

        # 构建单个文件的prompt
        prompt = [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": {
                    "file_path": file_path,
                    "vulnerabilities": vuln_info,
                    "code_context": get_file_context(file_path, line_numbers),
                    "key_ast_features": {
                        "sensitive_calls": ast_features.get("calls", []),
                        "sensitive_variables": ast_features.get("variables", [])
                    }
                }
            }
        ]
        prompts.append(prompt)

    # 保存聚合结果
    output_path = os.path.join(output_dir, "file_based_prompts.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(prompts, f, indent=2, ensure_ascii=False)
    
    print(f"生成完成，共处理 {len(prompts)} 个文件")
    return prompts
def validate_file_path(path: str) -> bool:
    """验证文件路径是否存在"""
    if not os.path.exists(path):
        print(f"\n错误：路径不存在 - {path}")
        return False
    if not path.lower().endswith('.json'):
        print(f"\n错误：仅支持JSON格式文件 - {path}")
        return False
    return True

def get_input_path(prompt: str) -> str:
    """获取并验证输入路径"""
    while True:
        path = input(prompt).strip('"').strip()  # 处理带引号的路径
        if validate_file_path(path):
            return path
        print("请重新输入有效路径（或按Ctrl+C退出）")
def main():
    print("=== 安全分析工具 ===")
    while True:
      print("\n请选择操作：")
      print("1. 生成增强的AST报告")
      print("2. 生成文件级分析Prompt")
      print("3. 两者都做")
      print("4. 退出")
      choice = input("请输入选项编号：")

      if choice == '4':
          break

      bandit_report_path = get_input_path("\n请输入Bandit报告文件路径（JSON格式）: ")
      output_dir = input("\n请输入输出目录（留空使用当前目录）: ").strip('"').strip()
      if not output_dir:
          output_dir = os.getcwd()
      os.makedirs(output_dir, exist_ok=True)
      print(f"输出将保存到：{os.path.abspath(output_dir)}")

      if choice in ('1', '3'):
        print("\n正在生成增强的AST报告...")
        generate_enhanced_ast_report(bandit_report_path, output_dir)

      if choice in ('2', '3'):
        print("\n正在生成文件级分析Prompt...")
        build_file_based_prompts(bandit_report_path, output_dir) # prompt 生成

if __name__ == "__main__":
    main()