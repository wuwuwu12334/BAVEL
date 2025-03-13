import subprocess
import json
import os
import logging
import sys
from tqdm import tqdm
import matplotlib.pyplot as plt
import ast

# 配置日志 (使用StreamHandler,更适合tqdm)
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
)
log = logging.getLogger()  # 获取logger
for h in log.handlers[:]:  # 移除之前的handlers
    log.removeHandler(h)
log.addHandler(logging.StreamHandler(sys.stdout)) # 添加新的handler

def run_bandit(file_path, bandit_config="bandit.yaml", output_format="json",
              severity_level="low", confidence_level="low"):
    """运行Bandit扫描并返回结果"""
    if not os.path.exists(file_path):
        logging.error(f"文件未找到: {file_path}")
        return {
            "errors": [{"filename": file_path, "reason": "File not found"}],
            "results": [],
            "metrics": {}
        }

    command = [
        "bandit",
        "-c", bandit_config,
        "-f", output_format,
        "-o", "-",
        f"--severity-level={severity_level}",
        f"--confidence-level={confidence_level}",
        file_path
    ]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output = []
        while True:
            line = process.stdout.readline()
            if not line:
                break
            output.append(line)

        return_code = process.wait()
        stderr_output = process.stderr.read()
        full_output = "".join(output)

        if return_code not in [0, 1]:
            logging.error(f"Bandit运行出错 (文件: {file_path}, 状态码: {return_code})")
            return {
                "errors": [{"filename": file_path, "reason": f"Bandit返回状态码{return_code}"}],
                "results": [],
                "metrics": {}
            }

        try:
            parsed_output = json.loads(full_output)
            # 统一Bandit的输出格式: 无论是否发现漏洞,都保证有results键
            if "results" not in parsed_output:
                parsed_output["results"] = []
            if "errors" not in parsed_output:  # Bandit本身可能有errors字段
                parsed_output["errors"] = []
            return parsed_output

        except json.JSONDecodeError:
            logging.error(f"Bandit输出解析失败:\n{full_output}")
            return {
                "errors": [{"filename": file_path, "reason": "Bandit返回无效JSON"}],
                "results": [],
                "metrics": {}
            }

    except FileNotFoundError:
        logging.error("Bandit未找到，请检查安装")
        return {
            "errors": [{"filename": file_path, "reason": "Bandit命令未找到"}],
            "results": [],
            "metrics": {}
        }
    except Exception as e:
        logging.error(f"未知错误: {e}")
        return {
            "errors": [{"filename": file_path, "reason": f"未知错误: {e}"}],
            "results": [],
            "metrics": {}
        }

def generate_report(results, output_file, output_format="json"):
    """生成汇总报告"""
    final_results = {
        "metadata": {
            "scanned_files": len(results),
            "generated_at": "",
            "report_version": "1.1"
        },
        "vulnerabilities": [],
        "metrics": {
            "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_confidence": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }
    }

    for file_path, bandit_output in results.items():
        if not bandit_output or "results" not in bandit_output:
            continue

        for result in bandit_output["results"]:
            vuln_entry = {
                "file_path": file_path,
                "test_id": result["test_id"],
                "test_name": result["test_name"],
                "severity": result["issue_severity"],
                "confidence": result["issue_confidence"],
                "line_number": result["line_number"],
                "code_snippet": result["code"]
            }
            final_results["vulnerabilities"].append(vuln_entry)

            # 更新指标
            final_results["metrics"]["by_severity"][vuln_entry["severity"]] += 1
            final_results["metrics"]["by_confidence"][vuln_entry["confidence"]] += 1

    if results:
        first_file = list(results.keys())[0]
        final_results["metadata"]["generated_at"] = results[first_file].get("generated_at", "")

    if output_format == "json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_results, f, indent=2, ensure_ascii=False)

    logging.info(f"报告已生成: {output_file}")
    return final_results

def generate_histogram(final_results, output_dir):
    """生成置信度分布图"""
    plt.rcParams['font.sans-serif'] = ['SimHei']  # 解决中文显示问题
    plt.rcParams['axes.unicode_minus'] = False

    # 准备数据
    conf_levels = ["HIGH", "MEDIUM", "LOW"]
    counts = [final_results["metrics"]["by_confidence"][l] for l in conf_levels]

    # 绘制图表
    plt.figure(figsize=(10, 6))
    bars = plt.bar(conf_levels, counts, color=['#ff6666', '#ffcc66', '#66cc99'])

    # 添加数值标签
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height}', ha='center', va='bottom')

    plt.xlabel("置信度等级", fontsize=12)
    plt.ylabel("漏洞数量", fontsize=12)
    plt.title("漏洞置信度分布", fontsize=14, pad=20)
    plt.xticks(fontsize=10)
    plt.yticks(fontsize=10)

    # 保存文件
    output_path = os.path.join(output_dir, "confidence_distribution.png")
    plt.savefig(output_path, bbox_inches='tight', dpi=300)
    plt.close()
    logging.info(f"图表已保存: {output_path}")

def analyze_ast_node(node):
    """
    分析单个AST节点，提取关键信息。
    """
    if node is None:
        return None

    node_type = type(node).__name__
    result = {"type": node_type}

    if isinstance(node, ast.Call):
        result["function"] = get_full_identifier(node.func)
        result["args"] = [analyze_ast_node(arg) for arg in node.args]
    elif isinstance(node, ast.Name):
        result["name"] = node.id
    elif isinstance(node, ast.Constant):
        result["value"] = node.value
    elif isinstance(node, ast.Attribute):
         result["value"] = get_full_identifier(node)
    elif isinstance(node, ast.Assign):
        result["targets"] = [analyze_ast_node(target) for target in node.targets]
        result["value"] = analyze_ast_node(node.value)
    elif isinstance(node, (ast.List, ast.Tuple)):
        result["elements"] = [analyze_ast_node(elt) for elt in node.elts]
    # 可以根据需要添加更多节点类型的处理

    return {k: v for k, v in result.items() if v is not None and k != "ctx"}

def get_full_identifier(node):
    """
    获取函数或变量的全限定名。
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return f"{get_full_identifier(node.value)}.{node.attr}"
    else:
        return "Unknown"
def extract_code_context(file_path, line_number, context_lines=3):
    """
    提取代码上下文（漏洞所在行及前后几行）。
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            start_line = max(0, line_number - context_lines -1)
            end_line = min(len(lines), line_number + context_lines)
            context = ''.join(lines[start_line:end_line])
            return context
    except Exception as e:
        return f"Error reading file: {e}"

def simplify_ast(tree, bandit_result):
    """
    根据Bandit结果简化AST。
    """

    simplified_nodes = []

    # 查找与Bandit结果相关的AST节点
    for node in ast.walk(tree):
        if (hasattr(node, 'lineno') and node.lineno == bandit_result['line_number']):
                # 核心节点
                core_node = analyze_ast_node(node)
                if core_node:
                    simplified_nodes.append({"type": "CoreNode", "info": core_node})

    return simplified_nodes

def process_vulnerabilities(results, output_dir):
    """处理漏洞，生成AST报告。"""
    ast_report = {}

    for file_path, bandit_data in results.items():
        if not bandit_data or "results" not in bandit_data:
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source_code = f.read()
            tree = ast.parse(source_code)
        except Exception as e:
            ast_report[file_path] = {"error": str(e)}
            continue

        file_entries = []
        for vuln in bandit_data["results"]:
            simplified_ast = simplify_ast(tree, vuln)  # 简化AST

            if simplified_ast:
                entry = {
                    "test_id": vuln["test_id"],
                    "line": vuln["line_number"],
                    "severity": vuln["issue_severity"],
                    "ast_info": simplified_ast,  # 包含简化后的AST
                    "context": extract_code_context(file_path, vuln["line_number"]),
                }
                file_entries.append(entry)

        if file_entries:
            ast_report[file_path] = file_entries

    # 保存AST报告
    output_path = os.path.join(output_dir, "ast_analysis.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ast_report, f, indent=2, ensure_ascii=False)

    logging.info(f"AST分析报告已保存: {output_path}")
    return output_path

def main():
    # 配置参数
    file_list_txt = r"F:\qqprofile\BAVEL\py150_files\sourcecode.txt"
    output_dir = "security_report"
    bandit_config = "bandit.yaml"
    vulnerable_files_txt = os.path.join(output_dir, "vulnerable_files.txt")  # 保存有漏洞文件路径

    # 初始化输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    if not os.path.isdir(output_dir):  # 显式检查
        logging.error(f"无法创建输出目录: {output_dir}")
        return  # 如果目录创建失败，直接退出

    # 读取文件列表
    try:
        with open(file_list_txt, "r") as f:
            file_paths = [os.path.abspath(l.strip()) for l in f if l.strip()]
    except FileNotFoundError:
        logging.error(f"文件列表不存在: {file_list_txt}")
        return

    # 运行Bandit扫描
    results = {}
    total_files = len(file_paths)
    successful_scans = 0
    vulnerable_files = set()

    with tqdm(file_paths, desc="扫描进度", unit="文件", ncols=80) as pbar:
        for fp in pbar:
            result = run_bandit(fp, bandit_config)
            if result:
                # 统一逻辑：无论是否有错误、是否有漏洞，都添加到results
                results[fp] = result

                # 检查是否有errors, 没有errors才算成功
                if "errors" not in result or not result["errors"]:
                     successful_scans += 1

                     # 如果有results, 并且results列表不为空，则表示有漏洞
                     if result.get("results"):
                        vulnerable_files.add(fp)

    # 生成主报告
    report_path = os.path.join(output_dir, "security_report.json")
    final_report = generate_report(results, report_path)

    # 生成可视化图表
    generate_histogram(final_report, output_dir)

    # 处理AST分析
    process_vulnerabilities(results, output_dir)

     # 保存有漏洞的文件路径列表
    with open(vulnerable_files_txt, "w", encoding="utf-8") as f:
        for file_path in vulnerable_files:
            f.write(file_path + "\n")
    logging.info(f"有漏洞的文件列表已保存: {vulnerable_files_txt}")

    # 统计并打印信息
    logging.info("分析完成，结果保存在: %s", os.path.abspath(output_dir))
    logging.info(f"总文件数: {total_files}")
    logging.info(f"成功扫描的文件数: {successful_scans}")  # 真正成功扫描的
    logging.info(f"检测到漏洞的文件数: {len(vulnerable_files)}")

if __name__ == "__main__":
    main()