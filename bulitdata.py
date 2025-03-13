import os
import subprocess
import json
import random
import argparse
from tqdm import tqdm  # 用于显示进度条

def run_bandit(input_paths, bandit_config, output_file):
    """
    运行 Bandit 并将结果保存到 JSON 文件。
    现在可以接收文件列表
    """
    try:
        # Bandit 的 -r 参数可以接收目录，也可以接收文件。
        # 为了统一处理，如果 input_paths 是一个目录，我们就使用 -r
        # 如果 input_paths 是一个文件列表，我们就逐个文件运行 Bandit
        if isinstance(input_paths, str) and os.path.isdir(input_paths):
             command = [
                "bandit",
                "-c", bandit_config,
                "-f", "json",
                "-o", output_file,
                "-r", input_paths, # 如果是目录，使用 -r
                "-ll",
                "-ii",
            ]
             subprocess.run(command, check=True, text=True, capture_output=True)
        else: # 假设是文件列表
            # 逐个文件运行 Bandit
            all_results = {"results": []}  # 用于存储所有文件的结果
            for file_path in tqdm(input_paths, desc="Scanning files with Bandit"):
                command = [
                    "bandit",
                    "-c", bandit_config,
                    "-f", "json",
                    "-ll",
                    "-ii",
                    file_path,  # 直接传入文件路径
                ]

                try:
                    result = subprocess.run(command, capture_output=True, text=True, check=True)
                    # 解析每个文件的 JSON 输出，并添加到 all_results 中
                    bandit_output = json.loads(result.stdout)
                    all_results["results"].extend(bandit_output["results"])
                except subprocess.CalledProcessError as e:
                    print(f"Bandit 运行出错 (文件: {file_path}): {e}")
                    print(e.stderr)
                except json.JSONDecodeError as e:
                     print(f"Bandit 输出解析出错(文件:{file_path}): {e}")

            # 将所有结果写入到总的输出文件
            with open(output_file, "w") as f:
                json.dump(all_results, f, indent=4)

        print(f"Bandit 扫描完成，结果已保存到 {output_file}")

    except subprocess.CalledProcessError as e:
        print(f"Bandit 运行出错：{e}")
        print(e.stderr)
        return False
    return True

def parse_bandit_output(output_file):
    """解析 Bandit 的 JSON 输出，提取文件路径和漏洞信息。"""
    vulnerable_files = set()
    try:
        with open(output_file, "r") as f:
            bandit_results = json.load(f)
            for issue in bandit_results["results"]:
                file_path = issue["filename"]
                vulnerable_files.add(file_path)

    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"解析 Bandit 输出文件出错：{e}")
    return list(vulnerable_files)

def get_all_python_files(base_path, file_list_files):
    """从 Py150K 的文件列表文件中获取所有 Python 文件路径。"""
    all_files = []
    for file_list_file in file_list_files:
        file_list_path = os.path.join(base_path, file_list_file)
        try:
            with open(file_list_path, "r") as f:
                for line in f:
                    file_path = line.strip()
                    # 直接拼接完整路径
                    full_path = os.path.join(base_path, file_path)
                    if os.path.exists(full_path):
                        all_files.append(full_path)
        except FileNotFoundError:
            print(f"警告：文件列表文件 {file_list_path} 未找到。")
    return all_files

def select_files(file_paths, num_files):
    """从文件路径列表中随机选择指定数量的文件, 如果不足则返回所有"""
    if len(file_paths) <= num_files:
        return file_paths
    else:
        return random.sample(file_paths, num_files)

def main():
    parser = argparse.ArgumentParser(description="从 Py150K 数据集中筛选有漏洞和无漏洞的 Python 文件。")
    parser.add_argument("py150k_path", help="Py150K 数据集的根目录")
    parser.add_argument("-c", "--config", default="bandit.yaml", help="Bandit 配置文件路径 (默认为 bandit.yaml)")
    parser.add_argument("-o", "--output", default="bandit_output.json", help="Bandit 输出文件路径 (默认为 bandit_output.json)")
    parser.add_argument("-v", "--vulnerable", default="vulnerable_files.txt", help="有漏洞文件列表保存路径 (默认为 vulnerable_files.txt)")
    parser.add_argument("-n", "--non-vulnerable", default="non_vulnerable_files.txt", help="无漏洞文件列表保存路径 (默认为 non_vulnerable_files.txt)")
    parser.add_argument("-vn", "--vulnerable-num", type=int, default=600, help="要选择的有漏洞文件数量 (默认为 600)")
    parser.add_argument("-nn", "--non-vulnerable-num", type=int, default=500, help="要选择的无漏洞文件数量 (默认为 500)")
    parser.add_argument("--sample-ratio", type=float, default=1.0, help="对 Py150K 文件列表进行采样的比例 (默认为 1.0, 即不采样)")
    args = parser.parse_args()

    # 1. 获取 Py150K/Py50k 数据集中所有 Python 文件的路径
    py150k_files = get_all_python_files(args.py150k_path, ["python100k_train.txt", "python50k_eval.txt"])

    # 1.1 (可选) 对文件列表进行采样
    if args.sample_ratio < 1.0:
        num_samples = int(len(py150k_files) * args.sample_ratio)
        py150k_files = random.sample(py150k_files, num_samples)
        print(f"已对 Py150K 文件列表进行采样，采样数量：{num_samples}")

    # 2. 使用 Bandit 进行批量检测
    if not os.path.exists(args.output):
        run_bandit(py150k_files, args.config, args.output) # 直接传入文件列表

    # 3. 解析 Bandit 结果
    vulnerable_files = parse_bandit_output(args.output)

    # 4. 划分数据集
    non_vulnerable_files = list(set(py150k_files) - set(vulnerable_files))

    # 5. 选择指定数量的文件
    selected_vulnerable_files = select_files(vulnerable_files, args.vulnerable_num)
    selected_non_vulnerable_files = select_files(non_vulnerable_files, args.non_vulnerable_num)

    # 6. 保存文件路径列表
    with open(args.vulnerable, "w") as f:
        for file_path in selected_vulnerable_files:
            f.write(file_path + "\n")
    print(f"已选择 {len(selected_vulnerable_files)} 个有漏洞的文件路径，保存到 {args.vulnerable}")

    with open(args.non_vulnerable, "w") as f:
        for file_path in selected_non_vulnerable_files:
            f.write(file_path + "\n")
    print(f"已选择 {len(selected_non_vulnerable_files)} 个无漏洞的文件路径，保存到 {args.non_vulnerable}")

if __name__ == "__main__":
    main()