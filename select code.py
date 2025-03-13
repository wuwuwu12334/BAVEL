import os
import random

def select_random_paths(file_list_txt, num_paths, output_file=None):
    """
    从 txt 文件中随机挑选指定数量的路径。
    
    Args:
        file_list_txt (str): 包含路径的 txt 文件路径。
        num_paths (int): 要随机挑选的路径数量。
        output_file (str, optional): 如果提供，则将结果保存到该文件。
    
    Returns:
        list: 随机挑选出的路径列表。
    """
    # 读取 txt 文件中的路径
    try:
        with open(file_list_txt, "r", encoding="utf-8") as f:
            all_paths = [line.strip() for line in f if line.strip()]  # 忽略空行
    except FileNotFoundError:
        print(f"错误：文件 {file_list_txt} 未找到。")
        return []
    except Exception as e:
        print(f"读取文件时发生错误：{e}")
        return []

    if not all_paths:
        print("错误：txt 文件中没有有效的路径。")
        return []

    total_paths = len(all_paths)
    if num_paths >= total_paths:
        print(f"警告：请求的路径数量 ({num_paths}) 超过文件中的路径总数 ({total_paths})，返回所有路径。")
        selected_paths = all_paths
    else:
        # 随机挑选指定数量的路径
        selected_paths = random.sample(all_paths, num_paths)

    # 转换为绝对路径并过滤不存在的路径
    valid_paths = [os.path.abspath(path) for path in selected_paths if os.path.exists(path)]
    invalid_count = len(selected_paths) - len(valid_paths)

    # 输出最终结果
    print(f"从 {total_paths} 个路径中随机挑选了 {len(selected_paths)} 个路径，其中 {len(valid_paths)} 个有效。")
    if invalid_count > 0:
        print(f"注意：{invalid_count} 个路径不存在，已被过滤。")

    # 如果指定了输出文件，则保存结果
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for path in valid_paths:
                    f.write(f"{path}\n")
            print(f"结果已保存到文件：{output_file}")
        except Exception as e:
            print(f"保存文件时发生错误：{e}")

    return valid_paths

def main():
    # 配置
    file_list_txt = r"F:\qqprofile\BAVEL\py150_files\python50k_eval.txt"  # 输入的 txt 文件
    num_paths = 2000  # 默认挑选 10 个路径，可根据需要修改
    output_file = "selected_paths.txt"  # 输出文件（可选），设为 None 则不保存

    # 运行随机挑选函数
    selected_paths = select_random_paths(file_list_txt, num_paths, output_file)

    # 输出最终结果
    if selected_paths:
        print(f"成功挑选 {len(selected_paths)} 个有效路径。")

if __name__ == "__main__":
    main()