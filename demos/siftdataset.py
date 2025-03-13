import os
import random

def sample_file_paths(dataset_root, num_samples=1000):
    """
    从 Py150k 数据集中随机采样指定数量的文件路径。

    Args:
        dataset_root: Py150k 数据集的根目录。
        num_samples: 要采样的文件数量，默认为 1000。

    Returns:
        一个列表，包含随机采样的文件路径。
    """

    all_file_paths = []

    # 遍历数据集目录，获取所有 .py 文件的路径
    for root, _, files in os.walk(dataset_root):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                all_file_paths.append(file_path)

    # 检查文件总数是否足够
    if len(all_file_paths) < num_samples:
        raise ValueError(
            f"Py150k 数据集中少于 {num_samples} 个 .py 文件。"
            f" 找到 {len(all_file_paths)} 个文件。"
        )

    # 随机采样
    sampled_file_paths = random.sample(all_file_paths, num_samples)

    return sampled_file_paths

# 示例用法 (请将 'path/to/py150k' 替换为您的 Py150k 数据集根目录)
dataset_root = r"F:\qqprofile\BAVEL\py150_files\python100k_train.txt"
try:
    sampled_paths = sample_file_paths(dataset_root, num_samples=1000)
    # 打印采样到的文件路径
    for path in sampled_paths:
        print(path)

    # 将采样到的文件路径保存到文件 (可选)
    with open("sampled_file_paths.txt", "w") as f:
        for path in sampled_paths:
            f.write(path + "\n")

except ValueError as e:
    print(f"错误: {e}")