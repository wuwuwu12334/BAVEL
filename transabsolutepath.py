import os

def convert_to_absolute_paths(input_file, output_file, base_dir):
    """
    将文本文件中的相对路径转换为绝对路径。

    Args:
        input_file:  包含相对路径的输入文件路径。
        output_file: 保存绝对路径的输出文件路径。
        base_dir:    相对路径的基准目录。
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            relative_paths = [line.strip() for line in infile]  # 读取所有行，去除首尾空白
    except FileNotFoundError:
        print(f"错误：输入文件 '{input_file}' 未找到。")
        return
    except UnicodeDecodeError:
        print(f"错误: 输入文件 '{input_file}' 编码错误, 请使用UTF-8编码")
        return

    absolute_paths = []
    for rel_path in relative_paths:
        # 转换为绝对路径
        abs_path = os.path.abspath(os.path.join(base_dir, rel_path))
        absolute_paths.append(abs_path)

    try:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            for abs_path in absolute_paths:
                outfile.write(abs_path + '\n')  # 写入绝对路径，每行一个
        print(f"已将路径转换为绝对路径，并保存到 '{output_file}'")
    except Exception as e:
        print(f"写入输出文件时出错：{e}")

def main():
    input_file = 'sampled_paths.txt'  # 输入文件名
    output_file = 'absolute_paths.txt'  # 输出文件名
    base_dir = r'F:\qqprofile\BAVEL\py150_files'  # 相对路径的基准目录

    convert_to_absolute_paths(input_file, output_file, base_dir)

if __name__ == "__main__":
    main()