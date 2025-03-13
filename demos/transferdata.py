def replace_path_prefix(input_file, output_file, old_prefix, new_prefix):
    """
    替换文件中文件路径的前缀。

    Args:
        input_file: 包含原始文件路径的文本文件。
        output_file: 保存修改后文件路径的文本文件。
        old_prefix: 要替换的旧前缀。
        new_prefix: 要替换成的新前缀。
    """
    try:
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
            for line in infile:
                # 去除行尾的换行符，并进行前缀替换
                modified_path = line.strip().replace(old_prefix, new_prefix, 1)  # 1 表示只替换第一个匹配项
                outfile.write(modified_path + '\n')  # 写回文件，并添加换行符
        print(f"路径前缀替换完成：{input_file} -> {output_file}")

    except FileNotFoundError:
        print(f"错误：文件未找到 - {input_file}")
    except Exception as e:
        print(f"发生错误：{e}")

if __name__ == "__main__":
    # 示例用法：
    input_txt_file = r"F:\qqprofile\BAVEL\py150_files\transfer_output.txt"  # 替换为您的输入文件路径
    output_txt_file = r"F:\qqprofile\BAVEL\py150_files\sourcecode.txt"  # 替换为您希望的输出文件路径
    old_prefix = r"F:\qqprofile\BAVEL\py150_files"  # 注意这里的反斜杠需要转义
    new_prefix = r"F:\qqprofile\BAVEL\py150_files\data" # 注意这里的反斜杠

    replace_path_prefix(input_txt_file, output_txt_file, old_prefix, new_prefix)