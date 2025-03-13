import chardet
def detect_encoding(file_path):
    with open(file_path, 'rb') as f:  # 以二进制模式打开
        result = chardet.detect(f.read())
        return result['encoding']

file_path = r"F:\qqprofile\BAVEL\py150_files\security_report\prompt_report\prompts.json"  # 替换为您的文件路径
encoding = detect_encoding(file_path)
print(f"文件 '{file_path}' 的编码可能是: {encoding}")