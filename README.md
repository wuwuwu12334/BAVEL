# BAVEL - Bandit-AST Vulnerability Enhanced with LLM

BAVEL 是一个自动化工具，旨在通过结合Bandit（静态代码分析工具）和抽象语法树（AST）分析，增强对Python代码中安全漏洞的检测能力，并利用大型语言模型（LLM）提供详细的漏洞分析和修复建议。

目录
功能
安装
使用方法
配置
贡献
许可证

功能
BAVEL工具提供了以下核心功能：

静态代码分析
使用Bandit对Python代码进行安全漏洞扫描，识别潜在的安全问题。
AST特征提取
通过分析代码的抽象语法树（AST），提取关键特征，例如函数调用、变量赋值和导入语句。
LLM增强分析
利用大型语言模型（如Spark API）对检测到的漏洞进行深入分析，提供详细的漏洞描述和修复建议。
报告生成
生成综合报告，包含漏洞详情、AST特征和LLM分析结果。


安装
依赖
Python 3.8 或更高版本
Bandit
OpenAI Python SDK
tqdm

安装步骤
克隆仓库
git clone https://github.com/yourusername/BAVEL.git
cd BAVEL

安装依赖
pip install -r requirements.txt

配置API密钥
获取Spark API的API密钥。
在config.py文件中设置你的API密钥，或在运行时通过命令行参数提供。

使用方法
1. 生成Bandit报告
使用Bandit扫描你的Python项目，生成JSON格式的报告：
bandit -r your_project_directory -f json -o bandit_report.json

2. 生成增强的AST报告
运行BAVEL工具，基于Bandit报告生成包含AST特征的增强报告：
python main.py --bandit-report bandit_report.json --output-dir reports

3. 生成LLM分析报告
使用生成的prompt文件调用LLM API，获取详细的漏洞分析结果：
python llm_analysis.py --prompts-file reports/file_based_prompts.json --output-file reports/llm_report.json --api-key your_api_key

配置
配置文件
BAVEL支持通过config.py文件进行配置。默认配置示例：
CONFIG = {
    "bandit_report_path": "bandit_report.json",
    "output_dir": "reports",
    "api_key": "your_api_key_here",
    "model": "lite"
}

参数说明
bandit_report_path：Bandit报告的输入路径。
output_dir：输出报告的保存目录。
api_key：Spark API的API密钥。
model：使用的LLM模型名称（如"lite"）。

贡献
欢迎为BAVEL工具做出贡献！以下是你可以参与的方式：

报告问题
在GitHub Issues中提交bug报告或功能请求。
提交Pull Request
Fork仓库，修改代码后提交Pull Request。
改进文档
帮助完善README.md或其他文档内容。
许可证
本项目采用MIT许可证。详情请见LICENSE文件。

