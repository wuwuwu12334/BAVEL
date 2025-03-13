import json
import os
from tqdm import tqdm
from openai import OpenAI
from typing import List, Dict

class MoonshotAPIClient:
    def __init__(self, api_key: str, base_url: str = "https://api.moonshot.cn/v1"):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )
        self.model = "moonshot-v1-128k"  # 可选 moonshot-v1-128k
    
    def create_completion(self, messages: List[Dict], temperature: float = 0.3) -> Dict:
        """创建对话补全"""
        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature
            )
            return {
                "id": completion.id,
                "model": completion.model,
                "content": completion.choices[0].message.content
            }
        except Exception as e:
            print(f"API调用失败: {str(e)}")
            return None

def process_prompts(prompts_file: str, output_dir: str, api_key: str):
    # 初始化客户端
    moonshot_client = MoonshotAPIClient(api_key=api_key)
    
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    
    # 加载prompts文件
    try:
        with open(prompts_file, "r", encoding="utf-8") as f:
            prompts = json.load(f)
    except Exception as e:
        print(f"加载prompts文件失败: {str(e)}")
        return

    if not isinstance(prompts, list):
        print("错误：prompts文件内容应为列表格式")
        return

    # 处理进度条
    with tqdm(total=len(prompts), desc="处理Prompts", unit="个") as pbar:
        for idx, prompt_pair in enumerate(prompts, 1):
            # 验证prompt格式
            if not validate_prompt_format(prompt_pair):
                print(f"跳过第{idx}个prompt - 格式无效")
                pbar.update(1)
                continue
            
            # 构造消息列表（保持原有格式）
            messages = [
                {"role": "system", "content": prompt_pair[0]["content"]},
                {"role": "user", "content": json.dumps(prompt_pair[1]["content"], ensure_ascii=False)}
            ]
            
            # 调用API
            response = moonshot_client.create_completion(messages)
            
            # 处理结果
            if response:
                save_result(response, output_dir, idx)
            else:
                print(f"第{idx}个prompt调用失败")
            
            pbar.update(1)

def validate_prompt_format(prompt_pair: List) -> bool:
    """验证prompt格式有效性"""
    return (
        isinstance(prompt_pair, list) 
        and len(prompt_pair) == 2
        and prompt_pair[0].get("role") == "system"
        and isinstance(prompt_pair[0].get("content"), str)
        and prompt_pair[1].get("role") == "user"
        and isinstance(prompt_pair[1].get("content"), (str, dict))
    )

def save_result(response: Dict, output_dir: str, index: int):
    """保存API响应结果"""
    try:
        filename = f"result_{index}.json"
        output_path = os.path.join(output_dir, filename)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(response, f, indent=2, ensure_ascii=False)
        print(f"结果已保存至: {output_path}")
    except Exception as e:
        print(f"保存结果失败: {str(e)}")

if __name__ == "__main__":
    # 配置参数（使用Moonshot的API Key）
    CONFIG = {
        "prompts_file": r"F:\qqprofile\BAVEL\py150_files\security_report\prompt_report\prompts.json",
        "output_dir": r"F:\qqprofile\BAVEL\py150_files\security_report\llm_report",
        "api_key": "sk-rwOkof41kwTSGQ1k4mKQQYB9KES3yE4HUSwfwopetjbZBM9Y"  # 从Moonshot控制台获取
    }
    
    process_prompts(**CONFIG)