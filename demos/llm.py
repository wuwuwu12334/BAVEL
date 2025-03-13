import json
import os
import re
from tqdm import tqdm
from openai import OpenAI
from typing import List, Dict

class SparkAPIClient:
    def __init__(self, api_key: str, base_url: str = "https://spark-api-open.xf-yun.com/v1"):
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )
        self.model = "lite"

    def create_completion(self, messages: List[Dict]) -> Dict:
        """创建带格式校验的API请求"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.3,
                max_tokens=1500,
                response_format={"type": "json_object"}
            )
            
            content = response.choices[0].message.content
            cleaned_content = self._clean_response(content)  # 清理标记
            if not self._validate_response(cleaned_content):
                raise ValueError("响应格式验证失败")
                
            return {
                "status": "success",
                "content": json.loads(cleaned_content),
                "raw_response": content  # 保留原始响应以便调试
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "raw_response": content if 'content' in locals() else None
            }

    def _clean_response(self, content: str) -> str:
        """清理响应中的 ```json 和 ``` 标记"""
        content = content.strip()
        if content.startswith("```json"):
            content = content[7:]  # 移除 ```json
        if content.endswith("```"):
            content = content[:-3]  # 移除 ```
        return content.strip()

    def _validate_response(self, content: str) -> bool:
        """验证响应是否包含必要字段"""
        try:
            data = json.loads(content)
            # 根据你期望的格式调整必要字段
            return all(key in data for key in ["vulnerability_type", "severity", "description", "recommendations"])
        except:
            return False

def process_prompts(prompts_file: str, output_file: str, api_key: str):
    """处理所有prompts并生成合并报告"""
    spark_client = SparkAPIClient(api_key=api_key)
    consolidated = []

    try:
        with open(prompts_file, "r", encoding="utf-8") as f:
            prompts = json.load(f)

        valid_count = 0
        with tqdm(total=len(prompts), desc="分析进度", unit="个") as pbar:
            for idx, prompt_pair in enumerate(prompts, 1):
                if not validate_prompt_format(prompt_pair):
                    print(f"\n跳过无效prompt #{idx}")
                    pbar.update(1)
                    continue
                
                # 构造请求消息
                messages = [
                    {
                        "role": "system",
                        "content": f"{prompt_pair[0]['content']}\n请严格使用JSON格式，包含以下字段：vulnerability_type, severity, description, recommendations"
                    },
                    {
                        "role": "user",
                        "content": json.dumps({
                            "file_info": prompt_pair[1]["content"]["file_path"],
                            "vulnerabilities": [
                                f"{v['test_id']}-{v['line_number']}" 
                                for v in prompt_pair[1]["content"]["vulnerabilities"]
                            ],
                            "code_snippets": prompt_pair[1]["content"]["code_context"]
                        }, ensure_ascii=False)
                    }
                ]
                
                # 调用API
                response = spark_client.create_completion(messages)
                
                # 记录结果
                consolidated.append({
                    "file_path": prompt_pair[1]["content"]["file_path"],
                    "vulnerabilities": prompt_pair[1]["content"]["vulnerabilities"],
                    "analysis": response
                })
                valid_count += 1
                pbar.update(1)

        # 保存最终报告
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump({
                "statistics": {
                    "total_prompts": len(prompts),
                    "valid_prompts": valid_count,
                    "success_rate": f"{(valid_count/len(prompts))*100:.1f}%"
                },
                "results": consolidated
            }, f, indent=2, ensure_ascii=False)

        print(f"\n✅ 成功处理 {valid_count}/{len(prompts)} 个prompt")
        print(f"📄 报告已保存至：{os.path.abspath(output_file)}")

    except Exception as e:
        print(f"\n❌ 处理失败：{str(e)}")

def validate_prompt_format(prompt_pair: List) -> bool:
    """增强的prompt格式验证"""
    try:
        # 基础结构验证
        if not isinstance(prompt_pair, list) or len(prompt_pair) != 2:
            return False
        
        # 角色验证
        if prompt_pair[0].get("role") != "system" or prompt_pair[1].get("role") != "user":
            return False
        
        # 内容结构验证
        user_content = prompt_pair[1].get("content", {})
        if not isinstance(user_content, dict):
            return False
        
        # 必要字段验证
        required_fields = ["file_path", "vulnerabilities", "code_context"]
        if not all(field in user_content for field in required_fields):
            return False
        
        # 漏洞条目验证
        for vuln in user_content["vulnerabilities"]:
            if not isinstance(vuln, dict) or "line_number" not in vuln:
                return False
        
        return True

    except (KeyError, TypeError):
        return False

if __name__ == "__main__":
    # 配置参数
    CONFIG = {
        "prompts_file": r"F:\qqprofile\BAVEL\py150_files\security_report\prompt_report\file_based_prompts.json",
        "output_file": r"F:\qqprofile\BAVEL\py150_files\security_report\llm_report\consolidated_report.json",
        "api_key": "kIMgPrepVzGlpgTpGZua:lmpNuZUmvnIzhqbERzho"
    }
    
    process_prompts(**CONFIG)