path = "V:/project/security-agent/src/common/config/settings.py"
content = open(path, "r", encoding="utf-8").read()

old = 'openai_api_key: str = ""\n    vllm_base_url'
new = 'openai_api_key: str = ""\n    openai_base_url: str = ""\n    openai_model: str = "gpt-4o"\n    vllm_base_url'

content = content.replace(old, new)
open(path, "w", encoding="utf-8").write(content)
print("settings.py updated")
