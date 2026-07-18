"""Update adapter.py to support custom openai_base_url and openai_model."""
path = "V:/project/security-agent/src/knowledge/models/adapter.py"
content = open(path, "r", encoding="utf-8").read()

# Add openai_base_url and openai_model usage
old = """        elif self._provider == "openai":
            self._llm = ChatOpenAI(
                model="gpt-4o",
                api_key=settings.openai_api_key,
                temperature=0.1,
            )"""

new = """        elif self._provider == "openai":
            kwargs = {
                "model": settings.openai_model,
                "api_key": settings.openai_api_key,
                "temperature": 0.1,
            }
            if settings.openai_base_url:
                kwargs["base_url"] = settings.openai_base_url
            self._llm = ChatOpenAI(**kwargs)"""

if old in content:
    content = content.replace(old, new)
    open(path, "w", encoding="utf-8").write(content)
    print("adapter.py updated")
else:
    print("Could not find old text in adapter.py")
    # Debug: show the actual content around the relevant area
    idx = content.find('self._provider == "openai"')
    if idx >= 0:
        print(repr(content[idx:idx+250]))
