"""Fix BOM, typo, and config for tests."""
import os

# 1. Fix BOM on all test files
for root, _dirs, files in os.walk("tests"):
    for f in files:
        if f.endswith(".py"):
            path = os.path.join(root, f)
            with open(path, "r", encoding="utf-8-sig") as fh:
                content = fh.read()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)

# 2. Fix ClassTestURLExtraction typo
path = "tests/unit/preprocessing/test_ioc_extractor.py"
content = open(path, "r", encoding="utf-8").read()
content = content.replace("ClassTestURLExtraction:", "class TestURLExtraction:")
open(path, "w", encoding="utf-8").write(content)
print("Fixed typo")

# 3. Add asyncio config to pyproject.toml
pp_path = "pyproject.toml"
pp = open(pp_path, "r", encoding="utf-8").read()
if "asyncio_default_fixture_loop_scope" not in pp:
    marker = "[tool.pytest.ini_options]"
    old = marker
    new = marker + '\nasyncio_default_fixture_loop_scope = "function"'
    pp = pp.replace(old, new, 1)
    open(pp_path, "w", encoding="utf-8").write(pp)
    print("Added asyncio config")
else:
    print("asyncio config already present")

print("Done!")
