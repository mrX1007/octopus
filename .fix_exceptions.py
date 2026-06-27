#!/usr/bin/env python3
"""
Fix swallowed exceptions across OCTOPUS codebase.

Replaces bare `except Exception:` + `pass` with logged versions.
Replaces `except Exception:` without any handler with logging.

Run: python3 fix_exceptions.py
"""

import re
import os

SKIP_DIRS = {"vendor", "venv", ".git", "tests", "__pycache__"}

# Pattern: bare except + pass (most common swallowed pattern)
# Match indented: except Exception:\n<indent>pass
BARE_EXCEPT_PASS = re.compile(
    r"([ \t]+)except Exception:\n\1    pass\n",
)

# Pattern: except Exception: with no 'as e' — needs variable binding  
BARE_EXCEPT_NO_VAR = re.compile(
    r"([ \t]+)except Exception:\n(\1    )(pass)\n",
)

FIX_COUNT = 0

def fix_file(filepath: str) -> int:
    """Fix swallowed exceptions in a single file. Returns count of fixes."""
    global FIX_COUNT
    
    with open(filepath, "r") as f:
        content = f.read()
    
    original = content
    fixes = 0
    
    # Get the module name for the logger
    module = filepath.replace("./", "").replace("/", ".").replace(".py", "")
    
    # Check if file already has logging import
    has_logging = "import logging" in content
    
    # Fix 1: `except Exception:` + `pass` → log + pass
    def replace_bare_pass(m):
        nonlocal fixes
        fixes += 1
        indent = m.group(1)
        return (
            f"{indent}except Exception as _exc:\n"
            f"{indent}    logging.debug(f\"Suppressed in {os.path.basename(filepath)}: {{_exc}}\")\n"
        )
    
    content = BARE_EXCEPT_PASS.sub(replace_bare_pass, content)
    
    # Fix 2: bare `except Exception:` without `as e` that does something
    # Convert to `except Exception as e:` to preserve error info
    def add_as_e(m):
        nonlocal fixes
        fixes += 1
        return m.group(0).replace("except Exception:", "except Exception as e:")
    
    # Only match `except Exception:` (no `as`)
    content = re.sub(
        r"except Exception:(\n[ \t]+(?!pass\b))",
        lambda m: f"except Exception as e:{m.group(1)}",
        content
    )
    
    if content != original:
        # Add logging import if missing
        if not has_logging and fixes > 0:
            # Add after first import line
            content = re.sub(
                r"(import \w+\n)",
                r"\1import logging\n",
                content,
                count=1
            )
        
        with open(filepath, "w") as f:
            f.write(content)
        
        FIX_COUNT += fixes
        print(f"  ✓ {filepath}: {fixes} exception(s) fixed")
    
    return fixes


def main():
    global FIX_COUNT
    
    target_files = []
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith(".py"):
                target_files.append(os.path.join(root, f))
    
    print(f"Scanning {len(target_files)} Python files...\n")
    
    for filepath in sorted(target_files):
        fix_file(filepath)
    
    print(f"\n{'='*50}")
    print(f"Total: {FIX_COUNT} swallowed exceptions fixed")


if __name__ == "__main__":
    main()
