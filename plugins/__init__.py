# OCTOPUS Plugin Directory
#
# Place custom tool modules here. Each .py file is auto-loaded on startup.
# Use the @tool() decorator to register your tools:
#
#   from core.tools.registry import tool
#
#   @tool("my_scanner", category="recon",
#         description="My custom scanner",
#         requires=["my_binary"])
#   def run_my_scanner(target, **kwargs):
#       import subprocess
#       result = subprocess.run(["my_binary", target], capture_output=True, text=True)
#       return result.stdout
#
# Tools are automatically available in the interactive menu and AI dispatch.
