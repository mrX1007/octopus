#!/usr/bin/env python3

import re
import os
import sys
import time
import json
import logging
import requests

# ─────────────────────────────────────────────
# CONFIG CONSTANTS
# ─────────────────────────────────────────────

OLLAMA_URL     = "http://localhost:11434/api/generate"
MODEL_NAME     = "octopus-qwen"
MAX_TOKENS     = 4096
MAX_TOOL_LOOPS = 20
OLLAMA_TIMEOUT = 180        # 
OLLAMA_RETRIES = 2          # 
CONTEXT_WINDOW = 6
SUMMARIZE_THRESHOLD = 8000
CONCURRENT_TOOLS = 8

# Load from config.yaml if available
try:
    from config import CFG
    _oc = CFG.get("ollama", {})
    OLLAMA_URL     = _oc.get("url", OLLAMA_URL)
    MODEL_NAME     = _oc.get("model", MODEL_NAME)
    MAX_TOKENS     = _oc.get("max_tokens", MAX_TOKENS)
    MAX_TOOL_LOOPS = _oc.get("max_tool_loops", MAX_TOOL_LOOPS)
    OLLAMA_TIMEOUT = _oc.get("timeout", OLLAMA_TIMEOUT)
    OLLAMA_RETRIES = _oc.get("retries", OLLAMA_RETRIES)
    CONTEXT_WINDOW = _oc.get("context_window", CONTEXT_WINDOW)
    SUMMARIZE_THRESHOLD = _oc.get("summarize_threshold", SUMMARIZE_THRESHOLD)
    CONCURRENT_TOOLS = _oc.get("concurrent_tools", CONCURRENT_TOOLS)
except ImportError:
    pass

# ANSI Colors
C_GREY   = "\033[90m"
C_RESET  = "\033[0m"
C_CYAN   = "\033[96m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_BLUE   = "\033[94m"
C_MAGENTA = "\033[95m"

logger = logging.getLogger("octopus.ollama")


# ─────────────────────────────────────────────
# OLLAMA QUERY WITH RETRY
# ─────────────────────────────────────────────

def ask_ollama(prompt: str, json_mode: bool = False) -> str:
    """Send prompt to Ollama. Streams output token by token.

    IMPORTANT CONTRACT:
    - On success: returns the model's text (cleaned of <thought> tags).
    - On failure: returns a string starting with "[!]".
    - NEVER returns an empty string.

    Callers that need JSON MUST:
      resp = ask_ollama(prompt, json_mode=True)
      if resp.startswith("[!]"):
          raise ValueError(resp)
      data = json.loads(resp)
    """

    def _build_options(minimal: bool = False) -> dict:
        """Build options dict. v12: removed num_gpu/num_batch — Modelfile handles GPU."""
        opts = {
            "num_predict": MAX_TOKENS,
            "temperature": 0.4,
            "top_p": 0.9,
            "top_k": 10,
            "repeat_penalty": 1.15,
            "stop": ["[TOOL RESULTS]", "[TOOL RESULT:", "[CMD RESULT:", "[CMD RESULTS]"],
        }
        if not minimal:
            opts["num_thread"] = 16
        return opts

    def _stream_response(resp) -> str:
        """Stream tokens from Ollama response with live coloring."""
        full_response = ""
        in_thought = False
        token_count = 0
        for line in resp.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                chunk = data.get("response", "")
                full_response += chunk
                token_count += 1

                # Live Color Logic: grey inside <thought>, normal outside
                if "<thought>" in chunk:
                    sys.stdout.write(chunk.replace("<thought>", f"{C_GREY}<thought>"))
                    in_thought = True
                elif "</thought>" in chunk:
                    sys.stdout.write(chunk.replace("</thought>", f"</thought>{C_RESET}"))
                    in_thought = False
                else:
                    if in_thought:
                        sys.stdout.write(f"{C_GREY}{chunk}{C_RESET}")
                    else:
                        sys.stdout.write(chunk)
                sys.stdout.flush()

                # Check for errors in response
                if data.get("error"):
                    print(f"\n{C_RED}[!] Ollama error: {data['error']}{C_RESET}")
                    return f"[!] Ollama error: {data['error']}"

        print()  # newline after stream

        # ── Diagnostic logging ──
        logger.debug(f"RAW response length={len(full_response)}, tokens={token_count}")
        if len(full_response) < 500:
            logger.debug(f"RAW response: {repr(full_response)}")

        # ── Strip <thought> tags ──
        clean = re.sub(r'<thought>.*?</thought>', '', full_response, flags=re.DOTALL).strip()

        logger.debug(f"CLEAN response length={len(clean)}")
        if len(clean) < 500:
            logger.debug(f"CLEAN response: {repr(clean)}")

        # ── Empty check BEFORE any JSON extraction ──
        if not clean:
            logger.warning(f"LLM returned only <thought> tags or empty. Raw len={len(full_response)}")
            return "[!] LLM returned empty response after stripping thought tags"

        # ── JSON mode: extract valid JSON boundary ──
        if json_mode:
            clean = _extract_json(clean)

        return clean

    for attempt in range(1, OLLAMA_RETRIES + 1):
        use_minimal = (attempt > 1)
        options = _build_options(minimal=use_minimal)

        payload = {
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": True,
            "options": options
        }
        if json_mode:
            payload["format"] = "json"

        try:
            label = f" (minimal mode)" if use_minimal else ""
            print(f"\n[*] Streaming from {MODEL_NAME}{label}...")

            resp = requests.post(OLLAMA_URL, json=payload, stream=True, timeout=OLLAMA_TIMEOUT)

            # Handle HTTP errors explicitly
            if resp.status_code == 500:
                error_text = ""
                try:
                    error_text = resp.text[:500]
                except Exception:
                    pass
                if attempt < OLLAMA_RETRIES:
                    print(f"\n{C_RED}[!] Ollama 500 error (attempt {attempt}/{OLLAMA_RETRIES}).{C_RESET}")
                    if error_text:
                        print(f"  {C_GREY}Detail: {error_text}{C_RESET}")
                    print(f"  {C_YELLOW}Retrying with minimal options in 3s...{C_RESET}")
                    time.sleep(3)
                    continue
                else:
                    return f"[!] Ollama 500 error after {OLLAMA_RETRIES} retries."

            if resp.status_code == 404:
                return f"[!] Model '{MODEL_NAME}' not found in Ollama."

            resp.raise_for_status()
            return _stream_response(resp)

        except requests.exceptions.Timeout:
            if attempt < OLLAMA_RETRIES:
                print(f"\n{C_YELLOW}[!] Ollama timed out (attempt {attempt}/{OLLAMA_RETRIES}). Retrying in 5s...{C_RESET}")
                time.sleep(5)
            else:
                return "[!] Ollama timed out after all retries."

        except requests.exceptions.ConnectionError:
            return "[!] Cannot connect to Ollama. Is it running? Start with: ollama serve"

        except Exception as e:
            if attempt < OLLAMA_RETRIES:
                print(f"\n{C_YELLOW}[!] Error: {e} (attempt {attempt}/{OLLAMA_RETRIES}). Retrying...{C_RESET}")
                time.sleep(3)
            else:
                return f"[!] Unexpected error after {OLLAMA_RETRIES} retries: {e}"

    return "[!] Ollama failed after all attempts."


def _extract_json(text: str) -> str:
    """Extract the outermost JSON object/array from a string.

    Strips markdown fences, finds { or [ boundaries.
    Returns the extracted JSON string, or "[!] ..." on failure.
    """
    # Strip markdown code fences
    s = text.strip()
    if s.startswith("```json"):
        s = s[7:]
    if s.startswith("```"):
        s = s[3:]
    if s.endswith("```"):
        s = s[:-3]
    s = s.strip()

    # Find JSON boundaries using bracket matching
    start_idx = -1
    for i, c in enumerate(s):
        if c in ('{', '['):
            start_idx = i
            break

    if start_idx == -1:
        logger.warning(f"No JSON start found in: {repr(s[:200])}")
        return f"[!] No JSON found in LLM response"

    # Match brackets to find the correct end
    open_char = s[start_idx]
    close_char = '}' if open_char == '{' else ']'
    depth = 0
    in_string = False
    escape = False
    end_idx = -1

    for i in range(start_idx, len(s)):
        c = s[i]
        if escape:
            escape = False
            continue
        if c == '\\':
            escape = True
            continue
        if c == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if c == open_char:
            depth += 1
        elif c == close_char:
            depth -= 1
            if depth == 0:
                end_idx = i
                break

    if end_idx == -1:
        # Fallback: find last matching bracket
        for i in range(len(s) - 1, start_idx, -1):
            if s[i] == close_char:
                end_idx = i
                break

    if end_idx == -1:
        logger.warning(f"No JSON end found. start_idx={start_idx}, text={repr(s[:200])}")
        return f"[!] Incomplete JSON in LLM response"

    result = s[start_idx:end_idx + 1]
    logger.debug(f"Extracted JSON ({len(result)} chars)")
    return result
