#!/usr/bin/env python3

import re
import sys
import time
import json
import logging
import requests
from typing import Generator

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
TEMPERATURE = 0.4
JSON_TEMPERATURE = 0.15
TOP_P = 0.9
TOP_K = 10
REPEAT_PENALTY = 1.15
NUM_THREAD = 16
NUM_CTX = 16384
NUM_BATCH = 512
NUM_GPU = None
JSON_MAX_TOKENS = 1536

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
    TEMPERATURE = _oc.get("temperature", TEMPERATURE)
    JSON_TEMPERATURE = _oc.get("json_temperature", JSON_TEMPERATURE)
    TOP_P = _oc.get("top_p", TOP_P)
    TOP_K = _oc.get("top_k", TOP_K)
    REPEAT_PENALTY = _oc.get("repeat_penalty", REPEAT_PENALTY)
    NUM_THREAD = _oc.get("num_threads", _oc.get("num_thread", NUM_THREAD))
    NUM_CTX = _oc.get("num_ctx", NUM_CTX)
    NUM_BATCH = _oc.get("num_batch", NUM_BATCH)
    NUM_GPU = _oc.get("num_gpu", NUM_GPU)
    JSON_MAX_TOKENS = _oc.get("json_max_tokens", JSON_MAX_TOKENS)
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
        """Build Ollama options from config.yaml with a lean JSON mode."""
        predict_tokens = JSON_MAX_TOKENS if json_mode else MAX_TOKENS
        opts = {
            "num_predict": predict_tokens,
            "temperature": JSON_TEMPERATURE if json_mode else TEMPERATURE,
            "top_p": TOP_P,
            "top_k": TOP_K,
            "repeat_penalty": REPEAT_PENALTY,
            "stop": ["[TOOL RESULTS]", "[TOOL RESULT:", "[CMD RESULT:", "[CMD RESULTS]"],
        }
        if NUM_CTX:
            opts["num_ctx"] = NUM_CTX
        if not minimal:
            if NUM_THREAD:
                opts["num_thread"] = NUM_THREAD
            if NUM_BATCH:
                opts["num_batch"] = NUM_BATCH
            if NUM_GPU is not None:
                opts["num_gpu"] = NUM_GPU
        elif NUM_BATCH:
            opts["num_batch"] = min(int(NUM_BATCH), 128)
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

                # Live Color Logic: grey inside <thought> or <think>, normal outside
                if "<thought>" in chunk or "<think>" in chunk:
                    chunk = chunk.replace("<thought>", f"{C_GREY}<thought>").replace("<think>", f"{C_GREY}<think>")
                    sys.stdout.write(chunk)
                    in_thought = True
                elif "</thought>" in chunk or "</think>" in chunk:
                    chunk = chunk.replace("</thought>", f"</thought>{C_RESET}").replace("</think>", f"</think>{C_RESET}")
                    sys.stdout.write(chunk)
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

        # ── Strip <thought> and <think> tags (even if unclosed) ──
        clean = re.sub(r'<(?:thought|think)>[\s\S]*?(?:</(?:thought|think)>|$)', '', full_response).strip()

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

        effective_prompt = prompt
        if json_mode:
            effective_prompt = (
                "Return exactly one valid JSON object or array. "
                "Do not use markdown, prose, comments, <think>, or <thought> tags.\n\n"
                + prompt
            )

        payload = {
            "model": MODEL_NAME,
            "prompt": effective_prompt,
            "stream": True,
            "options": options
        }

        # v13: Removed `payload["format"] = "json"` for json_mode.
        # Strict JSON mode blocks reasoning models (like Qwen) from outputting
        # their mandatory <think> tags, resulting in empty responses.
        # We rely on _extract_json() below to parse the output instead.

        try:
            label = f" (minimal mode)" if use_minimal else ""
            print(f"\n[*] Streaming from {MODEL_NAME}{label}...")

            resp = requests.post(OLLAMA_URL, json=payload, stream=True, timeout=OLLAMA_TIMEOUT)

            # Handle HTTP errors explicitly
            if resp.status_code == 500:
                error_text = ""
                try:
                    error_text = resp.text[:500]
                except Exception as _exc:
                    logging.debug(f"Suppressed in ollama_client.py: {_exc}")
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
            result = _stream_response(resp)
            if result.startswith("[!] LLM returned empty response") and attempt < OLLAMA_RETRIES:
                print(f"  {C_YELLOW}Retrying empty LLM response in minimal mode...{C_RESET}")
                time.sleep(2)
                continue
            return result

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


# ─────────────────────────────────────────────
# STRUCTURED JSON MODE (v9.0)
# ─────────────────────────────────────────────

def ask_ollama_structured(prompt: str, schema: dict, max_retries: int = 2) -> dict:
    """Ask Ollama and validate response against a JSON schema.

    Args:
        prompt: The prompt to send.
        schema: Dict describing expected structure:
            {"field_name": "description", ...}
            Values are descriptions used in the prompt.
        max_retries: Number of retries on invalid JSON.

    Returns:
        Parsed dict matching the schema, or {"error": "..."} on failure.

    Example:
        result = ask_ollama_structured(
            "Analyze this nmap output: ...",
            schema={
                "risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
                "vulnerabilities": "list of {name, severity, port, service}",
                "recommended_tools": "list of tool names to run next",
            }
        )
    """
    schema_text = json.dumps(schema, indent=2)
    full_prompt = (
        f"{prompt}\n\n"
        f"RESPOND WITH VALID JSON ONLY. Use this exact schema:\n"
        f"```json\n{schema_text}\n```\n"
        f"Return ONLY the JSON object, no markdown, no explanation."
    )

    for attempt in range(1, max_retries + 1):
        response = ask_ollama(full_prompt, json_mode=True)

        if response.startswith("[!]"):
            logger.warning(f"Structured query attempt {attempt} failed: {response}")
            if attempt < max_retries:
                continue
            return {"error": response}

        try:
            data = json.loads(response)
            # Validate required fields
            missing = [k for k in schema if k not in data]
            if missing:
                logger.warning(f"Missing fields in structured response: {missing}")
                # Don't fail — partial data is still useful
            return data
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse error attempt {attempt}: {e}")
            if attempt < max_retries:
                continue
            return {"error": f"Invalid JSON after {max_retries} retries: {e}",
                    "raw_response": response[:500]}

    return {"error": "Structured query exhausted all retries"}


def ask_ollama_stream(prompt: str) -> "Generator[str, None, None]":
    """Generator that yields tokens as they arrive from Ollama.

    Useful for real-time display in Rich panels or custom UI.
    Does NOT print to stdout (unlike ask_ollama).

    Yields:
        Individual text chunks/tokens from the model.

    Example:
        for token in ask_ollama_stream("Analyze this scan..."):
            sys.stdout.write(token)
            sys.stdout.flush()
    """
    options = {
        "num_predict": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "top_p": TOP_P,
        "top_k": TOP_K,
        "repeat_penalty": REPEAT_PENALTY,
    }
    if NUM_CTX:
        options["num_ctx"] = NUM_CTX
    if NUM_THREAD:
        options["num_thread"] = NUM_THREAD
    if NUM_BATCH:
        options["num_batch"] = NUM_BATCH
    if NUM_GPU is not None:
        options["num_gpu"] = NUM_GPU

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": True,
        "options": options,
    }

    try:
        resp = requests.post(
            OLLAMA_URL, json=payload,
            stream=True, timeout=OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()

        for line in resp.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                chunk = data.get("response", "")
                if chunk:
                    yield chunk
                if data.get("done"):
                    break
                if data.get("error"):
                    logger.error(f"Ollama stream error: {data['error']}")
                    yield f"\n[!] Error: {data['error']}"
                    break

    except requests.exceptions.RequestException as e:
        logger.error(f"Ollama stream request failed: {e}")
        yield f"[!] Connection failed: {e}"
