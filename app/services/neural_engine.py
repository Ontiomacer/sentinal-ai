"""
Neural Engine — Local Ollama-powered AI cognition for malware analysis.

Features:
- Streaming responses via async generators
- Conversation context memory per investigation
- APK-aware prompt templates
- Chunked analysis for large decompiled codebases
- Optimized for CPU inference (ThinkPad E490)
"""

import json
import logging
import asyncio
import traceback
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are Sentinel, a Banking Fraud Analyst. Detect: "
    "Credential Theft (overlays), OTP Interception (SMS), UPI Fraud, "
    "Accessibility Abuse, Account Takeover (ATO), and Targeted Banks (SBI, HDFC, etc.).\n"
    "Rules: Use only technical evidence. Be professional. No generic malware talk."
)

ANALYSIS_PROMPT = (
    "Perform a professional Banking Fraud Intelligence analysis on the following APK context. "
    "Provide a CONCISE overview (max 300 words). Return valid JSON with these EXACT keys:\n"
    "executive_summary (concise overview),\n"
    "threat_classification (e.g. Banking Trojan, Spyware),\n"
    "fraud_intent (e.g. Credential Theft, OTP Interception),\n"
    "risk_score (0-100),\n"
    "confidence (0-100),\n"
    "risk_contributors (list of strings explaining why the score is what it is, e.g. 'Accessibility Abuse +25'),\n"
    "key_findings (list of brief findings),\n"
    "recommendations (list),\n"
    "targeted_banking_apps (list),\n"
    "fraud_scores: {overall_risk, credential_theft, otp_theft, upi_fraud, account_takeover, financial_data_exposure}\n\n"
    "Context:\n{context}\n\n"
    "Respond with JSON only. No generic malware talk."
)

EXPLAIN_PROMPT = (
    "As a Malware Reverse Engineer, analyze this specific function/code block from a suspicious APK.\n"
    "APK Context: {apk_context}\n"
    "Code: ```\n{code}\n```\n\n"
    "Return valid JSON with these EXACT keys:\n"
    "function_name, purpose, behavior, security_impact, fraud_impact, evidence (cite code/strings), risk_contribution (numeric value), confidence (High/Medium/Low)."
)

SUMMARY_PROMPT = (
    "As a Banking Fraud Analyst, generate a CONCISE intelligence briefing (max 300 words). "
    "Focus on Threat Classification, Fraud Intent, Risk Score, and Top Risk Contributors.\n\n"
    "Data: {context}"
)

RISK_PROMPT = (
    "Return JSON risk assessment: "
    "overall_banking_fraud_risk, credential_theft_score, otp_theft_score, "
    "upi_fraud_score, account_takeover_score, financial_data_exposure_score, "
    "risk_factors (list), targeted_apps (list).\n"
    "Data: {context}\n"
    "JSON ONLY."
)

CHAT_SYSTEM = (
    "You are a professional Malware Reverse Engineer and Banking Fraud Analyst.\n\n"
    "Investigating APK Context: {context}\n\n"
    "Rules for Engagement:\n"
    "1. Respond based on technical evidence (functions, APIs, execution chains).\n"
    "2. If asked for 'malicious functions', return ranked suspicious functions with reasons, risk, and evidence.\n"
    "3. If asked 'why is this APK malicious', describe the reconstructed attack chain and specific fraud intent chains (e.g., OTP theft chain).\n"
    "4. For targeted apps, provide evidence (strings, package names) and confidence level.\n"
    "5. Avoid generic malware talk. Focus on actionable intelligence from the current evidence.\n"
    "6. Every conclusion must reference actual findings from the analysis."
)


class NeuralEngine:
    """Local Ollama-powered neural cognition engine for malware analysis."""

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "qwen3:4b",
        timeout: float = 300.0,
    ):
        self.ollama_url = ollama_url.rstrip("/")
        if model != "qwen3:4b":
            logger.error("Unsupported model configured: %s. Forcing qwen3:4b.", model)
        self.model = "qwen3:4b"
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        # Conversation memory per investigation (scan_id -> messages)
        self._conversation_memory: Dict[str, List[Dict[str, str]]] = {}
        # Simple in-memory cache for queries
        self._query_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # HTTP client lifecycle
    # ------------------------------------------------------------------

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            # Set timeout to None for local Ollama to allow for slow CPU inference
            timeout_config = httpx.Timeout(
                None, # No timeout
                connect=30.0,
                read=None,
                write=None,
                pool=None
            )
            self._client = httpx.AsyncClient(
                base_url=self.ollama_url,
                timeout=timeout_config,
                limits=httpx.Limits(
                    max_keepalive_connections=5, max_connections=10
                ),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> Dict[str, Any]:
        """Check Ollama availability and model readiness."""
        try:
            resp = await self.client.get("/api/tags")
            if resp.is_success:
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                has_model = any(self.model in m for m in models)
                return {
                    "healthy": True,
                    "ollama_running": True,
                    "model_available": has_model,
                    "model": self.model,
                    "available_models": models,
                }
        except Exception as exc:
            logger.warning("Ollama health check failed: %s", exc)
            return {
                "healthy": False,
                "ollama_running": False,
                "model_available": False,
                "model": self.model,
                "error": str(exc),
            }

        return {
            "healthy": False,
            "ollama_running": False,
            "model_available": False,
            "model": self.model,
            "error": "Ollama /api/tags did not return a successful response",
        }

    # ------------------------------------------------------------------
    # High-level API
    # ------------------------------------------------------------------

    async def generate_cognition_report(
        self, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a structured AI cognition report from analysis context."""
        prompt = ANALYSIS_PROMPT.format(
            context=self._truncate_context(context, max_chars=4500)
        )
        raw = await self._query(prompt, system=SYSTEM_PROMPT, max_tokens=1024)
        structured = self._parse_json_output(raw)
        return {
            "model": self.model,
            "raw_output": raw,
            "structured_output": structured,
            "context_summary": {
                "risk_score": context.get("threat_assessment", {}).get(
                    "risk_score"
                ),
                "severity": context.get("threat_assessment", {}).get(
                    "severity"
                ),
            },
        }

    async def generate_summary(
        self, context: Dict[str, Any]
    ) -> str:
        """Generate a threat intelligence summary."""
        prompt = SUMMARY_PROMPT.format(
            context=self._truncate_context(context, max_chars=4500)
        )
        return await self._query(prompt, system=SYSTEM_PROMPT, max_tokens=768)

    async def generate_risk_assessment(
        self, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate structured risk assessment."""
        prompt = RISK_PROMPT.format(
            context=self._truncate_context(context, max_chars=4500)
        )
        raw = await self._query(prompt, system=SYSTEM_PROMPT, max_tokens=512)
        return self._parse_json_output(raw)

    async def explain_code(
        self,
        code: str,
        apk_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Explain a code snippet in forensic context."""
        ctx_str = ""
        if apk_context:
            ctx_str = self._truncate_context(apk_context, max_chars=2000)
        prompt = EXPLAIN_PROMPT.format(code=code[:3000], apk_context=ctx_str)
        raw = await self._query(prompt, system=SYSTEM_PROMPT, max_tokens=768)
        return self._parse_json_output(raw)

    async def chat(
        self,
        scan_id: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Chat with investigation context (non-streaming)."""
        system = CHAT_SYSTEM.format(
            context=self._truncate_context(context or {}, max_chars=1500)
        )
        # Add to memory
        history = self._conversation_memory.setdefault(scan_id, [])
        history.append({"role": "user", "content": message})

        # Build prompt with history (last 3 messages for ultra-lite mode)
        recent = history[-3:]
        combined = "\n".join(
            f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
            for m in recent
        )
        response = await self._query(combined, system=system, max_tokens=512)

        history.append({"role": "assistant", "content": response})
        return response

    async def chat_stream(
        self,
        scan_id: str,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[str, None]:
        """Streaming chat with investigation context."""
        # Dynamic context selection: if question is about apps, send apps; if about functions, send functions
        msg_lower = message.lower()
        lite_ctx = {}
        if context:
            if any(k in msg_lower for k in ["app", "target", "bank", "institution"]):
                lite_ctx["targeted_banking_apps"] = context.get("targeted_banking_apps", [])
                lite_ctx["strings_sample"] = context.get("strings_sample", [])
            elif any(k in msg_lower for k in ["function", "method", "code", "suspicious"]):
                lite_ctx["suspicious_functions"] = context.get("suspicious_functions", [])
            else:
                # Default minimal context
                lite_ctx["risk_assessment"] = context.get("risk_assessment", {})
                lite_ctx["fraud_intent"] = context.get("fraud_intent", {})

        system = CHAT_SYSTEM.format(
            context=self._truncate_context(lite_ctx or context or {}, max_chars=1200)
        )
        history = self._conversation_memory.setdefault(scan_id, [])
        history.append({"role": "user", "content": message})

        # Use 3 messages of history for ultra-lite mode
        recent = history[-3:]
        combined = "\n".join(
            f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
            for m in recent
        )

        full_response = ""
        async for chunk in self._stream_query(combined, system=system):
            full_response += chunk
            yield chunk

        history.append({"role": "assistant", "content": full_response})

    def clear_memory(self, scan_id: str) -> None:
        """Clear conversation memory for a scan."""
        self._conversation_memory.pop(scan_id, None)

    # ------------------------------------------------------------------
    # Chunked analysis for large codebases
    # ------------------------------------------------------------------

    async def analyze_code_chunks(
        self,
        code_chunks: List[str],
        apk_context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Analyze code in chunks for large decompiled codebases."""
        results = []
        ctx_str = self._truncate_context(apk_context or {}, max_chars=1000)
        for i, chunk in enumerate(code_chunks):
            prompt = (
                f"Analyze chunk {i+1}/{len(code_chunks)} of decompiled APK code. "
                f"Identify suspicious patterns, malicious behavior, and fraud indicators.\n\n"
                f"APK Context:\n{ctx_str}\n\n"
                f"Code chunk:\n```\n{chunk[:3000]}\n```\n\n"
                f"List findings as bullet points."
            )
            result = await self._query(
                prompt, system=SYSTEM_PROMPT, max_tokens=512
            )
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Low-level Ollama communication
    # ------------------------------------------------------------------

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type(
            (httpx.HTTPError, httpx.ConnectError, httpx.ReadTimeout)
        ),
    )
    async def _query(
        self,
        prompt: str,
        *,
        system: str = "",
        max_tokens: int = 1024,
    ) -> str:
        """Non-streaming query to Ollama with caching."""
        import time
        start_time = time.time()
        
        # Merge system prompt into main prompt for better compatibility
        full_prompt = f"{system}\n\nUser: {prompt}\n\nAssistant:" if system else prompt
        
        logger.info(f"[NeuralEngine] _query START")
        logger.info(f"[NeuralEngine] Model: {self.model}")
        logger.info(f"[NeuralEngine] Prompt length: {len(full_prompt)} chars")
        logger.info(f"[NeuralEngine] Max tokens: {max_tokens}")
        logger.info(f"[NeuralEngine] System: {system[:100] if system else 'None'}")
        logger.info(f"[NeuralEngine] Prompt preview: {prompt[:200]}")
        
        # Create cache key from prompt
        cache_key = full_prompt
        if cache_key in self._query_cache:
            logger.info(f"[NeuralEngine] CACHE HIT: Len={len(self._query_cache[cache_key])}")
            return self._query_cache[cache_key]

        body: Dict[str, Any] = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_predict": max_tokens,
            },
        }

        logger.info(f"[NeuralEngine] Sending request to Ollama at {self.ollama_url}")
        logger.info(f"[NeuralEngine] Request body keys: {list(body.keys())}")
        
        try:
            request_start = time.time()
            resp = await self.client.post("/api/generate", json=body, timeout=300.0)
            request_time = time.time() - request_start
            
            logger.info(f"[NeuralEngine] Ollama request completed in {request_time:.2f}s")
            logger.info(f"[NeuralEngine] Response status: {resp.status_code}")
            
            resp.raise_for_status()
            
            parse_start = time.time()
            data = resp.json()
            parse_time = time.time() - parse_start
            
            logger.info(f"[NeuralEngine] JSON parsed in {parse_time:.4f}s")
            logger.info(f"[NeuralEngine] Response keys: {list(data.keys())}")
            logger.info(f"[NeuralEngine] Response 'done': {data.get('done')}")
            
            response_text = (data.get("response") or "").strip()
            
            logger.info(f"[NeuralEngine] Response text length: {len(response_text)} chars")
            logger.info(f"[NeuralEngine] Response preview: {response_text[:500] if response_text else '[EMPTY]'}")
            
            if not response_text:
                logger.error(f"[NeuralEngine] ❌ OLLAMA RETURNED EMPTY RESPONSE")
                logger.error(f"[NeuralEngine] Full data: {data}")
                # Return error message instead of empty string
                return "ERROR: Ollama returned empty response. Model may be overloaded or prompt invalid."
            
            # Store in cache
            self._query_cache[cache_key] = response_text
            
            total_time = time.time() - start_time
            logger.info(f"[NeuralEngine] _query COMPLETE in {total_time:.2f}s")
            logger.info(f"[NeuralEngine] Final response length: {len(response_text)}")
            
            return response_text
            
        except Exception as e:
            total_time = time.time() - start_time
            logger.error(f"[NeuralEngine] ❌ Ollama query FAILED after {total_time:.2f}s")
            logger.error(f"[NeuralEngine] Exception type: {type(e).__name__}")
            logger.error(f"[NeuralEngine] Exception message: {str(e)}")
            import traceback
            logger.error(f"[NeuralEngine] Traceback:\n{traceback.format_exc()}")
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(
            (httpx.HTTPError, httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError)
        ),
    )
    async def _stream_query(
        self,
        prompt: str,
        *,
        system: str = "",
        max_tokens: int = 512,
    ) -> AsyncGenerator[str, None]:
        """Streaming query to Ollama with disconnect protection."""
        full_prompt = f"{system}\n\nUser: {prompt}\n\nAssistant:" if system else prompt
        
        body: Dict[str, Any] = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": True,
            "options": {"temperature": 0.0, "num_predict": max_tokens},
        }

        logger.info("Ollama Stream Request: Model=%s, Prompt_Len=%d", self.model, len(full_prompt))

        try:
            async with self.client.stream("POST", "/api/generate", json=body, timeout=None) as resp:
                if resp.status_code != 200:
                    error_text = await resp.aread()
                    logger.error("Ollama error %d: %s", resp.status_code, error_text)
                    resp.raise_for_status()

                token_count = 0
                async for line in resp.aiter_lines():
                    if not line.strip():
                        yield "" # Heartbeat
                        continue
                    try:
                        data = json.loads(line)
                        token = data.get("response", "")
                        if token:
                            token_count += 1
                            yield token
                        if data.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
                
                if token_count == 0:
                    yield "\n[Analyst: CPU load is high. Still processing artifact behavior...]"
        except (httpx.RemoteProtocolError, httpx.ReadTimeout) as e:
            logger.warning("Stream interrupted: %s. Retrying...", e)
            raise
        except Exception as exc:
            logger.error("Inference failed: %s", exc)
            yield f"\n[Error: AI inference failed — {str(exc)}]"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _truncate_context(context: Dict[str, Any], max_chars: int = 6000) -> str:
        """Serialize context to JSON, truncating if too large."""
        raw = json.dumps(context, indent=1, ensure_ascii=False, default=str)
        if len(raw) > max_chars:
            return raw[:max_chars] + "\n... [truncated]"
        return raw

    @staticmethod
    def _parse_json_output(raw: str) -> Dict[str, Any]:
        """Parse JSON from model output, with fallback extraction."""
        # Try direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON block
        start = raw.find("{")
        end = raw.rfind("}")
        if start != -1 and end != -1 and start < end:
            try:
                return json.loads(raw[start : end + 1])
            except json.JSONDecodeError:
                pass

        # Fallback
        logger.warning("Could not parse JSON from Ollama output")
        return {
            "threat_summary": "AI output could not be parsed as structured JSON.",
            "analyst_narrative": raw,
            "raw_text": raw,
        }


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[NeuralEngine] = None


def get_neural_engine() -> NeuralEngine:
    """Get or create the singleton NeuralEngine."""
    global _engine_instance
    if _engine_instance is None:
        from app.config import settings

        _engine_instance = NeuralEngine(
            ollama_url=settings.ollama_url,
            model=settings.ollama_model,
            timeout=settings.ollama_timeout,
        )
    return _engine_instance
