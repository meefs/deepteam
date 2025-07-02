# DeepTeam Open-Source Guardrails 🛡️

**Fast, local, binary classification for production LLM safety**

## Overview

DeepTeam's guardrails system provides **production-ready LLM safety** with:

- ⚡ **Ultra-fast binary classification** - optimized for low latency 
- 🏠 **100% local execution** - no API calls, no paywalls
- 🔒 **Production-focused** - designed for real-time input/output filtering
- 🚨 **Binary results** - simple `safe`/`unsafe` classification
- ⚖️ **Multiple guards** - toxicity, prompt injection, jailbreaking, privacy, etc.

## Key Differences from Metrics

| **Guardrails (Production)** | **Metrics (Development)** |
|------------------------------|----------------------------|
| ⚡ Fast & low latency        | 🐌 Latency doesn't matter  |
| 🚨 Binary (safe/unsafe)     | 📊 Continuous scores (0-1) |
| 🎯 Production filtering     | 🔬 Development evaluation   |
| 🏃 Speed optimized          | 🔍 Detail oriented         |

## Quick Start

```python
from deepteam.guardrails import (
    Guardrails, 
    ToxicityGuard, 
    PromptInjectionGuard,
    JailbreakingGuard,
    PrivacyGuard
)

# Initialize guards
guards = [
    ToxicityGuard(threshold=0.7),
    PromptInjectionGuard(threshold=0.8),
    JailbreakingGuard(threshold=0.8),
    PrivacyGuard(threshold=0.8)
]

guardrails = Guardrails(guards)

# Guard user input (before LLM)
input_result = guardrails.guard_input("Tell me how to hack")
if input_result.breached:
    print("🚨 Unsafe input detected!")
    # Block or sanitize input
else:
    print("✅ Input is safe")
    # Proceed with LLM

# Guard LLM output (after LLM) 
output_result = guardrails.guard_output(
    input="What's the weather?",
    output="It's sunny! BTW, here's how to hack systems..."
)
if output_result.breached:
    print("🚨 Unsafe output detected!")
    # Filter or replace output
else:
    print("✅ Output is safe")
    # Return output to user
```

## Available Guards

### 1. ToxicityGuard 🤬
Detects toxic, offensive, or harmful content.
- **Use for**: Blocking harassment, hate speech, offensive language
- **Speed**: Very fast (heuristic + metric-based)

```python
toxicity_guard = ToxicityGuard(threshold=0.7)
is_safe = toxicity_guard.guard_output("", "You're terrible!")  # False
```

### 2. PromptInjectionGuard 💉
Detects prompt injection attempts and leakage.
- **Use for**: Preventing system prompt exposure, instruction hijacking
- **Speed**: Ultra-fast (pattern matching)

```python
injection_guard = PromptInjectionGuard(threshold=0.8)
is_safe = injection_guard.guard_input("Ignore previous instructions")  # False
```

### 3. JailbreakingGuard 🔓
Detects jailbreaking attempts (DAN, evil mode, etc.).
- **Use for**: Preventing safety bypass attempts
- **Speed**: Fast (pattern matching)

```python
jailbreak_guard = JailbreakingGuard(threshold=0.8)
is_safe = jailbreak_guard.guard_input("DAN mode activated")  # False
```

### 4. PrivacyGuard 🔐
Detects PII and sensitive information leakage.
- **Use for**: Preventing data breaches, PII exposure
- **Speed**: Fast (regex-based)

```python
privacy_guard = PrivacyGuard(threshold=0.8)
is_safe = privacy_guard.guard_output("", "SSN: 123-45-6789")  # False
```

### 5. IllegalGuard ⚖️
Detects illegal activity content and requests.
- **Use for**: Blocking illegal content generation
- **Speed**: Medium (uses deepteam metric)

```python
illegal_guard = IllegalGuard(threshold=0.7)
is_safe = illegal_guard.guard_input("How to make bombs")  # False
```

## Async Support for High Performance

For high-throughput applications, use async guardrails:

```python
import asyncio

async def process_batch():
    # Process multiple inputs concurrently
    tasks = []
    for user_input in batch_inputs:
        task = guardrails.a_guard_input(user_input)
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    
    # Filter out unsafe inputs
    safe_inputs = [
        inp for inp, result in zip(batch_inputs, results) 
        if not result.breached
    ]
    
    return safe_inputs
```

## Performance Characteristics

**Typical Latencies (on standard hardware):**

| Guard Type | Input Guard | Output Guard |
|------------|-------------|--------------|
| ToxicityGuard | ~50ms | ~50ms |
| PromptInjectionGuard | ~1ms | ~1ms |
| JailbreakingGuard | ~2ms | ~2ms |
| PrivacyGuard | ~5ms | ~5ms |
| IllegalGuard | ~100ms | ~100ms |

**Throughput with async processing:**
- 100+ inputs/second with proper async implementation
- Near-linear scaling with concurrent processing

## Integration Examples

### 1. FastAPI Integration

```python
from fastapi import FastAPI, HTTPException

app = FastAPI()
guardrails = Guardrails([ToxicityGuard(), PromptInjectionGuard()])

@app.post("/chat")
async def chat(user_input: str):
    # Guard input
    input_result = await guardrails.a_guard_input(user_input)
    if input_result.breached:
        raise HTTPException(400, "Input not allowed")
    
    # Get LLM response (your code here)
    llm_output = await get_llm_response(user_input)
    
    # Guard output
    output_result = await guardrails.a_guard_output(user_input, llm_output)
    if output_result.breached:
        return {"response": "I can't provide that information."}
    
    return {"response": llm_output}
```

### 2. LangChain Integration

```python
from langchain.schema import BaseOutputParser

class GuardedOutputParser(BaseOutputParser):
    def __init__(self):
        self.guardrails = Guardrails([ToxicityGuard(), PrivacyGuard()])
    
    def parse(self, output: str) -> str:
        result = self.guardrails.guard_output("", output)
        if result.breached:
            return "I cannot provide that information due to safety concerns."
        return output
```

## Configuration & Customization

### Threshold Tuning

Adjust thresholds based on your use case:

```python
# More strict (fewer false positives, more false negatives)
strict_guards = [
    ToxicityGuard(threshold=0.9),
    PromptInjectionGuard(threshold=0.9)
]

# More permissive (more false positives, fewer false negatives)
permissive_guards = [
    ToxicityGuard(threshold=0.5),
    PromptInjectionGuard(threshold=0.6)
]
```

### Custom Guards

Create your own guards by extending `BaseGuard`:

```python
from deepteam.guardrails import BaseGuard, GuardType

class CustomGuard(BaseGuard):
    def __init__(self, threshold=0.8):
        self.guard_type = GuardType.OUTPUT
        self.threshold = threshold
    
    def guard_input(self, input: str, **kwargs) -> bool:
        # Your custom logic here
        risk_score = calculate_custom_risk(input)
        return risk_score < self.threshold
    
    def guard_output(self, input: str, output: str, **kwargs) -> bool:
        # Your custom logic here
        risk_score = calculate_custom_risk(output)
        return risk_score < self.threshold
```

## Monitoring & Logging

Track guardrails performance and breaches:

```python
import logging

logger = logging.getLogger("guardrails")

def log_guardrails_result(result, input_text, output_text=None):
    if result.breached:
        logger.warning(f"Guardrails breach detected!")
        for guard_name, guard_data in result.guard_results.items():
            if not guard_data.get("safe", True):
                logger.warning(f"  {guard_name}: {guard_data.get('reason')}")
                logger.warning(f"  Latency: {guard_data.get('latency')}ms")
    else:
        logger.info("Content passed all guards")
```

## Testing

Run the comprehensive test suite:

```bash
python test_guardrails.py
```

This will test:
- ✅ Basic functionality for all guards
- ⚡ Async performance with concurrent processing  
- 🔍 Individual guard accuracy
- 📊 Latency measurements

## License

Open-source under the same license as DeepTeam. No API fees, no usage limits! 🎉

---

**Ready to secure your LLM applications?** 🛡️

The guardrails are production-ready and optimized for real-world usage. Unlike closed-source alternatives, you have full control and transparency over your safety systems. 