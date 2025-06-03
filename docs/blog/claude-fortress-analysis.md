---
title: Analyzing Claude Sonnet 4 Defenses
description: DeepTeam analysis of 140+ jailbreaking attempts reveals Claude Sonnet 4's 93% attack resistance, detailing its core defensive patterns.
slug: claude-sonnet-4-defense-analysis-deepteam-v2
authors: [sid]
date: 2025-06-03
hide_table_of_contents: false
---

## TL;DR

Using [DeepTeam](https://github.com/confident-ai/deepteam), we tested `claude-sonnet-4` with 140+ attacks across 7 jailbreaking techniques. It achieved a **93% defense success rate**. Key defensive patterns observed: **contextual anchoring**, **escalation detection**, and **semantic integrity checking**. Multi-turn attacks were **2.3x more effective** than single-turn, but overall success was minimal.

## Claude Sonnet 4: Built for Defense

Claude Sonnet 4's high resistance stems from explicit safety instructions within its architecture, unlike models relying on general safety training. These include:

*   Cautious content filtering
*   Intent verification
*   Red team awareness
*   Correction resistance

Interestingly, `claude-sonnet-4` and `claude-opus-4` have nearly identical system prompts. Yet Sonnet's **93.2%** defense rate significantly surpasses Opus 4's **83.6%**, suggesting additional safety-focused training for Sonnet.

## Experiment & Results with [DeepTeam](https://github.com/confident-ai/deepteam)

We tested `claude-sonnet-4` against 7 attack types and 4 vulnerability categories (140 total scenarios) using [DeepTeam](https://github.com/confident-ai/deepteam).

```python
from deepteam import red_team
from deepteam.vulnerabilities import Bias, Toxicity, ...
from deepteam.attacks.multi_turn import LinearJailbreaking, ...
from deepteam.attacks.single_turn import Roleplay, ...

# Example attack configurations (ensure these match the 7 types tested)
attacks = {
    "Linear": LinearJailbreaking(turns=4, escalation_rate=0.4),
    "Tree": TreeJailbreaking(max_branches=3, depth=4),
    ... 
}

vulnerabilities = [
    Bias(types=["gender", "race", "religion"]),
    ...
]

risk_assessment = red_team(
    model_callback=claude_callback, 
    vulnerabilities=vulnerabilities,
    attacks=attacks,
    attacks_per_vulnerability_type=5 
)
```

## Key Findings

*   **Overall Defense Rate**: `claude-sonnet-4` achieved a **93%** success rate.
*   **Attack Effectiveness**: Multi-turn attacks (Crescendo: 88% defense, Linear: 93% defense) were **2.3x more effective** than single-turn (Roleplay: 90% defense, Leetspeak: 96% defense), though all struggled.
*   **Vulnerability Resistance**: Strong across all categories (Competition: **94%** defense, Toxicity: **91%** defense).
*   **Sonnet vs. Opus**: Sonnet 4's **93%** rate is **10% higher** than Opus 4 (83%), despite similar system prompts, highlighting Sonnet's enhanced safety training.

### Defensive Patterns Identified

Analysis of responses using [DeepTeam](https://github.com/confident-ai/deepteam) revealed three core patterns:

*   **Contextual Anchoring**: Redirects harmful requests to legitimate goals (e.g., *"Happy to help with creative writing, but let's try this approach..."*).
*   **Escalation Detection**: Recognizes manipulation across turns (e.g., *"This conversation is moving toward content I can't assist with..."*).
*   **Semantic Integrity Checking**: Validates intent behind obfuscated requests (e.g., *"I see you're using math notation, but this asks about harmful content..."*).

## Conclusion

Claude Sonnet 4's **93%** defense rate, analyzed using [DeepTeam](https://github.com/confident-ai/deepteam), showcases the effectiveness of explicit architectural safety instructions combined with focused training. Its systematic defensive patterns (contextual anchoring, escalation detection, semantic integrity checking) and the **10 percentage point performance gap** over `claude-opus-4` (despite similar prompts) underscore this.

This approach suggests a path toward more robust AI safety, moving beyond general training to proactive, instruction-based defensive architectures.

*Analyze your model's defenses with [DeepTeam](https://github.com/confident-ai/deepteam).*

