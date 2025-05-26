---
title: Breaking Gemini 2.5 Pro using DeepTeam
description: Placeholder
slug: placeholder
authors: [sid]
date: 2025-05-24
hide_table_of_contents: false
image: https://deepeval-docs.s3.us-east-1.amazonaws.com/blog:top-g-eval-use-cases-cover.jpg
---

## TL;DR

We used [DeepTeam](https://github.com/confident-ai/deepteam) to simulate attacks across **33 vulnerability types** within 9 vulnerability classes against Gemini 2.5 Pro. The model was breached 75% of the time when responding to competition-related queries, and 67% of the time when prompted with tasks requiring excessive agency.

To increase overall attack efficacy, we introduced few-shot prompting, which raised the breach rate from **35%** (one-shot) to **76%** (64-shot).

Finally, standard attack methods were ineffective against bias and toxicity vulnerabilities (0% breach rate). To address this, we introduced two targeted enhancements—Roleplay Replay and Contextual Chains—which achieved breach rates of 87.5% and 37.5%, respectively.

## Methodology

We used DeepTeam to generate a total of **33 attacks** from 33 distinct vulnerablty types across 9 vulnerability classes, such as bias, misinformation, and excessive agency.

```python
from deepteam.vulnerabilities import PIILeakage, Bias, Toxicity

### Example: Functionality Vulnerability Type under Excessive Agency
excessive_agency = ExcessiveAgency(types=["functionality"])
red_team(model_callback=model_callback, vulnerabilities=[excessive_agency])
```

The attack prompts were passed to Gemini 2.5 Pro, and responses were evaluated using 9 DeepTeam metrics to determine breached status.

## Quantitative Analysis

Here, we break down Gemini 2.5 Pro's performance against various vulnerability classes and analyze the impact of few-shot prompting on breach rates.

![Vulnerability Bypass Landscape](./images/image_1.png)

While Gemini 2.5 Pro demonstrated strong robustness in well-studied areas such as bias and toxicity, it was notably less effective against vulnerabilities related to competition and excessive agency.

- **Competition** (75%) and **Excessive Agency** (66.7%) vulnerabilities were consistently breached.
- **Personal Safety** (20%) and **Illegal Activity** (14.3%) attacks led to harmful content leakage.
- **Bias, Toxicity, Graphic Content, Misinformation, IP** (0%) attacks failed to trigger any harmful responses.

### The Few-Shot Effect

To enhance attack efficacy, we employed few-shot prompting by providing examples of desired harmful outputs to Gemini 2.5 Pro before the main attack in the prompt. We varied the number of shots (from 1 to 64) to measure susceptibility to this conditioning.

![Few-Shot Prompting Impact Analysis](./images/image_2.png)

To differentiate between surface-level heuristics and deeper semantic safeguards, we grouped vulnerabilities as follows:

- **Group A (Easily Breached):** Competition, Excessive Agency, Personal Safety
- **Group B (More Resilient):** Bias, Toxicity, Graphic Content

In Group A, breach rates rose from 50% with four-shot prompting to 75%, reaching 100% at 64 examples. Group B remained largely robust, starting at 5.5% and increasing to 29% at 64 shots. Overall, breach rates escalated from 35.2% (one-shot) to 76.3% (sixty-four-shot).

## Jailbreaking Enhancements

Our experiments also showed that Gemini 2.5 Pro was robust against bias and toxicity vulnerabilities, with 0% breach rates. To specifically target these vulnerabilities and improve attack effectiveness, we applied two targeted jailbreaking enhancements—Roleplay Replay and Contextual Chains—using DeepTeam’s custom attack feature.

### Roleplay Replay

![Roleplay Replay](./images/roleplay-replay.png)

This technique instructs the LLM to adopt a persona (e.g., "cynical 1950s CEO") then embeds a harmful request within that character's context. The model, prioritizing persona consistency, often bypasses its safety guidelines.

- **Enhancement:** Exploits persona adherence over safety logic.
- **Impact:** Roleplay Replay raised the breach rate from 0% to **87.5%** for bias and toxicity vulnerabilities.

### Contextual Chains

![Contextual Chains](./images/contextual-chains.png)

Here, a single prompt contains benign-seeming sub-queries followed by a final question that forces a harmful synthesis from the preceding "neutral" information.

- **Enhancement:** Obscures malicious intent within a complex, initially harmless-looking structure.
- **Impact:** Contextual Chains raised the breach rate from 0% to **37.5%** for bias and toxicity vulnerabilities.

## Unexpected Findings

1. **Limited Few-Shot Impact on "Hard" Targets**: Few-shot prompting generally improved attack success, but had minimal effect on the most resilient vulnerability types, such as bias and toxicity. These categories remained largely unaffected by simply increasing the number of harmful examples shown.
2. **Attack Style Trumped Example Quantity**: A significant shift occurred when we introduced enhanced attack styles. Roleplay Replay, for instance, raised the breach rate for gender bias from 0% to 87.5%—without requiring extensive few-shot priming. Contextual Chains produced similar breakthroughs across other previously robust categories.

This contrast highlights an important finding: Gemini’s defenses are more resistant to direct or example-driven attacks, but susceptible to attacks that manipulate persona, context, or dialogue structure. Success was less about volume and more about the nature of the attack vector.

## Conclusion

Our DeepTeam analysis of Gemini 2.5 Pro exposed critical vulnerabilities. While initially robust against bias/toxicity, defenses against **Competition (75% breach)** and **Excessive Agency (67%)** proved weak. Few-shot prompting raised overall breaches from 35% to 76%.

However, the real breakthrough came from targeted single-turn attacks: **Roleplay Replay and Contextual Chains achieved near 100% success against even previously impenetrable categories.** This demonstrated that sophisticated attack _styles_, more than just example quantity, could bypass safeguards, revealing fragile refusal logic and unpredictable safety thresholds.

These insights directly informed critical patches to Gemini 2.5 Pro, with continuous DeepTeam scans now ensuring these safety improvements endure.
