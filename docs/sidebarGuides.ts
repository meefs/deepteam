module.exports = {
  guides: [
    {
      type: "category",
      label: "AI Agent Security",
      items: [
        "guide-agentic-ai-red-teaming",
        "guide-red-teaming-conversational-agents",
        "guide-red-teaming-agentic-rag",
      ],
      collapsed: false,
    },
    {
      type: "category",
      label: "Model Security",
      items: ["guide-red-teaming-models"],
      collapsed: false,
    },
    {
      type: "category",
      label: "Responsible AI & Ethics",
      items: ["guide-responsible-ai"],
      collapsed: false,
    },
    {
      type: "category",
      label: "Frameworks & Compliance",
      items: ["guide-safety-frameworks"],
      collapsed: false,
    },
    {
      type: "category",
      label: "Guardrails",
      items: ["guide-deploying-guardrails"],
      collapsed: false,
    },
    {
      type: "category",
      label: "Customizations",
      items: [
        "guide-custom-vulnerability",
        "guide-custom-attacks",
        "guide-custom-red-teaming-pipelines",
      ],
      collapsed: false,
    },
    {
      type: "category",
      label: "Operations",
      items: ["guide-cli-yaml"],
      collapsed: false,
    },
  ],
};
