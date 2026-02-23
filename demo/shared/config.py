import os

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
PORKBUN_API_KEY = os.environ.get("PORKBUN_API_KEY")
PORKBUN_SECRET_KEY = os.environ.get("PORKBUN_SECRET_KEY")


def validate_keys():
    """Validate all required API keys are present in environment."""
    missing = []
    for name in [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "TAVILY_API_KEY",
        "GITHUB_TOKEN",
        "PORKBUN_API_KEY",
        "PORKBUN_SECRET_KEY",
    ]:
        if not os.environ.get(name):
            missing.append(name)
    if missing:
        raise ValueError(f"Missing environment variables: {', '.join(missing)}")
    print("✓ All API keys loaded")
