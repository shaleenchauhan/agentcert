import agentcert
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")


def setup_keys():
    """Generate all keys for the demo. Only runs once — skips if keys exist."""
    os.makedirs(KEYS_DIR, exist_ok=True)

    # Creator keys (one keypair for all agents — you are the creator)
    creator_path = os.path.join(KEYS_DIR, "creator.keys.json")
    if not os.path.exists(creator_path):
        creator_keys = agentcert.generate_keys()
        agentcert.save_keys(creator_keys, creator_path)
        print(f"✓ Creator keys generated: {creator_path}")

        # Show Bitcoin mainnet address for funding
        address = agentcert.derive_bitcoin_address(creator_keys, network="mainnet")
        print(f"\n⚡ FUND THIS BITCOIN MAINNET ADDRESS: {address}")
        print(
            f"   Send ~$15-20 worth of BTC for domain purchase + anchoring fees\n"
        )
    else:
        creator_keys = agentcert.load_keys(creator_path)
        address = agentcert.derive_bitcoin_address(creator_keys, network="mainnet")
        print(f"✓ Creator keys already exist: {creator_path}")
        print(f"  Bitcoin address: {address}")

    # Agent keys (one per agent)
    agent_names = [
        "security-monitor",
        "ecosystem-tracker",
        "code-reviewer",
        "shopping-agent",
        "vendor-agent",
    ]

    for name in agent_names:
        agent_path = os.path.join(KEYS_DIR, f"{name}.keys.json")
        if not os.path.exists(agent_path):
            agent_keys = agentcert.generate_keys()
            agentcert.save_keys(agent_keys, agent_path)
            print(f"✓ Agent keys generated: {name}")
        else:
            print(f"✓ Agent keys already exist: {name}")

    print(f"\nAll keys saved in: {KEYS_DIR}")
    return creator_keys


if __name__ == "__main__":
    setup_keys()
