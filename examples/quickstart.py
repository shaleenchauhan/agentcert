"""AgentCert Quickstart — create and verify a certificate in under 5 minutes.

Run:
    python examples/quickstart.py
"""

import agentcert


def main() -> None:
    # 1. Generate key pairs for the creator and agent
    creator_keys = agentcert.generate_keys()
    agent_keys = agentcert.generate_keys()
    print(f"Creator public key: {creator_keys.public_key_hex}")
    print(f"Agent public key:   {agent_keys.public_key_hex}")

    # 2. Create a signed certificate
    cert = agentcert.create_certificate(
        creator_keys=creator_keys,
        agent_keys=agent_keys,
        name="quickstart-agent",
        platform="langchain",
        model_hash="sha256:e3b0c44298fc1c149afbf4c8996fb924",
        capabilities=["summarization", "Q&A"],
        constraints=["no-PII-access"],
        risk_tier=1,
        expires_days=30,
    )
    print(f"\nCertificate created:")
    print(f"  cert_id:  {cert.cert_id}")
    print(f"  agent:    {cert.agent_metadata.name}")
    print(f"  type:     CREATION")

    # 3. Verify the certificate (offline — no anchor receipt)
    result = agentcert.verify(cert)
    print(f"\nVerification: {result.status}")
    for check in result.checks:
        status = "PASS" if check.passed else "FAIL"
        print(f"  [{status}] {check.name}: {check.detail}")

    # 4. Save to disk
    agentcert.save_certificate(cert, "quickstart.cert.json")
    agentcert.save_keys(creator_keys, "quickstart-creator.keys.json")
    print(f"\nSaved: quickstart.cert.json, quickstart-creator.keys.json")

    # 5. Load and re-verify
    loaded = agentcert.load_certificate("quickstart.cert.json")
    assert loaded.cert_id == cert.cert_id
    print(f"Loaded and verified: cert_id matches")


if __name__ == "__main__":
    main()
