# agentcert-middleware

Shared middleware base for AgentCert framework integrations (LangChain, CrewAI, AutoGen).

This package provides the common infrastructure that all framework-specific AgentCert packages depend on:

- **Storage backends** — local disk, managed service, or both
- **Retry policy** — exponential backoff for resilient service submission
- **Trust verification** — verify peer agent certificates
- **Coordinator identity** — auto-managed identity for multi-agent coordinators
- **Base middleware class** — shared init, logging, and persistence logic

Most users install a framework-specific package (e.g., `agentcert-langchain`) which pulls this in as a dependency. Install directly only if building a custom integration.

## Install

```bash
pip install agentcert-middleware
```

## Storage Modes

### Local (default)

```python
from agentcert_middleware import BaseMiddleware

mw = BaseMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    agent_name="my-agent",
    storage="local",
    storage_dir="./agentcert-audit/",
)
```

### Service

```python
mw = BaseMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    agent_name="my-agent",
    storage="service",
    service_url="http://localhost:8932",
)
```

### Both (local backup + service)

```python
mw = BaseMiddleware(
    creator_keys=creator_keys,
    agent_keys=agent_keys,
    agent_name="my-agent",
    storage="both",
    storage_dir="./agentcert-audit/",
    service_url="http://localhost:8932",
)
```

## Trust Verification

```python
from agentcert_middleware import TrustVerifier

verifier = TrustVerifier(service_url="http://localhost:8932")
result = verifier.verify_peer(peer_certificate)

if result.valid:
    print("Peer certificate is trusted")
else:
    print(f"Peer certificate invalid: signature={result.signature_valid}")
```

## Coordinator Identity

```python
from agentcert_middleware import CoordinatorIdentity

coord_keys, coord_cert = CoordinatorIdentity.get_or_create(
    creator_keys=creator_keys,
    coordinator_name="crew-coordinator",
    storage_dir="./agentcert-audit/",
)
```

## Links

- [AgentCert main repo](https://github.com/shaleenchauhan/agentcert)
- [Documentation](https://agentcert.dev)
