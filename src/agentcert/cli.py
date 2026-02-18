"""Command-line interface for AgentCert."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

import click

import agentcert
from agentcert.audit import create_audit_trail, log_action, load_trail, save_trail, get_trail_info
from agentcert.audit_verify import verify_audit_entry, verify_audit_trail
from agentcert.exceptions import AgentCertError
from agentcert.types import ActionType


def _parse_expires(value: str) -> int:
    """Parse an expiration string like '90d' or '90' into days."""
    value = value.strip().lower()
    if value.endswith("d"):
        value = value[:-1]
    try:
        days = int(value)
    except ValueError:
        raise click.BadParameter(f"Invalid expiration format: {value!r} (use e.g. '90d' or '90')")
    if days < 1:
        raise click.BadParameter("Expiration must be at least 1 day")
    return days


def _format_timestamp(ts: int) -> str:
    """Format a Unix timestamp as a human-readable UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _handle_error(func):
    """Decorator that catches AgentCertError and prints a clean message."""
    @click.pass_context
    def wrapper(ctx, *args, **kwargs):
        try:
            return ctx.invoke(func, *args, **kwargs)
        except AgentCertError as exc:
            click.secho(f"Error: {exc}", fg="red", err=True)
            sys.exit(1)
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


# ── Main group ───────────────────────────────────────────────────────────────


@click.group()
@click.version_option(version=agentcert.__version__, prog_name="agentcert")
def cli() -> None:
    """AgentCert — Bitcoin-anchored identity certificates for AI agents."""


# ── keygen ───────────────────────────────────────────────────────────────────


@cli.command()
@click.option("--output", "-o", required=True, help="Output file path for the key pair.")
@_handle_error
def keygen(output: str) -> None:
    """Generate a new secp256k1 key pair."""
    keys = agentcert.generate_keys()
    agentcert.save_keys(keys, output)
    click.echo(f"Key pair saved to {output}")
    click.echo(f"  Public key: {keys.public_key_hex}")
    click.echo(f"  Identity:   {keys.identity}")


# ── create ───────────────────────────────────────────────────────────────────


@cli.command()
@click.option("--creator-keys", required=True, help="Path to creator key pair JSON.")
@click.option("--agent-keys", required=True, help="Path to agent key pair JSON.")
@click.option("--name", required=True, help="Agent name.")
@click.option("--platform", required=True, help="Platform (e.g. langchain, autogen).")
@click.option("--model-hash", default="", help="Model hash (e.g. sha256:...).")
@click.option("--capabilities", default="", help="Comma-separated capabilities.")
@click.option("--constraints", default="", help="Comma-separated constraints.")
@click.option("--risk-tier", type=int, default=1, help="Risk tier (1-5).")
@click.option("--expires", default="90d", help="Expiration (e.g. '90d' or '90').")
@click.option("--output", "-o", required=True, help="Output file path for the certificate.")
@_handle_error
def create(
    creator_keys: str,
    agent_keys: str,
    name: str,
    platform: str,
    model_hash: str,
    capabilities: str,
    constraints: str,
    risk_tier: int,
    expires: str,
    output: str,
) -> None:
    """Create a new agent identity certificate."""
    ck = agentcert.load_keys(creator_keys)
    ak = agentcert.load_keys(agent_keys)

    caps = [c.strip() for c in capabilities.split(",") if c.strip()] if capabilities else []
    cons = [c.strip() for c in constraints.split(",") if c.strip()] if constraints else []
    days = _parse_expires(expires)

    cert = agentcert.create_certificate(
        creator_keys=ck,
        agent_keys=ak,
        name=name,
        platform=platform,
        model_hash=model_hash,
        capabilities=caps,
        constraints=cons,
        risk_tier=risk_tier,
        expires_days=days,
    )

    agentcert.save_certificate(cert, output)
    click.echo(f"Certificate saved to {output}")
    click.echo(f"  cert_id:  {cert.cert_id}")
    click.echo(f"  agent:    {name}")
    click.echo(f"  expires:  {_format_timestamp(cert.expires)}")


# ── anchor ───────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("cert_file")
@click.option("--creator-keys", required=True, help="Path to creator key pair JSON (for funding).")
@click.option("--network", default="testnet", type=click.Choice(["testnet", "mainnet"]), help="Bitcoin network.")
@click.option("--output", "-o", required=True, help="Output file path for the anchor receipt.")
@_handle_error
def anchor(cert_file: str, creator_keys: str, network: str, output: str) -> None:
    """Anchor a certificate to Bitcoin via OP_RETURN."""
    cert = agentcert.load_certificate(cert_file)
    ck = agentcert.load_keys(creator_keys)

    click.echo(f"Anchoring to Bitcoin {network}...")
    address = agentcert.derive_bitcoin_address(ck, network=network)
    click.echo(f"  Funding address: {address}")

    receipt = agentcert.anchor(cert, creator_keys=ck, network=network)
    agentcert.save_receipt(receipt, output)

    click.echo(f"Anchor receipt saved to {output}")
    click.echo(f"  txid: {receipt.txid}")


# ── verify ───────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("cert_file")
@click.option("--receipt", default=None, help="Path to anchor receipt JSON.")
@_handle_error
def verify(cert_file: str, receipt: str | None) -> None:
    """Verify a certificate (all 6 checks)."""
    cert = agentcert.load_certificate(cert_file)
    rcpt = agentcert.load_receipt(receipt) if receipt else None

    result = agentcert.verify(cert, rcpt)

    for check in result.checks:
        symbol = click.style("PASS", fg="green") if check.passed else click.style("FAIL", fg="red")
        click.echo(f"  [{symbol}] {check.name}: {check.detail}")

    click.echo()
    if result.valid:
        click.secho(f"Status: {result.status}", fg="green", bold=True)
    else:
        click.secho(f"Status: {result.status}", fg="red", bold=True)


# ── inspect ──────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("cert_file")
@_handle_error
def inspect(cert_file: str) -> None:
    """Display certificate details."""
    cert = agentcert.load_certificate(cert_file)

    type_names = {1: "CREATION", 2: "UPDATE", 3: "REVOCATION"}
    type_label = type_names.get(cert.cert_type, f"UNKNOWN({cert.cert_type})")

    click.echo(f"Certificate: {cert.cert_id}")
    click.echo(f"  AIT version:  {cert.ait_version}")
    click.echo(f"  Type:         {type_label} ({cert.cert_type})")
    click.echo(f"  Created:      {_format_timestamp(cert.timestamp)}")
    click.echo(f"  Expires:      {_format_timestamp(cert.expires)}")
    click.echo(f"  Creator:")
    click.echo(f"    Public key: {cert.creator_public_key}")
    click.echo(f"    ID:         {cert.creator_id}")
    click.echo(f"  Agent:")
    click.echo(f"    Public key: {cert.agent_public_key}")
    click.echo(f"    ID:         {cert.agent_id}")
    click.echo(f"  Metadata:")
    click.echo(f"    Name:         {cert.agent_metadata.name}")
    click.echo(f"    Platform:     {cert.agent_metadata.platform}")
    click.echo(f"    Model hash:   {cert.agent_metadata.model_hash}")
    click.echo(f"    Risk tier:    {cert.agent_metadata.risk_tier}")
    click.echo(f"    Capabilities: {', '.join(cert.agent_metadata.capabilities) or '(none)'}")
    click.echo(f"    Constraints:  {', '.join(cert.agent_metadata.constraints) or '(none)'}")
    if cert.previous_cert_id:
        click.echo(f"  Previous cert: {cert.previous_cert_id}")
    if cert.revocation_reason:
        click.echo(f"  Revocation:    {cert.revocation_reason}")
    click.echo(f"  Signature:     {cert.creator_signature[:32]}...")


# ── update ───────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("cert_file")
@click.option("--creator-keys", required=True, help="Path to creator key pair JSON.")
@click.option("--name", default=None, help="New agent name.")
@click.option("--platform", default=None, help="New platform.")
@click.option("--model-hash", default=None, help="New model hash.")
@click.option("--capabilities", default=None, help="Replace capabilities (comma-separated).")
@click.option("--add-capability", multiple=True, help="Add a capability (repeatable).")
@click.option("--constraints", default=None, help="Replace constraints (comma-separated).")
@click.option("--risk-tier", type=int, default=None, help="New risk tier (1-5).")
@click.option("--expires", default=None, help="New expiration (e.g. '90d').")
@click.option("--output", "-o", required=True, help="Output file path.")
@_handle_error
def update(
    cert_file: str,
    creator_keys: str,
    name: str | None,
    platform: str | None,
    model_hash: str | None,
    capabilities: str | None,
    add_capability: tuple[str, ...],
    constraints: str | None,
    risk_tier: int | None,
    expires: str | None,
    output: str,
) -> None:
    """Update a certificate (create a new version in the chain)."""
    prev = agentcert.load_certificate(cert_file)
    ck = agentcert.load_keys(creator_keys)

    # Resolve capabilities: --capabilities replaces, --add-capability appends
    caps = None
    if capabilities is not None:
        caps = [c.strip() for c in capabilities.split(",") if c.strip()]
    if add_capability:
        base = list(caps if caps is not None else prev.agent_metadata.capabilities)
        base.extend(add_capability)
        caps = base

    cons = None
    if constraints is not None:
        cons = [c.strip() for c in constraints.split(",") if c.strip()]

    days = _parse_expires(expires) if expires else None

    updated = agentcert.update_certificate(
        previous_cert=prev,
        creator_keys=ck,
        name=name,
        platform=platform,
        model_hash=model_hash,
        capabilities=caps,
        constraints=cons,
        risk_tier=risk_tier,
        expires_days=days,
    )

    agentcert.save_certificate(updated, output)
    click.echo(f"Updated certificate saved to {output}")
    click.echo(f"  cert_id:       {updated.cert_id}")
    click.echo(f"  previous_cert: {updated.previous_cert_id}")


# ── revoke ───────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("cert_file")
@click.option("--creator-keys", required=True, help="Path to creator key pair JSON.")
@click.option("--reason", required=True, help="Reason for revocation.")
@click.option("--output", "-o", required=True, help="Output file path.")
@_handle_error
def revoke(cert_file: str, creator_keys: str, reason: str, output: str) -> None:
    """Revoke a certificate."""
    prev = agentcert.load_certificate(cert_file)
    ck = agentcert.load_keys(creator_keys)

    rev = agentcert.revoke_certificate(
        previous_cert=prev,
        creator_keys=ck,
        reason=reason,
    )

    agentcert.save_certificate(rev, output)
    click.echo(f"Revocation certificate saved to {output}")
    click.echo(f"  cert_id: {rev.cert_id}")
    click.echo(f"  reason:  {reason}")


# ── verify-chain ─────────────────────────────────────────────────────────────


@cli.command("verify-chain")
@click.argument("cert_files", nargs=-1, required=True)
@_handle_error
def verify_chain(cert_files: tuple[str, ...]) -> None:
    """Verify a certificate chain (ordered list of cert files)."""
    certs = [agentcert.load_certificate(f) for f in cert_files]
    result = agentcert.verify_chain(certs)

    for check in result.checks:
        symbol = click.style("PASS", fg="green") if check.passed else click.style("FAIL", fg="red")
        click.echo(f"  [{symbol}] {check.name}: {check.detail}")

    click.echo()
    color = "green" if result.valid else "red"
    click.secho(f"Chain status: {result.status} ({result.chain_length} cert(s))", fg=color, bold=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Audit trail subcommand group
# ═══════════════════════════════════════════════════════════════════════════════


_ACTION_TYPES = {a.name.lower(): a for a in ActionType}
_ACTION_TYPE_NAMES = ", ".join(_ACTION_TYPES.keys())


def _parse_action_type(value: str) -> ActionType:
    """Parse an action type string (name or int) into an ActionType."""
    lower = value.strip().lower()
    if lower in _ACTION_TYPES:
        return _ACTION_TYPES[lower]
    try:
        return ActionType(int(value))
    except (ValueError, KeyError):
        raise click.BadParameter(
            f"Invalid action type: {value!r}. "
            f"Use a name ({_ACTION_TYPE_NAMES}) or integer."
        )


@cli.group()
def audit() -> None:
    """Audit trail commands (create, log, verify, inspect)."""


# ── audit create ─────────────────────────────────────────────────────────────


@audit.command("create")
@click.argument("cert_file")
@click.option("--agent-keys", required=True, help="Path to agent key pair JSON.")
@click.option("--output", "-o", required=True, help="Output file path for the audit trail.")
@_handle_error
def audit_create(cert_file: str, agent_keys: str, output: str) -> None:
    """Create a new audit trail bound to a certificate."""
    cert = agentcert.load_certificate(cert_file)
    ak = agentcert.load_keys(agent_keys)

    trail = create_audit_trail(cert, ak)
    save_trail(trail, output)

    click.echo(f"Audit trail created: {output}")
    click.echo(f"  trail_id: {trail.trail_id}")
    click.echo(f"  cert_id:  {trail.cert_id}")
    click.echo(f"  agent_id: {trail.agent_id}")


# ── audit log ────────────────────────────────────────────────────────────────


@audit.command("log")
@click.argument("trail_file")
@click.option("--agent-keys", required=True, help="Path to agent key pair JSON.")
@click.option("--action-type", required=True, help=f"Action type ({_ACTION_TYPE_NAMES}, or integer).")
@click.option("--summary", required=True, help="Brief description of the action.")
@click.option("--detail", default=None, help="JSON string with structured action details.")
@_handle_error
def audit_log(
    trail_file: str, agent_keys: str, action_type: str, summary: str, detail: str | None,
) -> None:
    """Log a new action to an audit trail."""
    trail = load_trail(trail_file)
    ak = agentcert.load_keys(agent_keys)
    at = _parse_action_type(action_type)

    action_detail = {}
    if detail:
        try:
            action_detail = json.loads(detail)
        except json.JSONDecodeError as exc:
            raise click.BadParameter(f"--detail must be valid JSON: {exc}")

    entry = log_action(
        trail, ak,
        action_type=at,
        action_summary=summary,
        action_detail=action_detail,
    )

    save_trail(trail, trail_file)

    click.echo(f"Action logged (entry {entry.sequence})")
    click.echo(f"  entry_id: {entry.entry_id}")
    click.echo(f"  type:     {ActionType(entry.action_type).name}")
    click.echo(f"  summary:  {entry.action_summary}")


# ── audit verify ─────────────────────────────────────────────────────────────


@audit.command("verify")
@click.argument("trail_file")
@click.option("--cert", "cert_file", default=None, help="Path to certificate JSON (for binding check).")
@_handle_error
def audit_verify(trail_file: str, cert_file: str | None) -> None:
    """Verify an audit trail (all 11 checks)."""
    trail = load_trail(trail_file)
    cert = agentcert.load_certificate(cert_file) if cert_file else None

    result = verify_audit_trail(trail, cert)

    for check in result.checks:
        symbol = click.style("PASS", fg="green") if check.passed else click.style("FAIL", fg="red")
        click.echo(f"  [{symbol}] {check.name}: {check.detail}")

    click.echo()
    if result.valid:
        click.secho(
            f"Status: {result.status} ({result.entry_count} entry(ies))",
            fg="green", bold=True,
        )
    else:
        click.secho(
            f"Status: {result.status} ({result.entry_count} entry(ies))",
            fg="red", bold=True,
        )


# ── audit inspect ────────────────────────────────────────────────────────────


@audit.command("inspect")
@click.argument("trail_file")
@click.option("--entries/--no-entries", default=False, help="Show individual entries.")
@_handle_error
def audit_inspect(trail_file: str, entries: bool) -> None:
    """Display audit trail details."""
    trail = load_trail(trail_file)
    info = get_trail_info(trail)

    click.echo(f"Audit Trail: {info.trail_id}")
    click.echo(f"  cert_id:     {info.cert_id}")
    click.echo(f"  agent_id:    {info.agent_id}")
    click.echo(f"  entries:     {info.entry_count}")
    click.echo(f"  created:     {_format_timestamp(info.created)}")
    if info.last_entry:
        click.echo(f"  last entry:  {_format_timestamp(info.last_entry)}")

    if entries and trail.entries:
        click.echo()
        for entry in trail.entries:
            action_name = ActionType(entry.action_type).name
            click.echo(f"  [{entry.sequence}] {_format_timestamp(entry.timestamp)} "
                        f"{action_name}: {entry.action_summary}")
            click.echo(f"       entry_id: {entry.entry_id}")
            if entry.action_detail:
                click.echo(f"       detail:   {json.dumps(entry.action_detail)}")
