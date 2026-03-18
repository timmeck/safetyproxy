"""SafetyProxy CLI — Click-based command interface."""

import asyncio

import click

from src.config import SAFETYPROXY_PORT
from src.db.database import Database


def run_async(coro):
    """Run an async coroutine from sync context."""
    return asyncio.get_event_loop().run_until_complete(coro)


@click.group()
def cli():
    """SafetyProxy — Self-hosted AI Safety Proxy."""
    pass


@cli.command()
def status():
    """Show SafetyProxy status."""
    db = Database()
    run_async(db.initialize())
    stats = run_async(db.get_stats())
    click.echo("SafetyProxy v1.0.0")
    click.echo(f"  Active apps:       {stats['active_apps']}")
    click.echo(f"  Total requests:    {stats['total_requests']}")
    click.echo(f"  Total violations:  {stats['total_violations']}")
    click.echo(f"  Requests today:    {stats['requests_today']}")
    click.echo(f"  Blocked today:     {stats['blocked_today']}")
    click.echo(f"  PII redacted:      {stats['pii_redacted_today']}")
    click.echo(f"  Injection blocked: {stats['injection_attempts_today']}")


@cli.command()
def apps():
    """List registered apps."""
    db = Database()
    run_async(db.initialize())
    app_list = run_async(db.get_apps())
    if not app_list:
        click.echo("No registered apps.")
        return
    click.echo(f"{'ID':<5} {'Name':<20} {'Policy':<15} {'Status':<10} {'API Key':<30}")
    click.echo("-" * 80)
    for a in app_list:
        key_display = a["api_key"][:16] + "..." if a.get("api_key") else "-"
        click.echo(
            f"{a['id']:<5} {a['name']:<20} {a.get('policy_name', 'default'):<15} {a['status']:<10} {key_display:<30}"
        )


@cli.command()
@click.argument("name")
@click.option("--policy", default=None, help="Policy name to assign")
def register(name, policy):
    """Register a new app and generate an API key."""
    db = Database()
    run_async(db.initialize())
    policy_id = None
    if policy:
        p = run_async(db.get_policy_by_name(policy))
        if p:
            policy_id = p["id"]
        else:
            click.echo(f"Policy '{policy}' not found. Using default.")
    result = run_async(db.register_app(name, policy_id))
    click.echo(f"App registered: {result['name']}")
    click.echo(f"  API Key: {result['api_key']}")
    click.echo(f"  Policy ID: {result['policy_id']}")


@cli.command()
def policies():
    """List security policies."""
    db = Database()
    run_async(db.initialize())
    policy_list = run_async(db.get_policies())
    if not policy_list:
        click.echo("No policies configured.")
        return
    click.echo(f"{'ID':<5} {'Name':<15} {'Injection':<12} {'PII':<10} {'Content':<10} {'RPM':<8} {'RPH':<8} {'RPD':<8}")
    click.echo("-" * 76)
    for p in policy_list:
        click.echo(
            f"{p['id']:<5} {p['name']:<15} {p['injection_threshold']:<12} {p['pii_mode']:<10} {p['content_action']:<10} {p['rate_limit_rpm']:<8} {p['rate_limit_rph']:<8} {p['rate_limit_rpd']:<8}"
        )


@cli.command("create-policy")
@click.argument("name")
@click.option("--preset", type=click.Choice(["strict", "moderate", "permissive"]), default=None, help="Use a preset")
@click.option("--injection-threshold", type=int, default=70, help="Injection score threshold (0-100)")
@click.option("--pii-mode", type=click.Choice(["detect", "redact", "block"]), default="redact")
@click.option("--content-action", type=click.Choice(["warn", "block"]), default="block")
@click.option("--rpm", type=int, default=60, help="Rate limit per minute")
@click.option("--rph", type=int, default=1000, help="Rate limit per hour")
@click.option("--rpd", type=int, default=10000, help="Rate limit per day")
def create_policy(name, preset, injection_threshold, pii_mode, content_action, rpm, rph, rpd):
    """Create a new security policy."""
    db = Database()
    run_async(db.initialize())
    if preset:
        from src.guard.policies import PolicyManager

        pm = PolicyManager(db)
        pid = run_async(pm.create_from_preset(name, preset))
        click.echo(f"Policy '{name}' created from preset '{preset}' (ID: {pid})")
    else:
        pid = run_async(
            db.create_policy(
                name,
                injection_threshold=injection_threshold,
                pii_mode=pii_mode,
                content_action=content_action,
                rate_limit_rpm=rpm,
                rate_limit_rph=rph,
                rate_limit_rpd=rpd,
            )
        )
        click.echo(f"Policy '{name}' created (ID: {pid})")


@cli.command()
@click.option("--limit", type=int, default=20, help="Number of violations to show")
def violations(limit):
    """Show recent violations."""
    db = Database()
    run_async(db.initialize())
    viols = run_async(db.get_violations(limit=limit))
    if not viols:
        click.echo("No violations recorded.")
        return
    click.echo(f"{'ID':<5} {'App':<15} {'Type':<15} {'Severity':<10} {'Details':<50}")
    click.echo("-" * 95)
    for v in viols:
        details = (v["details"] or "")[:50]
        app_name = v.get("app_name", f"App #{v['app_id']}")
        click.echo(f"{v['id']:<5} {app_name:<15} {v['violation_type']:<15} {v['severity']:<10} {details:<50}")


@cli.command()
@click.option("--host", default="0.0.0.0", help="Bind host")
@click.option("--port", type=int, default=None, help="Bind port")
def serve(host, port):
    """Start the SafetyProxy dashboard and API server."""
    import uvicorn

    actual_port = port or SAFETYPROXY_PORT
    click.echo(f"Starting SafetyProxy on {host}:{actual_port}")
    uvicorn.run("src.web.api:app", host=host, port=actual_port, reload=False)


if __name__ == "__main__":
    cli()
