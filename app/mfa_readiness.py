"""Production readiness checks for privileged MFA enforcement."""
from __future__ import annotations

import json
import sqlite3

from . import auth

PRIVILEGED_MFA_ROLES=("admin","superadmin")


def privileged_mfa_readiness() -> dict:
    """Return aggregate-only readiness for privileged MFA.

    Tenants without active privileged users are ignored. No user or tenant
    identifiers are returned so this status is safe for operational readiness.
    """
    conn=None
    try:
        conn=auth._db()
        tenants=conn.execute("SELECT id FROM tenants WHERE active=1").fetchall()
        checked=0
        not_ready=0
        missing_policy=0
        unenrolled=0
        for tenant in tenants:
            tenant_id=tenant["id"]
            privileged=conn.execute(
                """SELECT COUNT(*) AS total FROM users
                   WHERE tenant_id=? AND active=1 AND role IN (?,?)""",
                (tenant_id,*PRIVILEGED_MFA_ROLES),
            ).fetchone()["total"]
            if int(privileged or 0)==0:
                continue
            checked+=1
            policy=conn.execute(
                "SELECT mfa_required_roles FROM tenant_security_policy WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            try:
                roles=set(json.loads(policy["mfa_required_roles"])) if policy else set()
            except (TypeError,ValueError,json.JSONDecodeError):
                roles=set()
            policy_gap=not set(PRIVILEGED_MFA_ROLES).issubset(roles)
            missing=conn.execute(
                """SELECT COUNT(*) AS total FROM users u
                   LEFT JOIN users_mfa m ON m.user_id=u.id AND m.enabled=1
                   WHERE u.tenant_id=? AND u.active=1 AND u.role IN (?,?)
                     AND m.user_id IS NULL""",
                (tenant_id,*PRIVILEGED_MFA_ROLES),
            ).fetchone()["total"]
            missing=int(missing or 0)
            if policy_gap:
                missing_policy+=1
            unenrolled+=missing
            if policy_gap or missing:
                not_ready+=1
        return {
            "status":"healthy" if not_ready==0 else "degraded",
            "required_roles":list(PRIVILEGED_MFA_ROLES),
            "tenants_checked":checked,
            "tenants_not_ready":not_ready,
            "tenants_missing_policy":missing_policy,
            "privileged_users_without_mfa":unenrolled,
        }
    except (sqlite3.Error,KeyError):
        return {
            "status":"unavailable",
            "required_roles":list(PRIVILEGED_MFA_ROLES),
            "tenants_checked":0,
            "tenants_not_ready":0,
            "tenants_missing_policy":0,
            "privileged_users_without_mfa":0,
        }
    finally:
        if conn is not None:
            conn.close()
