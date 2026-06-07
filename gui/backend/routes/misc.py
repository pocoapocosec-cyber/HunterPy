"""Settings, tools, auth — small misc endpoints."""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from config.tool_paths import ToolPathValidator, REQUIRED_TOOLS, OPTIONAL_TOOLS
from gui.backend.schemas import GenericMessage, ToolStatus


tools_router    = APIRouter(prefix="/api/tools",    tags=["tools"])
settings_router = APIRouter(prefix="/api/settings", tags=["settings"])
auth_router     = APIRouter(prefix="/api/auth",     tags=["auth"])
ua_router       = APIRouter(prefix="/api/user-agents", tags=["user-agents"])


@ua_router.get("")
def list_user_agent_presets() -> Dict[str, Any]:
    """Return the catalogue of UA presets + supported rotation strategies.

    The frontend uses this to populate the "User-Agent" dropdown in the
    scan-options panel. The `category` field is what lets the UI flag
    impersonation presets (Googlebot/Bingbot) with a warning badge.
    """
    from config.user_agents import (
        PRESETS, DEFAULT_USER_AGENT, UserAgentSelector,
    )
    return {
        "default":     DEFAULT_USER_AGENT,
        "strategies":  list(UserAgentSelector.STRATEGIES),
        "presets": [
            {
                "name":        p.name,
                "category":    p.category,
                "description": p.description,
                "count":       len(p.user_agents),
                "user_agents": list(p.user_agents),
            }
            for p in PRESETS.values()
        ],
    }


@tools_router.get("", response_model=List[ToolStatus])
def list_tools() -> List[ToolStatus]:
    statuses = ToolPathValidator().check_all_tools(console=None)
    out: List[ToolStatus] = []
    for name, info in statuses.items():
        out.append(ToolStatus(
            name=name,
            available=bool(info.get("available")),
            path=info.get("path"),
            version=info.get("version"),
            required=name in REQUIRED_TOOLS,
        ))
    return out


# In-memory settings store. Production would persist these in the SQLite
# DB or a YAML config; that's out of scope for v2.1.
_SETTINGS: Dict[str, Any] = {
    "default_mode":  "passive",
    "default_threads": 10,
    "default_rate_limit": 10,
    "nvd_api_key": "",
    "notifications_enabled": True,
}


@settings_router.get("")
def get_settings() -> Dict[str, Any]:
    return dict(_SETTINGS)


@settings_router.put("", response_model=GenericMessage)
def update_settings(payload: Dict[str, Any]) -> GenericMessage:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be an object")
    _SETTINGS.update({k: v for k, v in payload.items() if k in _SETTINGS})
    return GenericMessage(message="settings updated")


@auth_router.post("/login")
def login(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Stub login — accepts any non-empty credentials.

    Real auth is intentionally out of scope: HunterPy is a self-hosted
    internal tool and the threat model assumes the operator already
    controls the host. If you expose this API to the public internet,
    put a reverse proxy with proper auth in front of it.
    """
    user = (payload or {}).get("username", "")
    pw   = (payload or {}).get("password", "")
    if not user or not pw:
        raise HTTPException(status_code=400, detail="username + password required")
    return {
        "token": f"hunterpy-stub-token-{user}",
        "user":  {"name": user, "role": "analyst"},
    }


@auth_router.get("/me")
def me() -> Dict[str, Any]:
    return {"user": {"name": "local-operator", "role": "admin"}}
