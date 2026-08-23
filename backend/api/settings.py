"""Storage and tool API key configuration management."""
from __future__ import annotations
from fastapi import APIRouter

from models import ToolApiKeysConfig
from tool_secrets import apply_tool_api_keys, mask_tool_api_keys, merge_tool_api_keys

router = APIRouter(prefix="/settings", tags=["settings"])


def _get_storage():
    from main import storage
    return storage


@router.get("/api-keys")
async def get_tool_api_keys():
    cfg = await _get_storage().load_tool_api_keys()
    return mask_tool_api_keys(cfg)


@router.post("/api-keys")
async def save_tool_api_keys(body: ToolApiKeysConfig):
    storage = _get_storage()
    existing = await storage.load_tool_api_keys()
    cfg = merge_tool_api_keys(existing, body.model_dump())
    await storage.save_tool_api_keys(cfg)
    apply_tool_api_keys(cfg)
    return {"ok": True}
