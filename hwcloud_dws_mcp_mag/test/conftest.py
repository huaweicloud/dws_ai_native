import pytest


@pytest.fixture(autouse=True)
def _reset_config():
    import dws_autopilot_mcp.config as cfg
    original_ak = cfg.SDK_AK
    original_sk = cfg.SDK_SK
    original_project_id = cfg.PROJECT_ID
    yield
    cfg.SDK_AK = original_ak
    cfg.SDK_SK = original_sk
    cfg.PROJECT_ID = original_project_id
