import pytest


@pytest.fixture(autouse=True)
def _reset_token_cache():
    import dws_autopilot_mcp.token_manager as tm
    tm._cached_token = ""
    tm._token_expire_at = 0.0
    yield
    tm._cached_token = ""
    tm._token_expire_at = 0.0
