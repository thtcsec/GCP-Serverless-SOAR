import os
from unittest.mock import patch

import pytest

from src.cross_project.cross_project_responder import CrossProjectResponder


def test_cross_project_map_from_json():
    payload = (
        '{"dev":{"project_id":"valid-dev-project","target_sa":"soar-dev@valid-dev-project.iam.gserviceaccount.com"}}'
    )
    with patch.dict(
        os.environ,
        {
            "CROSS_PROJECT_ACCOUNT_MAP": payload,
            "CROSS_PROJECT_STRICT_CONFIG": "true",
        },
        clear=False,
    ):
        responder = CrossProjectResponder(environment="dev")
    assert responder.account["project_id"] == "valid-dev-project"
    assert responder.account["target_sa"] == "soar-dev@valid-dev-project.iam.gserviceaccount.com"


def test_cross_project_strict_validation_raises():
    payload = '{"prod":{"project_id":"bad","target_sa":"invalid"}}'
    with (
        patch.dict(
            os.environ,
            {
                "CROSS_PROJECT_ACCOUNT_MAP": payload,
                "CROSS_PROJECT_STRICT_CONFIG": "true",
            },
            clear=False,
        ),
        pytest.raises(ValueError),
    ):
        CrossProjectResponder(environment="prod")


def test_cross_project_env_override():
    payload = '{"staging":{"project_id":"old-project","target_sa":"old@old-project.iam.gserviceaccount.com"}}'
    with patch.dict(
        os.environ,
        {
            "CROSS_PROJECT_ACCOUNT_MAP": payload,
            "STAGING_TARGET_PROJECT_ID": "new-staging-project",
            "STAGING_TARGET_SERVICE_ACCOUNT": "soar-staging@new-staging-project.iam.gserviceaccount.com",
            "CROSS_PROJECT_STRICT_CONFIG": "true",
        },
        clear=False,
    ):
        responder = CrossProjectResponder(environment="staging")
    assert responder.account["project_id"] == "new-staging-project"
    assert responder.account["target_sa"] == "soar-staging@new-staging-project.iam.gserviceaccount.com"
