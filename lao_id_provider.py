import logging
from typing import Awaitable, Callable, Optional, Tuple
import jwt
import requests
import synapse
from synapse import module_api

logger = logging.getLogger(__name__)

class MyAuthProvider:
    def __init__(self, config: dict, api: module_api):

        self.api = api
        self.laoid_verify_url = config.get("laoid_verify_url", "https://demo-network.tinasoft.io/third-party/verify")
        self.laoid_client_id = config.get("laoid_client_id", "client_id")
        self.laoid_secret = config.get("laoid_secret", "secret")

        api.register_password_auth_provider_callbacks(
            auth_checkers={
                ("my.login_type", ("my_field",)): self.check_my_login,
            },
        )

    async def check_my_login(
        self,
        username: str,
        login_type: str,
        login_dict: "synapse.module_api.JsonDict",
    ) -> Optional[
        Tuple[
            str,
            Optional[Callable[["synapse.module_api.LoginResponse"], Awaitable[None]]],
        ]
    ]:
        if login_type != "my.login_type":
            return None

        logger.info(login_dict)
        response = await self._verify_credentials(login_dict.get("my_field"))

        logger.info(response)
        if response.status_code != 200:
            return None
        if not response.get("success"):
            return None
        token = response.get("data").get("accessToken")

        logger.info(jwt.decode(token, "secret", algorithms=["HS256"]))

        return (self.api.get_qualified_user_id(username), None)

    async def _verify_credentials(self, code: str) -> dict:
        """
        Verify credentials against custom API
        """
        try:
            headers = {
                "Content-Type": "application/json"
            }
            
            response = await self.api.http_client.post_json_get_json(
                uri=self.laoid_verify_url,
                post_json={
                    "code": code,
                    "clientId": laoid_client_id,
                    "clientSecret": laoid_secret,
                    "isReturnRefreshToken": False
                },
                headers=headers
            )
            
            return response

    @staticmethod
    def parse_config(config: dict) -> dict:
        if "laoid_verify_url" not in config:
            raise ValueError("laoid_verify_url is required")
        if "laoid_client_id" not in config:
            raise ValueError("laoid_client_id is required")
        if "laoid_secret" not in config:
            raise ValueError("laoid_secret is required")
        return config
