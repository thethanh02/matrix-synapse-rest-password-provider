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
        self.laoid_verify_url = config.get("laoid_verify_url", "https://demo-sso.tinasoft.io/api/v1/third-party/verify")
        self.laoid_client_id = config.get("laoid_client_id", "client_id")
        self.laoid_secret = config.get("laoid_secret", "secret")
        self.jwt_secret = config.get("jwt_secret", "secret")
        self.jwt_alg = config.get("jwt_alg", "HS512")
        self._sso_handler = api._hs.get_sso_handler()

        api.register_password_auth_provider_callbacks(
            auth_checkers={
                ("my.login_lao_id", ("authorization_code",)): self.check_my_login,
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
        if login_type != "my.login_lao_id":
            return None

        logger.info("login_dict %s", login_dict)
        # response = await self._verify_credentials(login_dict.get("authorization_code"))

        # logger.info("response %s", response)
        # if not response.get("success"):
        #     return None
        # token = response.get("data").get("idToken")

        # # TODO: verify secret and alg
        # # logger.info(jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_alg]))
        # user = jwt.decode(token, options={"verify_signature": False}).get('user')
        # logger.info("----")
        # logger.info("user: %s", user)

        localpart = f"user_123"
        # localpart = f"user_{user.get('id')}"
        # user_id = f"@{localpart}:{self.api._hs.hostname}"

        # if not await self.api.check_user_exists(user_id):
        #     registered_user_id = await self.api.register_user(
        #         localpart=localpart,
        #         displayname=user.get("username")
        #     )
        #     logger.info("----registered_user_id---- %s", registered_user_id)

        #     if user.get("avatar"):
        #         logger.info("----avatar----")
        #         await self._sso_handler.set_avatar(registered_user_id, user.get("avatar"))

        return (self.api.get_qualified_user_id(localpart), None)

    async def _verify_credentials(self, code: str) -> dict:
        """
        Verify credentials against custom API
        """
        try:
            headers = {
                "Content-Type": ["application/json"],
            }

            response = await self.api.http_client.post_json_get_json(
                uri=self.laoid_verify_url,
                post_json={
                    "code": code,
                    "clientId": self.laoid_client_id,
                    "clientSecret": self.laoid_secret,
                    "isReturnRefreshToken": False
                },
                headers=headers
            )

            return response
        except Exception as e:
            logger.error("API verification failed: %s", e)
            return {"success": False}

    @staticmethod
    def parse_config(config: dict) -> dict:
        if "laoid_verify_url" not in config:
            raise ValueError("laoid_verify_url is required")
        if "laoid_client_id" not in config:
            raise ValueError("laoid_client_id is required")
        if "laoid_secret" not in config:
            raise ValueError("laoid_secret is required")
        if "jwt_secret" not in config:
            raise ValueError("jwt_secret is required")
        return config
