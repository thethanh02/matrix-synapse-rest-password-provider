from typing import Awaitable, Callable, Optional, Tuple

import synapse
from synapse import module_api


class MyAuthProvider:
    def __init__(self, config: dict, api: module_api):

        self.api = api

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

        return (self.api.get_qualified_user_id(username), None)
