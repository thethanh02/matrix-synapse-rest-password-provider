# -*- coding: utf-8 -*-
#
# REST endpoint Authentication module for Matrix synapse
# Copyright (C) 2017 Kamax Sarl
#
# https://www.kamax.io/
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import logging
import requests
import json
import time
from synapse.module_api import ModuleApi

logger = logging.getLogger(__name__)


class RestAuthProvider(object):

    def __init__(self, config, account_handler, api: ModuleApi):
        self.api = api
        self.account_handler = account_handler

        # if not config.endpoint:
        #     raise RuntimeError('Missing endpoint config')

        # self.endpoint = config.endpoint
        self.regLower = config.regLower
        self.config = config

        # logger.info('Endpoint: %s', self.endpoint)
        logger.info('Enforce lowercase username during registration: %s', self.regLower)

    def get_localpart_from_id(self, user_id: str) -> str:
        """Extract localpart from user_id.
        Example: "@user:domain.com" -> "user"
        """
        if user_id.startswith("@"):
            return user_id[1:].split(":")[0]
        return user_id.split(":")[0]

    async def check_password(self, user_id, password):
        logger.info("Got password check for " + user_id)
        data = {'user': {'id': user_id, 'password': password}}

        localpart = self.get_localpart_from_id(user_id)
        
        if self.regLower:
            localpart = localpart.lower()

        if not await self.api.check_user_exists(user_id):
            user_profile = UserProfile(
                display_name="display_name",
                avatar_url=""
            )
            
            await self.api.register_user(
                localpart=localpart,
                profile=user_profile,
                admin=False
            )

        return True

    @staticmethod
    def parse_config(config):
        # verify config sanity
        # _require_keys(config, ["endpoint"])

        class _RestConfig(object):
            # endpoint = ''
            regLower = True
            setNameOnRegister = True
            setNameOnLogin = False
            updateThreepid = True
            replaceThreepid = False

        rest_config = _RestConfig()
        # rest_config.endpoint = config["endpoint"]

        try:
            rest_config.regLower = config['policy']['registration']['username']['enforceLowercase']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.setNameOnRegister = config['policy']['registration']['profile']['name']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.setNameOnLogin = config['policy']['login']['profile']['name']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.updateThreepid = config['policy']['all']['threepid']['update']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        try:
            rest_config.replaceThreepid = config['policy']['all']['threepid']['replace']
        except TypeError:
            # we don't care
            pass
        except KeyError:
            # we don't care
            pass

        return rest_config


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise Exception(
            "REST Auth enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )


def time_msec():
    """Get the current timestamp in milliseconds
    """
    return int(time.time() * 1000)
