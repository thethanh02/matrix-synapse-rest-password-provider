import logging
from typing import Optional, Tuple
import jwt
import requests
from twisted.internet import defer
from synapse.api.errors import SynapseError
from synapse.module_api import ModuleApi, UserProfile

logger = logging.getLogger(__name__)

class CustomAuthProvider:
  def __init__(self, config: dict, api: ModuleApi):
    self.api = api
    self.custom_api_url = config.get("custom_api_url", "https://demo-network.tinasoft.io/third-party/verify")
    self.custom_api_secret = config.get("custom_api_secret", "your-secret")
    
    # Register callbacks
    api.register_password_auth_provider(
      auth_checkers={
        "m.login.password": self.check_auth,
      }
    )

  @staticmethod
  def parse_config(config: dict) -> dict:
    if "custom_api_url" not in config:
      raise ValueError("custom_api_url is required")
    if "custom_api_secret" not in config:
      raise ValueError("custom_api_secret is required")
    return config

  async def check_auth(
    self, username: str, login_type: str, login_dict: dict
  ) -> Optional[Tuple[str, UserProfile]]:
    """
    Check authentication against custom API and handle user registration
    """
    logger.info(username)
    logger.info(login_type)
    logger.info(login_dict)
    if "password" not in login_dict:
      return None

    try:
      # Call your custom API for verification
      # response = await self._verify_credentials(
      #   username, 
      #   login_dict["password"]
      # )
      
      # if not response.get("success"):
      #   return None

      # Get or create localpart (username part of MXID)
      localpart = self._get_localpart(username)
      
      # Check if user exists in Matrix
      user_id = "@%s:%s" % (localpart, self.api.server_name)
      if not await self.api.check_user_exists(user_id):
        # Register new user if doesn't exist
        user_profile = UserProfile(
          display_name="display_name",
          avatar_url=""
        )
        
        await self.api.register_user(
          localpart=localpart,
          profile=user_profile,
          admin=False
        )
      
      return user_id, UserProfile()

    except Exception as e:
      self.api.log.error("Auth error: %s", e)
      raise SynapseError(500, "Internal server error")

  async def _verify_credentials(self, username: str, password: str) -> dict:
    """
    Verify credentials against custom API
    """
    try:
      # Create signed token for API request
      token = jwt.encode(
        {"username": username},
        self.custom_api_secret,
        algorithm="HS256"
      )
      
      # Make request to custom API
      headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
      }
      
      response = await self.api.http_client.post_json_get_json(
        uri=f"{self.custom_api_url}/verify",
        post_json={
          "username": username,
          "password": password
        },
        headers=headers
      )
      
      return response

    except Exception as e:
      self.api.log.error("API verification failed: %s", e)
      return {"success": False}

  def _get_localpart(self, username: str) -> str:
    """
    Convert username to valid Matrix localpart
    """
    # Remove invalid characters and ensure valid Matrix username
    import re
    localpart = re.sub(r'[^a-zA-Z0-9._=/-]', '', username)
    return localpart.lower()
