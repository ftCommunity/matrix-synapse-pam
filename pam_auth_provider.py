# Copyright 2017 Willem Mulder
#
# Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
# the European Commission - subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the Licence is distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the Licence for the specific language governing permissions and
# limitations under the Licence.

import pam

from collections import namedtuple
from synapse import types

class PAMAuthProvider:
    def __init__(self, config, account_handler):
        self.account_handler = account_handler
        self.create_users = config.create_users

    async def check_password(self, user_id, password):
        """ Attempt to authenticate a user against PAM
            and register an account if none exists.

            Returns:
                True if authentication against PAM was successful,
                False if not
        """
        if not password:
            return False
        # user_id is of the form @foo:bar.com
        localpart = user_id.split(":", 1)[0][1:]

        # check if localpart is a valid mxid.
        # If not, bail out without even checking PAM because
        # we can't create a user with that id anyway.
        if types.contains_invalid_mxid_characters(localpart):
            return False

        # Now check the password
        if not pam.pam().authenticate(localpart, password, service='matrix-synapse'):
            return False

        # From here on, the user is authenticated
        if (await self.account_handler.check_user_exists(user_id)):
            return True

        if self.create_users:
            user_id = await self.account_handler.register_user(localpart=localpart)
            return bool(user_id)

        return False

    @staticmethod
    def parse_config(config):
        pam_config = namedtuple('_Config', 'create_users')
        pam_config.create_users = config.get('create_users', True)

        return pam_config
