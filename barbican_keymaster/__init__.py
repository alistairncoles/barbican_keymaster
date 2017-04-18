# Copyright (c) 2015 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
import hmac

from castellan import key_manager, options
from castellan.common.credentials import keystone_password
from oslo_config import cfg

from swift.common.middleware.crypto.keymaster import KeyMasterContext
from swift.common.swob import Request, HTTPException
from swift.common.utils import readconf, get_logger


class BarbicanKeyMaster(object):
    """Middleware for providing encryption keys.

    The middleware requires its encryption root secret to be set. This is the
    root secret from which encryption keys are derived. This must be set before
    first use to a value that is at least 256 bits. The security of all
    encrypted data critically depends on this key, therefore it should be set
    to a high-entropy value. For example, a suitable value may be obtained by
    generating a 32 byte (or longer) value using a cryptographically secure
    random number generator. Changing the root secret is likely to result in
    data loss.
    """

    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf, log_route='barbican_keymaster')
        self.keymaster_config_path = conf.get('keymaster_config_path')
        # The _get_root_secret() function is overridden by other keymasters
        self.root_secret = self._get_root_secret(conf)

    def _get_root_secret(self, conf):
        """
        Retrieve the root encryption secret from an external key management
        system using Castellan.

        :param conf: the keymaster config section from proxy-server.conf
        :type conf: dict

        :return: the encryption root secret binary bytes
        :rtype: bytearray
        """
        if self.keymaster_config_path is not None:
            if any(opt in conf for opt in ('key_id',)):
                raise ValueError('keymaster_config_path is set, but there '
                                 'are other config options specified!')
            conf = readconf(self.keymaster_config_path, 'kms_keymaster')
        self.logger.info("Attempting to retrieve secret %s from %s" %
                         (conf.get('key_id'), conf.get('auth_endpoint')))
        ctxt = keystone_password.KeystonePassword(
            username=conf.get('username'),
            password=conf.get('password'),
            project_name=conf.get('project_name'),
            user_domain_name=conf.get('user_domain_name'),
            project_domain_name=conf.get(
                'project_domain_name'),
            user_id=conf.get('user_id'),
            user_domain_id=conf.get('user_domain_id'),
            trust_id=conf.get('trust_id'),
            domain_id=conf.get('domain_id'),
            domain_name=conf.get('domain_name'),
            project_id=conf.get('project_id'),
            project_domain_id=conf.get('project_domain_id'),
            reauthenticate=conf.get('reauthenticate'))
        oslo_conf = cfg.ConfigOpts()
        options.set_defaults(
            oslo_conf, auth_endpoint=conf.get('auth_endpoint'),
            api_class=conf.get('api_class')
        )
        options.enable_logging()
        manager = key_manager.API(oslo_conf)
        key = manager.get(ctxt, conf.get('key_id'))
        if (key.bit_length < 256) or (key.algorithm.lower() != "aes"):
            raise ValueError('encryption root secret stored in the external '
                             'KMS must be an AES key of at least 256 bits '
                             '(provided key length: %d, provided key '
                             'algorithm: %s)'
                             % (key.bit_length, key.algorithm))
        if (key.format != 'RAW'):
            raise ValueError('encryption root secret stored in the external '
                             'KMS must be in RAW format and not e.g., as a '
                             'base64 encoded string (format of key with uuid '
                             '%s: %s)' % (conf.get('key_id'), key.format))
        secret = key.get_encoded()
        self.logger.info("Successfully retrieved secret %s from %s" %
                         (conf.get('key_id'), conf.get('auth_endpoint')))
        return secret

    def __call__(self, env, start_response):
        req = Request(env)

        try:
            parts = req.split_path(2, 4, True)
        except ValueError:
            return self.app(env, start_response)

        if req.method in ('PUT', 'POST', 'GET', 'HEAD'):
            # handle only those request methods that may require keys
            km_context = KeyMasterContext(self, *parts[1:])
            try:
                return km_context.handle_request(req, start_response)
            except HTTPException as err_resp:
                return err_resp(env, start_response)

        # anything else
        return self.app(env, start_response)

    def create_key(self, key_id):
        return hmac.new(self.root_secret, key_id,
                        digestmod=hashlib.sha256).digest()


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def keymaster_filter(app):
        return BarbicanKeyMaster(app, conf)

    return keymaster_filter
