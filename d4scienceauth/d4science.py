"""D4Science Authenticator for JupyterHub
"""

import base64
import hashlib
import json
import os

from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPError, HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import Authenticator, LocalAuthenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join


D4SCIENCE_SOCIAL_URL = (os.environ.get('D4SCIENCE_SOCIAL_URL') or
                        'https://socialnetworking1.d4science.org/'
                        'social-networking-library-ws/rest/')
                        
D4SCIENCE_PROFILE= '2/people/profile'


class D4ScienceLoginHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        user = self.get_current_user()
        if user:
            # make sure we don't do a mess here
            self.clear_login_cookie()
        token = self.get_argument('gcube-token', '')
        http_client = AsyncHTTPClient()
        url = url_concat(url_path_join(D4SCIENCE_SOCIAL_URL,
                                       D4SCIENCE_PROFILE),
                        {'gcube-token': token})
        req = HTTPRequest(url, method='GET')
        try:
            resp = yield http_client.fetch(req)
        except HTTPError as e:
            # whatever, get out
            self.log.warning('Something happened with gcube service: %s', e)
            raise web.HTTPError(403)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        username = resp_json.get('result', {}).get('username', '')
        if not username:
            self.log.error('Unable to get the user from gcube?')
            raise web.HTTPError(403)

        self.log.info('%s is now authenticated!', username)
        auth_state = {'gcube-token': token, 'gcube-user': username}
        auth_state.update(resp_json['result'])
        name = '%s-%s' % (username, 
                          hashlib.sha512(token.encode('utf-8')).hexdigest())
        return {'name': name, 'auth_state': auth_state}

class D4ScienceAuthenticator(Authenticator):
    auto_login = True

    def login_url(self, base_url):
        return url_path_join(base_url, 'gcube-login')

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """Pass gcube-token to spawner via environment variable"""
        auth_state = yield user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return
        spawner.environment['GCUBE_TOKEN'] = auth_state['gcube-token']

    def get_handlers(self, app):
        #base = super(Authenticator, self).get_handlers(app)
        return((r'/gcube-login', self.login_handler))
        #return base
