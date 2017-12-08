# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# pylint: disable=C0103

# FIXME:
#
# pylint: disable=W1505


import unittest
import time

import webtest

from zope.interface.verify import verifyClass


import hawkauthlib

from pyramid_hawkauth import HawkAuthenticationPolicy


from pyramid.config import Configurator
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.httpexceptions import HTTPUnauthorized

from pyramid.security import (
    authenticated_userid
    , Everyone
    , Authenticated
    , )


from . helper import *   # pylint: disable=W0401, W0614


TEST_PREFIX="pyramid_hawkauth.tests.helper"

class TestHawkAuthenticationPolicy(unittest.TestCase):
    """Testcases for the HawkAuthenticationPolicy class."""

    def setUp(self):
        self.config = Configurator(settings={
            "hawkauth.find_groups": TEST_PREFIX + ":stub_find_groups",
        })
        self.config.include("pyramid_hawkauth")
        self.config.add_route("public", "/public")
        self.config.add_view(stub_view_public, route_name="public")
        self.config.add_route("auth", "/auth")
        self.config.add_view(stub_view_auth, route_name="auth")
        self.config.add_route("groups", "/groups")
        self.config.add_view(stub_view_groups, route_name="groups")
        self.app = webtest.TestApp(self.config.make_wsgi_app())
        self.policy = self.config.registry.queryUtility(IAuthenticationPolicy)

    def _make_request(self, *args, **kwds):
        return make_request(self.config, *args, **kwds)

    def _make_signed_request(self, userid, *args, **kwds):
        req = self._make_request(*args, **kwds)
        creds = self._get_credentials(req, userid=userid)
        hawkauthlib.sign_request(req, **creds)
        return req

    def _get_credentials(self, req, **data):
        id_, key = self.policy.encode_hawk_id(req, **data)
        return {"id_": id_, "key": key}

    def test_the_class_implements_auth_policy_interface(self):
        verifyClass(IAuthenticationPolicy, HawkAuthenticationPolicy)

    def test_from_settings_can_explicitly_set_all_properties(self):
        policy = HawkAuthenticationPolicy.from_settings({
          "hawkauth.find_groups": TEST_PREFIX + ":stub_find_groups",
          "hawkauth.master_secret": "V8 JUICE IS 1/8TH GASOLINE",
          "hawkauth.nonce_cache": "hawkauthlib:NonceCache",
          "hawkauth.decode_hawk_id": TEST_PREFIX + ":stub_decode_id",
          "hawkauth.encode_hawk_id": TEST_PREFIX + ":stub_encode_id",
        })
        self.assertEquals(policy.find_groups, stub_find_groups)
        self.assertEquals(policy.master_secret, "V8 JUICE IS 1/8TH GASOLINE")
        self.assertTrue(isinstance(policy.nonce_cache, hawkauthlib.NonceCache))
        self.assertEquals(policy.decode_hawk_id, stub_decode_id)
        self.assertEquals(policy.encode_hawk_id, stub_encode_id)

    def test_from_settings_passes_on_args_to_nonce_cache(self):
        policy = HawkAuthenticationPolicy.from_settings({
          "hawkauth.nonce_cache": "hawkauthlib:NonceCache",
          "hawkauth.nonce_cache_window": 42,
        })
        self.assertTrue(isinstance(policy.nonce_cache, hawkauthlib.NonceCache))
        self.assertEquals(policy.nonce_cache.window, 42)
        self.assertRaises(TypeError, HawkAuthenticationPolicy.from_settings, {
          "hawkauth.nonce_cache": "hawkauthlib:NonceCache",
          "hawkauth.nonce_cache_invalid_arg": "WHAWHAWHAWHA",
        })

    def test_from_settings_errors_out_on_unexpected_keyword_args(self):
        self.assertRaises(ValueError, HawkAuthenticationPolicy.from_settings, {
          "hawkauth.unexpected": "spanish-inquisition",
        })

    def test_from_settings_errors_out_on_args_to_a_non_callable(self):
        self.assertRaises(ValueError, HawkAuthenticationPolicy.from_settings, {
          "hawkauth.nonce_cache": TEST_PREFIX + ":stub_non_callable",
          "hawkauth.nonce_cache_arg": "invalidarg",
        })

    def test_from_settings_errors_out_if_decode_hawk_id_is_not_callable(self):
        self.assertRaises(ValueError, HawkAuthenticationPolicy.from_settings, {
          "hawkauth.decode_hawk_id": TEST_PREFIX + ":stub_non_callable"
        })

    def test_from_settings_errors_out_if_encode_hawk_id_is_not_callable(self):
        self.assertRaises(ValueError, HawkAuthenticationPolicy.from_settings, {
          "hawkauth.encode_hawk_id": TEST_PREFIX + ":stub_non_callable"
        })

    def test_from_settings_produces_sensible_defaults(self):
        policy = HawkAuthenticationPolicy.from_settings({})
        # Using __code__ here is a Py2/Py3 compatible way of checking
        # that a bound and unbound method point to the same function object.
        self.assertEquals(policy.find_groups.__code__,
                          HawkAuthenticationPolicy.find_groups.__code__)
        self.assertEquals(policy.decode_hawk_id.__code__,
                          HawkAuthenticationPolicy.decode_hawk_id.__code__)
        self.assertTrue(isinstance(policy.nonce_cache, hawkauthlib.NonceCache))

    def test_from_settings_curries_args_to_decode_hawk_id(self):
        policy = HawkAuthenticationPolicy.from_settings({
          "hawkauth.decode_hawk_id": TEST_PREFIX + ":stub_decode_id",
          "hawkauth.decode_hawk_id_suffix": "-TEST",
        })
        self.assertEquals(policy.decode_hawk_id(None, "id"), ("id", "id-TEST"))

    def test_from_settings_curries_args_to_encode_hawk_id(self):
        policy = HawkAuthenticationPolicy.from_settings({
          "hawkauth.encode_hawk_id": TEST_PREFIX + ":stub_encode_id",
          "hawkauth.encode_hawk_id_suffix": "-TEST",
        })
        self.assertEquals(policy.encode_hawk_id(None, "id"), ("id", "id-TEST"))

    def test_remember_does_nothing(self):
        policy = HawkAuthenticationPolicy()
        req = self._make_signed_request("test@moz.com", "/")
        self.assertEquals(policy.remember(req, "test@moz.com"), [])

    def test_forget_gives_a_challenge_header(self):
        policy = HawkAuthenticationPolicy()
        req = self._make_signed_request("test@moz.com", "/")
        headers = policy.forget(req)
        self.assertEquals(len(headers), 1)
        self.assertEquals(headers[0][0], "WWW-Authenticate")
        self.assertTrue(headers[0][1] == "Hawk")

    def test_unauthenticated_requests_get_a_challenge(self):
        r = self.app.get("/auth", status=401)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith("Hawk"))

    def test_authenticated_request_works(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        r = self.app.request(req)
        self.assertEquals(r.body, b"test@moz.com")

    def test_authentication_fails_when_hawkid_has_no_userid(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, hello="world")
        hawkauthlib.sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_non_hawk_scheme_fails(self):
        req = self._make_request("/auth")
        req.authorization = "OpenID hello=world"
        self.app.request(req, status=401)
        req = self._make_request("/public")
        req.authorization = "OpenID hello=world"
        self.app.request(req, status=200)

    def test_authentication_without_hawkid_fails(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("id", "idd")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_timestamp_fails(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("ts", "typostamp")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_nonce_fails(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("nonce", "typonce")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_with_expired_timestamp_fails(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, username="test@moz.com")
        ts = str(int(time.time() - 1000))
        req.authorization = ("Hawk", {"ts": ts})
        hawkauthlib.sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_far_future_timestamp_fails(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, username="test@moz.com")
        ts = str(int(time.time() + 1000))
        req.authorization = ("Hawk", {"ts": ts})
        hawkauthlib.sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_reused_nonce_fails(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, username="test@moz.com")
        # First request with that nonce should succeed.
        req.authorization = ("Hawk", {"nonce": "PEPPER"})
        hawkauthlib.sign_request(req, **creds)
        r = self.app.request(req)
        self.assertEquals(r.body, b"test@moz.com")
        # Second request with that nonce should fail.
        req = self._make_request("/auth")
        req.authorization = ("Hawk", {"nonce": "PEPPER"})
        hawkauthlib.sign_request(req, **creds)
        self.app.request(req, status=401)

    def test_authentication_with_busted_hawkid_fails(self):
        req = self._make_signed_request("test@moz.com", "/auth")
        id = hawkauthlib.utils.parse_authz_header(req)["id"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(id, "XXX" + id)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_with_busted_signature_fails(self):
        req = self._make_request("/auth")
        creds = self._get_credentials(req, username="test@moz.com")
        hawkauthlib.sign_request(req, **creds)
        signature = hawkauthlib.utils.parse_authz_header(req)["mac"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_groupfinder_can_block_authentication(self):
        req = self._make_signed_request("baduser", "/auth")
        r = self.app.request(req, status=401)
        req = self._make_signed_request("baduser", "/public")
        r = self.app.request(req, status=200)
        self.assertEquals(r.body, b"baduser")

    def test_groupfinder_groups_are_correctly_reported(self):
        req = self._make_request("/groups")
        r = self.app.request(req)
        self.assertEquals(r.json,
                          [str(Everyone)])
        req = self._make_signed_request("gooduser", "/groups")
        r = self.app.request(req)
        self.assertEquals(r.json,
                          ["gooduser", str(Everyone), str(Authenticated)])
        req = self._make_signed_request("test", "/groups")
        r = self.app.request(req)
        self.assertEquals(r.json,
                          ["test", str(Everyone), str(Authenticated), "group"])
        req = self._make_signed_request("baduser", "/groups")
        r = self.app.request(req)
        self.assertEquals(r.json,
                          [str(Everyone)])

    def test_access_to_public_urls(self):
        # Request with no credentials is allowed access.
        req = self._make_request("/public")
        resp = self.app.request(req)
        self.assertEquals(resp.body, b"None")
        # Request with valid credentials is allowed access.
        req = self._make_signed_request("test@moz.com", "/public")
        resp = self.app.request(req)
        self.assertEquals(resp.body, b"test@moz.com")
        # Request with invalid credentials still reports a userid.
        req = self._make_signed_request("test@moz.com", "/public")
        signature = hawkauthlib.utils.parse_authz_header(req)["mac"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        resp = self.app.request(req)
        self.assertEquals(resp.body, b"test@moz.com")
        # Request with malformed credentials gets a 401
        req = self._make_signed_request("test@moz.com", "/public")
        tokenid = hawkauthlib.utils.parse_authz_header(req)["id"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(tokenid, "XXX" + tokenid)
        req.environ["HTTP_AUTHORIZATION"] = authz
        resp = self.app.request(req, status=401)

    def test_check_signature_fails_if_no_params_present(self):
        req = self._make_request("/auth")
        self.assertRaises(
            HTTPUnauthorized
            , self.policy._check_signature  # pylint: disable=W0212
            , req, "XXX"
            , )

    def test_default_groupfinder_returns_empty_list(self):
        policy = HawkAuthenticationPolicy()
        req = self._make_request("/auth")
        self.assertEquals(policy.find_groups("test", req), [])

    def test_auth_can_be_checked_several_times_on_same_request(self):
        req = self._make_signed_request("test@moz.com", "/public")
        self.assertEquals(authenticated_userid(req), "test@moz.com")
        self.assertEquals(authenticated_userid(req), "test@moz.com")
