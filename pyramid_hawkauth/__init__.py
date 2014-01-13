# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

A Pyramid authentication plugin for Hawk Access Authentication:

    https://npmjs.org/package/hawk

"""

__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


import functools

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.util import DottedNameResolver

import tokenlib

import hawkauthlib
import hawkauthlib.utils


@implementer(IAuthenticationPolicy)
class HawkAuthenticationPolicy(object):
    """Pyramid Authentication Policy implementing Hawk Access Auth.

    This class provides an IAuthenticationPolicy implementation based on
    signed requests, using the Hawk Access Authentication standard with
    pre-shared credentials.

    The plugin can be customized with the following arguments:

        * find_groups:  a callable taking a userid and a Request object, and
                        returning a list of the groups that userid is a
                        member of.

        * master_secret:  a secret known only by the server, used for signing
                          Hawk auth tokens in the default implementation.

        * decode_hawk_id:  a callable taking a Request object and Hawk token
                           id, and returning the userid and Hawk secret key.

        * encode_hawk_id:  a callable taking a Request object and userid, and
                           returning the Hawk token id and secret key.

        * nonce_cache:  an object implementing the same interface as
                        hawkauthlib.NonceCache.

    """

    # The default value of master_secret is None, which will cause tokenlib
    # to generate a fresh secret at application startup.
    master_secret = None

    def __init__(self, find_groups=None, master_secret=None, nonce_cache=None,
                 decode_hawk_id=None, encode_hawk_id=None):
        if find_groups is not None:
            self.find_groups = find_groups
        if master_secret is not None:
            self.master_secret = master_secret
        if nonce_cache is not None:
            self.nonce_cache = nonce_cache
        else:
            self.nonce_cache = hawkauthlib.NonceCache()
        if decode_hawk_id is not None:
            self.decode_hawk_id = decode_hawk_id
        if encode_hawk_id is not None:
            self.encode_hawk_id = encode_hawk_id

    @classmethod
    def from_settings(cls, settings={}, prefix="hawkauth.", **extra):
        """Construct a HawkAuthenticationPolicy from deployment settings.

        This is a helper function for loading a HawkAuthenticationPolicy from
        settings provided in the pyramid application registry.  It extracts
        settings with the given prefix, converts them to the appropriate type
        and passes them into the constructor.
        """
        # Grab out all the settings keys that start with our prefix.
        hawkauth_settings = {}
        for name in settings:
            if not name.startswith(prefix):
                continue
            hawkauth_settings[name[len(prefix):]] = settings[name]
        # Update with any additional keyword arguments.
        hawkauth_settings.update(extra)
        # Pull out the expected keyword arguments.
        kwds = cls._parse_settings(hawkauth_settings)
        # Error out if there are unknown settings.
        for unknown_setting in hawkauth_settings:
            raise ValueError("unknown hawkauth setting: %s" % unknown_setting)
        # And finally we can finally create the object.
        return cls(**kwds)

    @classmethod
    def _parse_settings(cls, settings):
        """Parse settings for an instance of this class.

        This classmethod takes a dict of string settings and parses them into
        a dict of properly-typed keyword arguments, suitable for passing to
        the default constructor of this class.

        Implementations should remove each setting from the dict as it is
        processesed, so that any unsupported settings can be detected by the
        calling code.
        """
        load_function = _load_function_from_settings
        load_object = _load_object_from_settings
        kwds = {}
        kwds["find_groups"] = load_function("find_groups", settings)
        kwds["master_secret"] = settings.pop("master_secret", None)
        kwds["nonce_cache"] = load_object("nonce_cache", settings)
        kwds["decode_hawk_id"] = load_function("decode_hawk_id", settings)
        kwds["encode_hawk_id"] = load_function("encode_hawk_id", settings)
        return kwds

    def authenticated_userid(self, request):
        """Get the authenticated userid for the given request.

        This method extracts the claimed userid from the request, checks
        the request signature, and calls the groupfinder callback to check
        the validity of the claimed identity.
        """
        userid, key = self._get_credentials(request)
        if userid is None:
            return None
        self._check_signature(request, key)
        if self.find_groups(userid, request) is None:
            return None
        return userid

    def unauthenticated_userid(self, request):
        """Get the unauthenticated userid for the given request.

        This method extracts the claimed userid from the request without
        checking its authenticity.  This means that the request signature
        is *not* checked when you call this method.  The groupfinder
        callback is also not called.
        """
        userid, _ = self._get_credentials(request)
        return userid

    def effective_principals(self, request):
        """Get the list of effective principals for the given request.

        This method combines the authenticated userid from the request with
        with the list of groups returned by the groupfinder callback, if any.
        """
        principals = [Everyone]
        userid, key = self._get_credentials(request)
        if userid is None:
            return principals
        self._check_signature(request, key)
        groups = self.find_groups(userid, request)
        if groups is None:
            return principals
        principals.insert(0, userid)
        principals.append(Authenticated)
        principals.extend(groups)
        return principals

    def remember(self, request, principal, **kw):
        """Get headers to remember to given principal identity.

        This is a no-op for this plugin; the client is supposed to remember
        its Hawk credentials and use them for all requests.
        """
        return []

    def forget(self, request):
        """Get headers to forget the identity in the given request.

        This simply issues a new WWW-Authenticate challenge, which should
        cause the client to forget any previously-provisioned credentials.
        """
        return [("WWW-Authenticate", "Hawk")]

    def challenge(self, request, content="Unauthorized"):
        """Challenge the user for credentials.

        This method returns a 401 response using the WWW-Authenticate field
        as constructed by forget().  You might like to use it as pyramid's
        "forbidden view" when using this auth policy.
        """
        return HTTPUnauthorized(content, headers=self.forget(request))

    def find_groups(self, userid, request):
        """Find the list of groups for the given userid.

        This method provides a default implementation of the "groupfinder
        callback" used by many pyramid authn policies to look up additional
        user data.  It can be overridden by passing a callable into the
        HawkAuthenticationPolicy constructor.

        The default implementation returns an empty list.
        """
        return []

    def decode_hawk_id(self, request, tokenid):
        """Decode a Hawk token id into its userid and Hawk secret key.

        This method decodes the given Hawk token id to give the corresponding
        userid and Hawk secret key.  It is a simple default implementation
        using the tokenlib library, and can be overridden by passing a callable
        info the HawkAuthenticationPolicy constructor.

        If the Hawk token id is invalid then ValueError will be raised.
        """
        secret = tokenlib.get_token_secret(tokenid, secret=self.master_secret)
        data = tokenlib.parse_token(tokenid, secret=self.master_secret)
        userid = None
        for key in ("username", "userid", "uid", "email"):
            userid = data.get(key)
            if userid is not None:
                break
        else:
            msg = "Hawk id contains no userid"
            raise self.challenge(request, msg)
        return userid, secret

    def encode_hawk_id(self, request, userid=None, **data):
        """Encode the given userid into a Hawk token id and secret key.

        This method is essentially the reverse of decode_hawk_id.  Given
        a userid, it returns a Hawk id and corresponding secret key.
        It is not needed for consuming authentication tokens, but is very
        useful when building them for testing purposes.
        """
        if userid is not None:
            data["userid"] = userid
        master_secret = self.master_secret
        tokenid = tokenlib.make_token(data, secret=master_secret)
        secret = tokenlib.get_derived_secret(tokenid, secret=master_secret)
        return tokenid, secret

    def _get_params(self, request):
        """Get the Hawk auth parameters from the given request.

        This method parses the Authorization header to get the Hawk auth
        parameters.  If they seem sensible, we cache them in the request
        to avoid reparsing and return them as a dict.

        If the request contains no Hawk auth credentials, None is returned.
        """
        try:
            return request.environ["hawkauth.params"]
        except KeyError:
            params = hawkauthlib.utils.parse_authz_header(request, None)
            if params is not None:
                if params.get("scheme").upper() != "HAWK":
                    params = None
            request.environ["hawkauth.params"] = params
            return params

    def _get_credentials(self, request):
        """Extract the Hawk userid and secret key from the request.

        This method extracts and returns the claimed userid from the Hawk auth
        data in the request, along with the corresonding request signing key.
        It does *not* check the signature on the request.

        If there are no Hawk auth credentials in the request then (None, None)
        is returned.  If the Hawk token id is invalid then HTTPUnauthorized
        will be raised.
        """
        params = self._get_params(request)
        if params is None:
            return None, None
        # Extract the claimed Hawk id token.
        tokenid = hawkauthlib.get_id(request, params=params)
        if tokenid is None:
            return None, None
        # Parse the Hawk id into its userid and secret key.
        try:
            userid, key = self.decode_hawk_id(request, tokenid)
        except ValueError:
            msg = "invalid Hawk id: %s" % (tokenid,)
            raise self.challenge(request, msg)
        return userid, key

    def _check_signature(self, request, key):
        """Check the Hawk auth signaure on the request.

        This method checks the Hawk signature on the request against the
        supplied signing key.  If missing or invalid then HTTPUnauthorized
        is raised.
        """
        # See if we've already checked the signature on this request.
        # This is important because pyramid doesn't cache the results
        # of authenticating the request, but we mark the nonce as stale
        # after the first check.
        if request.environ.get("hawkauth.signature_is_valid", False):
            return True
        # Grab the (hopefully cached) params from the request.
        params = self._get_params(request)
        if params is None:
            msg = "missing Hawk signature"
            raise self.challenge(request, msg)
        # Validate the signature with the given key.
        sig_valid = hawkauthlib.check_signature(request, key, params=params,
                                                nonces=self.nonce_cache)
        if not sig_valid:
            msg = "invalid Hawk signature"
            raise self.challenge(request, msg)
        # Mark this request as having a valid signature.
        request.environ["hawkauth.signature_is_valid"] = True
        return True


def _load_function_from_settings(name, settings):
    """Load a plugin argument as a function created from the given settings.

    This function is a helper to load and possibly curry a callable argument
    to the plugin.  It grabs the value from the dotted python name found in
    settings[name] and checks that it is a callable.  It then looks for args
    of the form settings[name_*] and curries them into the function as extra
    keyword argument before returning.
    """
    # See if we actually have the named object.
    dotted_name = settings.pop(name, None)
    if dotted_name is None:
        return None
    func = DottedNameResolver(None).resolve(dotted_name)
    # Check that it's a callable.
    if not callable(func):
        raise ValueError("Argument %r must be callable" % (name,))
    # Curry in any keyword arguments.
    func_kwds = {}
    prefix = name + "_"
    for key in list(settings.keys()):
        if key.startswith(prefix):
            func_kwds[key[len(prefix):]] = settings.pop(key)
    # Return the original function if not currying anything.
    # This is both more efficent and better for unit testing.
    if func_kwds:
        func = functools.partial(func, **func_kwds)
    return func


def _load_object_from_settings(name, settings):
    """Load a plugin argument as an object created from the given settings.

    This function is a helper to load and possibly instanciate an argument
    to the plugin.  It grabs the value from the dotted python name found in
    settings[name].  If this is a callable, it looks for arguments of the
    form settings[name_*] and calls it with them to instanciate an object.
    """
    # See if we actually have the named object.
    dotted_name = settings.pop(name, None)
    if dotted_name is None:
        return None
    obj = DottedNameResolver(None).resolve(dotted_name)
    # Extract any arguments for the callable.
    obj_kwds = {}
    prefix = name + "_"
    for key in list(settings.keys()):
        if key.startswith(prefix):
            obj_kwds[key[len(prefix):]] = settings.pop(key)
    # Call it if callable.
    if callable(obj):
        obj = obj(**obj_kwds)
    elif obj_kwds:
        raise ValueError("arguments provided for non-callable %r" % (name,))
    return obj


def includeme(config):
    """Install HawkAuthenticationPolicy into the provided configurator.

    This function provides an easy way to install Hawk Access Authentication
    into your pyramid application.  It loads a HawkAuthenticationPolicy from
    the deployment settings and installs it into the given configurator.
    """
    # Hook up a default AuthorizationPolicy.
    # ACLAuthorizationPolicy is usually what you want.
    # If the app configures one explicitly then this will get overridden.
    # In auto-commit mode this needs to be set before adding an authn policy.
    authz_policy = ACLAuthorizationPolicy()
    config.set_authorization_policy(authz_policy)

    # Build a HawkAuthenticationPolicy from the deployment settings.
    settings = config.get_settings()
    authn_policy = HawkAuthenticationPolicy.from_settings(settings)
    config.set_authentication_policy(authn_policy)

    # Set the forbidden view to use the challenge() method on the policy.
    config.add_forbidden_view(authn_policy.challenge)
