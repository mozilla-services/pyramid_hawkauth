# -*- coding: utf-8; mode: python -*-
# pylint: disable=W0613

__all__ = ["stub_find_groups"
           , "stub_view_public"
           , "stub_view_auth"
           , "stub_view_groups"
           , "stub_decode_id"
           , "stub_encode_id"
           , "make_request"
           , ]

import json

from pyramid.request import Request
from pyramid.response import Response
from pyramid.httpexceptions import HTTPForbidden
from pyramid.security import (
    unauthenticated_userid
    , authenticated_userid
    , effective_principals
    , )

def make_request(config, path="/", environ=None):
    """Helper function for making pyramid Request objects."""
    if environ is None:
        environ = {}
    my_environ = {}
    my_environ["wsgi.version"] = (1, 0)
    my_environ["wsgi.multithread"] = True
    my_environ["wsgi.multiprocess"] = True
    my_environ["wsgi.run_once"] = False
    my_environ["wsgi.url_scheme"] = "http"
    my_environ["REQUEST_METHOD"] = "GET"
    my_environ["SCRIPT_NAME"] = ""
    my_environ["PATH_INFO"] = path
    my_environ["SERVER_NAME"] = "localhost"
    my_environ["SERVER_PORT"] = "5000"
    my_environ["QUERY_STRING"] = "5000"
    my_environ.update(environ)
    request = Request(my_environ)
    request.registry = config.registry
    return request


# Something non-callable, to test loading non-callables by name.
stub_non_callable = None

def stub_find_groups(userid, request):
    """Groupfinder with the following rules:

        * any user with "bad" in their name is invalid
        * the "test" user belongs to group "group"
        * all other users have no groups

    """
    if "bad" in userid:
        return None
    if userid == "test":
        return ["group"]
    return []


def stub_view_public(request):
    """Stub view that returns userid if logged in, None otherwise."""
    userid = unauthenticated_userid(request)
    return Response(str(userid))


def stub_view_auth(request):
    """Stub view that returns userid if logged in, fails if not."""
    userid = authenticated_userid(request)
    if userid is None:
        raise HTTPForbidden
    return Response(userid)


def stub_view_groups(request):
    """Stub view that returns groups if logged in, fails if not."""
    groups = effective_principals(request)
    return Response(json.dumps([str(g) for g in groups]))


def stub_decode_id(request, _id, suffix="-SECRET"):
    """Stub id-decoding function that appends suffix to give the secret."""
    return _id, _id + suffix


def stub_encode_id(request, _id, suffix="-SECRET"):
    """Stub id-encoding function that appends suffix to give the secret."""
    return _id, _id + suffix
