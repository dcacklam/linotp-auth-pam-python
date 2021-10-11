#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    linotp-auth-pam-python - LinOTP PAM module for pam_python
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#     E-mail: linotp@keyidentity.com
#     Contact: www.linotp.org
#     Support: www.keyidentity.com
#

'''
# LinOTP authentication pam module - for usage under libpam-python

Installation:
=============
Install this file in the directory:
    /lib/security/

and setup a file:
    /etc/pam.d/common-linotp

with this component:

---8<------8<------8<------8<------8<------8<------8<------8<------8<------8<--
## here are the per-package modules (the "Primary" block)
auth    [success=1 default=ignore]  pam_python.so /lib/security/pam_linotp.py \
                              debug url=https://localhost/validate/simplecheck

--->8------>8------>8------>8------>8------>8------>8------>8------>8------>8--
- compare to common auth and use it in the pam services.

Test:
=====

For test purpose, you can extend the /etc/pam.d/loggin by replacing the
common-auth:

# Standard Un*x authentication.
#@include common-auth
@include common-linotp

and start a "login user" from a root shell

Module Parameters:
==================

Paramters to the module are:

 :param debug: display security relevant information in the syslog - critical -
 :param utrl=: the LinOTP verification url
 :param realm: the users LinOTP realm, which is requrired, if the user is not
               in the default realm
 :param prompt: the first password propmt (_ will be replaced with whitespaces)


Happy Authenticating!

__all__ = [
    'PAMError',
    'authenticate',
    'open_session',
    'close_session',
    'check_account',
    'change_password',
]

import syslog
import urllib
import urllib2
import pwd
import ssl

from ctypes import CDLL, POINTER, Structure, CFUNCTYPE, cast, pointer, sizeof, byref
from ctypes import c_void_p, c_uint, c_char_p, c_char, c_int
from ctypes.util import find_library
import getpass
import sys

LIBPAM = CDLL(find_library("pam"))

PAM_CHAUTHTOK = LIBPAM.pam_chauthtok
PAM_CHAUTHTOK.restype = c_int
PAM_CHAUTHTOK.argtypes = [c_void_p, c_int]

PAM_SETCRED = LIBPAM.pam_setcred
PAM_SETCRED.restype = c_int
PAM_SETCRED.argtypes = [c_void_p, c_int]

PAM_ACCT_MGMT = LIBPAM.pam_acct_mgmt
PAM_ACCT_MGMT.restype = c_int
PAM_ACCT_MGMT.argtypes = [c_void_p, c_int]

PAM_OPEN_SESSION = LIBPAM.pam_open_session
PAM_OPEN_SESSION.restype = c_int
PAM_OPEN_SESSION.argtypes = [c_void_p, c_int]

PAM_CLOSE_SESSION = LIBPAM.pam_close_session
PAM_CLOSE_SESSION.restype = c_int
PAM_CLOSE_SESSION.argtypes = [c_void_p, c_int]

## PAM CONSTANTS
PAM_SUCCESS=0
PAM_OPEN_ERR=1
PAM_SYMBOL_ERR=2
PAM_SERVICE_ERR=3
PAM_SYSTEM_ERR=4
PAM_BUF_ERR=5
PAM_PERM_DENIED=6
PAM_AUTH_ERR=7
PAM_CRED_INSUFFICIENT=8
PAM_AUTHINFO_UNAVAIL=9
PAM_USER_UNKNOWN=10
PAM_MAXTRIES=11
PAM_NEW_AUTHTOK_REQD=12
PAM_ACCT_EXPIRED=13
PAM_SESSION_ERR=14
PAM_CRED_UNAVAIL=15
PAM_CRED_EXPIRED=16
PAM_CRED_ERR=17
PAM_NO_MODULE_DATA=18
PAM_CONV_ERR=19
PAM_AUTHTOK_ERR=20
PAM_AUTHTOK_RECOVER_ERR=21
PAM_AUTHTOK_RECOVERY_ERR=21
PAM_AUTHTOK_LOCK_BUSY=22
PAM_AUTHTOK_DISABLE_AGING=23
PAM_TRY_AGAIN=24
PAM_IGNORE=25
PAM_ABORT=26
PAM_AUTHTOK_EXPIRED=27
PAM_MODULE_UNKNOWN=28
PAM_BAD_ITEM=29
PAM_CONV_AGAIN=30
PAM_INCOMPLETE=31
PAM_SERVICE=1
PAM_USER=2
PAM_TTY=3
PAM_RHOST=4
PAM_CONV=5
PAM_AUTHTOK=6
PAM_OLDAUTHTOK=7
PAM_RUSER=8
PAM_USER_PROMPT=9
PAM_FAIL_DELAY=10
PAM_XDISPLAY=11
PAM_XAUTHDATA=12
PAM_AUTHTOK_TYPE=13
PAM_SILENT=0x8000
PAM_DISALLOW_NULL_AUTHTOK=0x0001
PAM_ESTABLISH_CRED=0x0002
PAM_DELETE_CRED=0x0004
PAM_REINITIALIZE_CRED=0x0008
PAM_REFRESH_CRED=0x0010
PAM_CHANGE_EXPIRED_AUTHTOK=0x0020
PAM_DATA_SILENT=0x40000000
PAM_PROMPT_ECHO_OFF=1
PAM_PROMPT_ECHO_ON=2
PAM_ERROR_MSG=3
PAM_TEXT_INFO=4
PAM_RADIO_TYPE=5
PAM_BINARY_PROMPT=7
PAM_MAX_NUM_MSG=32
PAM_MAX_MSG_SIZE=512
PAM_MAX_RESP_SIZE=512


LINOTP_FAIL = ":-/"
LINOTP_OK = ":-)"
LINOTP_REJECT = ":-("

def get_config( argv ):
    '''
    parse the module arguments and put them in a config dict

    :param argv: array of arguments from the config file
    :return: config dict
    '''

    config = {}
    config["url"] = "https://localhost/validate/simplecheck"
    config["prompt"] = "Your OTP:"
    config["debug"] = False

    # split the config parameters
    if "debug" in argv:
        config["debug"] = True
    # Make nosslcertverify option work, allow people to use self-signed certs
    if "nosslcertverify" in argv:
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            # Legacy Python that doesn't verify HTTPS certificates by default
            pass
        else:
            # Handle target environment that doesn't support HTTPS verification
            ssl._create_default_https_context = _create_unverified_https_context
    # parse parameter
    for arg in argv:

        if arg.startswith( "url=" ):
            config["url"] = arg[len( "url=" ):]

        if arg.startswith( "realm=" ):
            config["realm"] = arg[len( "realm=" ):]

        if arg.startswith( "prompt=" ):
            prompt = arg[len( "prompt=" ):]
            config["prompt"] = prompt.replace( "_", " " )

    return config

def pam_sm_authenticate( pamh, flags, argv ):
    '''
    callback for the pam authentication

    :param pamh: pam context handle
    :param flags: ?? - unknown to me
    :param argv: configuration arguments
    '''

    syslog.openlog( "pam_linotp", syslog.LOG_PID, syslog.LOG_AUTH )
    result = pamh.PAM_AUTH_ERR

    try:
        config = get_config( argv )
        debug = config.get( 'debug', False )
        url = config.get( 'url', 'https://localhost/validate/simplecheck' )

        if debug:
            syslog.syslog( "start pam_linotp.py authentication: %s, %s" %
                                                             ( flags, argv ) )

        ## get the password of the user:
        ##     either from the pam handle or request this
        if pamh.authtok == None:
            if debug:
                syslog.syslog( "got no password in authtok - "
                                                "trying through conversation" )
            msg = pamh.Message( pamh.PAM_PROMPT_ECHO_OFF, config.get( 'prompt',
                                                        "[LinOTP] Password" ) )
            rsp = pamh.conversation( msg )
            pamh.authtok = rsp.resp

            if debug:
                syslog.syslog( "got password: " + pamh.authtok )

        #
        # check pamh.authtok against LinOTP  with pamh.user and pamh.authtok
        params = {}
        params["user"] = pamh.user
        params["pass"] = pamh.authtok

        if config.has_key( "realm" ):
            params["realm"] = config.get( "realm" )

        if debug:
            syslog.syslog( syslog.LOG_INFO, "calling url %s %r" %
                                                            ( url, params ) )

        data = urllib.urlencode( params )
        req = urllib2.Request( url, data )

        response = urllib2.urlopen( req )
        ret = response.read()

        if debug:
            syslog.syslog( ret )

        result = check_response( pamh, ret, pamh.user, config )

    except Exception as exept:
        syslog.syslog( "Error: %r" % exept )

    finally:
        syslog.closelog()

    return result


def check_response( pamh, ret, user, config ):
    """
    analyse the LinOTP result and return the corresponding return codes

    :param pamh: the pam request handle
    :param ret: the response of a former LinOTP request
    :param user: the requesting user
    :param config: the module configuration for accessin 'debug' or url

    :return: pamh.PAM_AUTH_ERR or pamh.PAM_SUCCESS
    """

    result = pamh.PAM_AUTH_ERR

    ## access failed - error report from LinOTP
    if ret == LINOTP_FAIL:
        syslog.syslog( syslog.LOG_INFO, "user failed to authenticate" )
        result = pamh.PAM_AUTH_ERR

    ## access accepted
    elif ret == LINOTP_OK:
        syslog.syslog( syslog.LOG_INFO, "user successfully authenticated" )
        result = pamh.PAM_SUCCESS

    ## access rejected
    elif ret == LINOTP_REJECT:
        syslog.syslog( syslog.LOG_INFO, "user rejected" )
        result = pamh.PAM_AUTH_ERR

    ## challenge mode
    elif len( ret ) > len( LINOTP_REJECT ) and ret.startswith( LINOTP_REJECT ):
        syslog.syslog( "in challenge mode" )
        parts = ret.split( ' ' )
        ## What you want users to be prompted for
        challenge_prompt = "OTP:"
        challenge = challenge_prompt
        state = ""

        if len( parts ) > 1:
            state = parts[1]

        if len( parts ) > 2:
            del parts[0]
            del parts[0]
            challenge = " ".join( parts )
            ## The original OTP prompt was overwritten by the message from the server. Add it back. 
            challenge=challenge+" - "+challenge_prompt
        msg = pamh.Message( pamh.PAM_PROMPT_ECHO_OFF, challenge )
        rsp = pamh.conversation( msg )
        pamh.authtok = rsp.resp

        syslog.syslog( "submitting response of challenge" )

        ## now redo the simplecheck
        params = {}
        params["user"] = user

        params['pass'] = rsp.resp
        params['state'] = state

        data = urllib.urlencode( params )
        req = urllib2.Request( config.get( 'url' ), data )

        response = urllib2.urlopen( req )
        ret = response.read()

        if config.get( 'debug' ):
            syslog.syslog( "challenge returned %s " % ret )

        result = check_response( pamh, ret, user, config )

    else:
        syslog.syslog( syslog.LOG_INFO, "user failed to authenticate" )
        result = pamh.PAM_AUTH_ERR


    return result


def pam_sm_setcred( pamh, flags, argv ):
    """  pam_sm_setcred  """
    c_void_p _handle_ = pamh.pamh
    return PAM_SETCRED( handle, flags )

def pam_sm_acct_mgmt( pamh, flags, argv ):
    """  pam_sm_acct_mgmt  """
    c_void_p _handle_ = pamh.pamh
    return PAM_ACCT_MGMT( handle, flags )

def pam_sm_chauthtok( pamh, flags, argv ):
    # pam_sm_chauthtok 
    # def change_password(username, password=None, service='login', encoding='utf-8'):  
    c_void_p _handle_ = pamh.pamh
    return PAM_CHAUTHTOK( handle, flags )

def pam_sm_open_session( pamh, flags, argv ):
    c_void_p _handle_ = pamh.pamh
    return PAM_OPEN_SESSION( handle, flags )

def pam_sm_close_session( pamh, flags, argv ):
    """ pam_sm_close_session """
    c_void_p _handle_ = pamh.pamh
    return PAM_CLOSE_SESSION( handle, flags )

##eof##########################################################################
