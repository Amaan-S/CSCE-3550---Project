# ----------------------------
# Name: Amaan Jamil Siddiqui
# euid: ajs0576
# ----------------------------

import base64, json, sys, threading, datetime as dt, jwt

from Project1 import generate_rsa_key,KeyStore,jwk_from_public,mint_jwt,JWKSHandler

'''Test file below implements a test suite for the functions
used in the JWKS server (Project1.py). '''

#UNIT TEST FOR TESTING WHETHER ONLY VALID KEYS ARE STORED IN THE KeyStore class
def TEST_KEYS_Unexpired():            #if the keys are all unexp in JWKS then I can say that the JWKS isn't storing valid keys as its supposed to
    All_Keys = KeyStore()
    JWKS = All_Keys.jwks()          #get the jwks currently stored in the Key Storate
    
    assert "keys" in JWKS and isinstance(JWKS["keys"],list)
    assert len(JWKS["keys"]) == 1
    assert JWKS["keys"][0]["kid"] == All_Keys.current().kid