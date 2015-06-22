:- module(
  jwt_util,
  [
    atom_json_dict/2, % ?Atom;atom
                      % ?Json:dict
    hmac_algorithm/2, % +JwsAlg:atom
                      % -PlArg:atom
    interpret_key/3 % +Header:dict
                    % ?Key
                    % -Secret:string
  ]
).

/** <module> JSON Web Tokens (JWT): Utilities

@author Wouter Beek
@tbd Support kty="EC" once Prolog supports Elliptic Curve.
@tbd Support kty="RSA" once Prolog supports RSA.
@tbd Support JOSE Header `jku` (JWK Set URL) for a URI that refers to
     a JWK Set. The HTTP GET request that retrieves the JWK Set must use
     Transport Layer Security (TLS) and the identity of the server must be
     validated, as per Section 6 of RFC 6125.
@version 2015/06
*/

:- use_module(library(base64)).
:- use_module(library(http/json)).





%! atom_json_dict(+Atom:atom, +Json:dict) is semidet.
%! atom_json_dict(+Atom:atom, -Json:dict) is det.
%! atom_json_dict(-Atom:atom, +Json:dict) is det.

atom_json_dict(Atom, Json):-
  atom_json_dict(Atom, Json, []).



%! hmac_algorithm(+JwsAlg:atom, -PlArg:atom) is semidet.
% Translates values for the algorithm JOSE Header to values
% accepted by hmac/3.

hmac_algorithm("HS256", sha256):- !.
hmac_algorithm("HS384", sha384):- !.
hmac_algorithm("HS512", sha512):- !.



%! interpret_key(+Header:dict, ?KeySet, -Secret:string) is det.

% A public key is includes in the JOSE Header.
interpret_key(Header, _, Secret):-
  Key = Header.get(jwk), !,
  interpret_key(Key, Secret).
% The JOSE Header specifies a private key from a JWK Set of private keys.
interpret_key(Header, KeySet, Secret):-
  Kid = Header.get(kid), !,
  member(Key, KeySet.keys),
  Key.kid == Kid,
  interpret_key(Key, Secret).
% The JOSE Header contains no information about keys. Use a JWK private key.
interpret_key(_, Key, Secret):-
  interpret_key(Key, Secret).

%! interpret_key(+Key:dict, -Secret:string) is det.

interpret_key(Key, Key.k):-
  Key.kty == "oct", !.
