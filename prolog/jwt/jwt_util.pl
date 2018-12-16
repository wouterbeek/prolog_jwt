:- module(
  jwt_util,
  [
    atom_json_dict/2,      % ?Atom, ?Json
    dict_add_default/4,    % +Old, +Key, +Value, -New
    hmac_algorithm_name/2, % +JwsAlgorithmName, -PrologAlgorithmName
    interpret_key/3        % +Header, ?Key, -Secret
  ]
).

/** <module> JSON Web Tokens (JWT): Utilities

@author Wouter Beek
@tbd Support kty="EC" once Prolog supports Elliptic Curve.
@tbd Support kty="RSA" once Prolog supports RSA.
@tbd Support JOSE Header `jku` (JWK Set URL) for a URI that refers to
     a JWK Set.  The HTTP GET request that retrieves the JWK Set must use
     Transport Layer Security (TLS) and the identity of the server must be
     validated, as per Section 6 of RFC 6125.
@version 2015/06
*/

:- use_module(library(base64)).
:- use_module(library(http/json)).
:- use_module(library(lists)).





%! atom_json_dict(+Atom:atom, +Json:dict) is semidet.
%! atom_json_dict(+Atom:atom, -Json:dict) is det.
%! atom_json_dict(-Atom:atom, +Json:dict) is det.

atom_json_dict(Atom, Json):-
  atom_json_dict(Atom, Json, []).



%! dict_add_default(+Old:dict, +Key:atom, +Value:term, -New:dict) is det.
%
% Adds the given Key-Value pair, but only if Key is not yet set in the
% Old dictionary.

dict_add_default(Old, Key, _, Old) :-
  get_dict(Key, Old, _), !.
dict_add_default(Old, Key, Value, New) :-
  New = Old.put(Key, Value).



%! hmac_algorithm_name(+JwsAlgorithmName:atom, -PrologArgorithmName:atom) is semidet.
%
% Translates values for the algorithm JOSE Header to values
% accepted by hmac/3.

hmac_algorithm_name("HS256", sha256):- !.
hmac_algorithm_name("HS384", sha384):- !.
hmac_algorithm_name("HS512", sha512).



%! interpret_key(+Key:dict, -Secret:string) is semidet.

interpret_key(Key, Key.k):-
  Key.kty == "oct", !.



%! interpret_key(+Header:dict, ?KeySet, -Secret:string) is semidet.

% A public key is included in the JOSE Header.
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
