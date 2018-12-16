:- module(test_jwt, []).

/** <module> Tests for JSON Web Token (JWT)

@author Wouter Beek
@version 2015/06
*/

:- use_module(library(plunit)).

:- use_module(library(jwt/jwt_dec)).
:- use_module(library(jwt/jwt_enc)).




:- begin_tests(jwt, []).

test(encode_decode, [forall(jwt_test(Header,Payload,Key))]) :-
  jwt_enc(Header, Payload, Key, Token),
  jwt_dec(Token, Key, Payload0),
  Payload :< Payload0.



%! jwt_test(-Header:dict, -Payload:dict, -Key:dict) is semidet.
%! jwt_test(-Header:dict, -Payload:dict, -Key:dict) is multi.

jwt_test(
  json{alg: "none"},
  json{exp: 13000819380, 'https://example.com/is_root': true, iss: "joe"},
  _NoKey
).
jwt_test(
  json{alg: "HS256", typ: "JWT"},
  json{exp: 2300819380, 'https://example.com/is_root': true, iss: "joe"},
  json{k: "kq4HLmbjAsaN", kty: "oct"}
).

:- end_tests(jwt).
