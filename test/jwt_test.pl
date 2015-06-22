:- module(
  jwt_test,
  [
    jwt_test/1, % +Name:atom
    jwt_test/4 % ?Name:atom
               % ?Header:dict
               % ?Payload:dict
               % ?Key:dict
  ]
).

/** <module> JSON Web Token (JWT): Tests

@author Wouter Beek
@version 2015/06
*/

:- use_module(library(jwt/jwt_dec)).
:- use_module(library(jwt/jwt_enc)).





%! jwt_test(Name) is semidet.

jwt_test(Name):-
  jwt_test(Name, Header, Payload, Key),
  format(
    user_output,
    'Let\'s encode:\n  HEADER: ~w\n  PAYLOAD: ~w\n  KEY: ~w\n',
    [Header,Payload,Key]
  ),
  jwt_enc(Header, Payload, Key, Token),
  format(user_output, 'Encoded as TOKEN:\t~w\n', [Token]),
  jwt_dec(Token, Key, Payload0),
  Payload :< Payload0,
  format(
    user_output,
    'Successfully, decoded back to the original header, payload, and key.\n',
    []
  ).



%! jwt_test(+Name:atom, -Header:dict, -Payload:dict, -Key:dict) is semidet.
%! jwt_test(-Name:atom, -Header:dict, -Payload:dict, -Key:dict) is multi.

jwt_test(
  test0,
  json{
    alg: "none"
  },
  json{
    exp: 13000819380,
    'http://example.com/is_root': true,
    iss: "joe"
  },
  _
).
jwt_test(
  test1,
  json{
    alg: "HS256",
    typ:"JWT"
  },
  json{
    exp: 2300819380,
    'http://example.com/is_root': true,
    iss: "joe"
  },
  json{
    k: "kq4HLmbjAsaN",
    kty: "oct"
  }
).
