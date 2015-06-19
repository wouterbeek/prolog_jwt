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

:- use_module(jwt_cmd).
:- use_module(jwt_dec).
:- use_module(jwt_enc).



%! jwt_cmd_test(Name) is semidet.

jwt_cmd_test(Name):-
  jwt_test(Name, Header, Payload, Key),
  jwt_cmd_enc(Header, Payload, Key, Token),
  writeln(Token),
  jwt_cmd_dec(Token, Key, Payload).



%! jwt_test(Name) is semidet.

jwt_test(Name):-
  jwt_test(Name, Header, Payload, Key),
  jwt_enc(Header, Payload, Key, Token),
  writeln(Token),
  jwt_dec(Token, Key, Payload).



%! jwt_test(+Name:atom, -Header:dict, -Payload:dict, -Key:dict) is semidet.
%! jwt_test(-Name:atom, -Header:dict, -Payload:dict, -Key:dict) is multi.

jwt_test(
  test0,
  json{
    alg: "none"
  },
  json{
    exp: 1300819380,
    'http://example.com/is_root': true,
    iss: "joe"
  },
  json{}
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
    k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    kty: "oct"
  }
).
jwt_test(
  test2,
  json{
    alg: "HS256",
    typ: "JWT"
  },
  json{
    admin: true,
    sub: 1234567890,
    name: "John Doe"
  },
  secret
).
