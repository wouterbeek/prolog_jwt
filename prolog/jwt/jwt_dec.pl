:- module(
  jwt_dec,
  [
    jwt_dec/3 % +Token:atom
              % +Key:dict
              % -Payload:dict
  ]
).

/** <module> JSON Web Tokens (JWT): Decoding

@author Wouter Beek
@version 2015/06
*/

:- use_module(library(apply)).
:- use_module(library(base64)).
:- use_module(library(http/json)).
:- use_module(library(sha)).

:- use_module(jwt_util).



%! jwt_dec(+Token:atom, +Key:dict, -Payload:dict) is det.

jwt_dec(Token, Key, Payload):-
  atomic_list_concat([HeaderEnc,PayloadEnc,_], '.', Token),
  base64url(HeaderDec, HeaderEnc),
  atom_json_dict(HeaderDec, Header),
  verify_signature(Header.alg, Token, Key),
  base64url(PayloadDec, PayloadEnc),
  atom_json_dict(PayloadDec, Payload).

%! verify_signature(+Algorithm:string, +Token:atom, +Key:dict) is semidet.

verify_signature("none", _, _):- !.
verify_signature("HS256", Token, Key):- !,
  atomic_list_concat([HeaderEnc,PayloadEnc,SignatureEnc], '.', Token),
  atomic_list_concat([HeaderEnc,PayloadEnc], '.', SignWith),
  interpret_key(Key, Secret),
  hmac_sha(Secret, SignWith, Hash, [algorithm(sha256)]),
  atom_codes(SignatureDec, Hash),
  base64url(SignatureDec, SignatureEnc).
