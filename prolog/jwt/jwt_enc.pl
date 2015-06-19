:- module(
  jwt_enc,
  [
    jwt_enc/4 % +Header:dict
              % +Payload:dict
              % +Key:dict
              % -Token:atom
  ]
).

/** <module> JSON Web Tokens (JWT): Encoding

@author Wouter Beek
@version 2015/06
*/

:- use_module(library(apply)).
:- use_module(library(base64)).
:- use_module(library(sha)).

:- use_module(jwt_util).



%! jwt_enc(+Header:dict, +Payload:dict, +Key:dict, -Token:atom) is det.

jwt_enc(Header, Payload, Key, Token):-
  maplist(atom_json_dict, [HeaderDec,PayloadDec], [Header,Payload]),
  maplist(base64url, [HeaderDec,PayloadDec], [HeaderEnc,PayloadEnc]),
  atomic_list_concat([HeaderEnc,PayloadEnc], '.', SignWith),
  create_signature(Header.alg, SignWith, Key, SignatureEnc),
  atomic_list_concat([SignWith,SignatureEnc], '.', Token).

%! create_signature(
%!   +Algorithm:string,
%!   +SignWith:atom,
%!   +Key:dict,
%!   -Signature:atom
%! ) is det.

create_signature("none", _, _, ''):- !.
create_signature("HS256", SignWith, Key, SignatureEnc):- !,
  interpret_key(Key, Secret),
  hmac_sha(Secret, SignWith, Hash, [algorithm(sha256)]),
  atom_codes(SignatureDec, Hash),
  base64url(SignatureDec, SignatureEnc).
