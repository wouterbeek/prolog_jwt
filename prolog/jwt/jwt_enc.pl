:- module(
  jwt_enc,
  [
    jwt_enc/4 % +Header:dict
              % +Payload:dict
              % ?Key
              % -Token:atom
  ]
).

/** <module> JSON Web Tokens (JWT): Encoding

@author Wouter Beek
@version 2015/06
*/

:- use_module(library(apply)).
:- use_module(library(base64)).
:- use_module(library(jwt/jwt_util)).
:- use_module(library(sha)).





%! jwt_enc(+Header:dict, +Payload:dict, ?Key, -Token:atom) is det.

jwt_enc(Header0, Payload0, Key, Token):-
  header_claims(Header0, Header),
  payload_claims(Payload0, Payload),
  maplist(atom_json_dict, [HeaderDec,PayloadDec], [Header,Payload]),
  maplist(base64url, [HeaderDec,PayloadDec], [HeaderEnc,PayloadEnc]),
  atomic_list_concat([HeaderEnc,PayloadEnc], '.', SignWith),
  create_signature(Header, SignWith, Key, SignatureEnc),
  atomic_list_concat([SignWith,SignatureEnc], '.', Token).

%! create_signature(
%!   +Header:dict,
%!   +SignWith:atom,
%!   ?Key,
%!   -Signature:atom
%! ) is det.

create_signature(Header, _, _, ''):-
  Header.alg == "none", !.
create_signature(Header, SignWith, Key, SignatureEnc):- !,
  hmac_algorithm(Header.alg, Alg), !,
  interpret_key(Header, Key, Secret),
  hmac_sha(Secret, SignWith, Hash, [algorithm(Alg)]),
  atom_codes(SignatureDec, Hash),
  base64url(SignatureDec, SignatureEnc).

header_claims(D0, D):-
  dict_pairs(D0, Tag, L0),
  (   memberchk(typ-_, L0)
  ->  L = L0
  ;   L = [typ-"JWT"|L0]
  ),
  dict_pairs(D, Tag, L).

payload_claims(D0, D):-
  dict_pairs(D0, Tag, L0),
  (   memberchk(iss-_, L0)
  ->  L1 = L0
  ;   L1 = [iss-"SWI-Prolog"|L0]
  ),
  (   memberchk(iat-_, L1)
  ->  L = L1
  ;   get_time(Now0),
      Now is floor(Now0),
      L = [iat-Now|L1]
  ),
  dict_pairs(D, Tag, L).
