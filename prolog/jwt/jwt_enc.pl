:- module(
  jwt_enc,
  [
    jwt_enc/4 % +Header, +Payload, ?Key, -Token
  ]
).

/** <module> JSON Web Tokens (JWT): Encoding

@author Wouter Beek
@version 2015/06
*/

:- use_module(library(apply)).
:- use_module(library(base64)).
:- use_module(library(sha)).

:- use_module(library(jwt/jwt_util)).





%! jwt_enc(+Header:dict, +Payload:dict, ?Key, -Token:atom) is det.

jwt_enc(Header0, Payload0, Key, Token):-
  header_claims(Header0, Header),
  payload_claims(Payload0, Payload),
  maplist(atom_json_dict, [HeaderDec,PayloadDec], [Header,Payload]),
  maplist(base64url, [HeaderDec,PayloadDec], [HeaderEnc,PayloadEnc]),
  atomic_list_concat([HeaderEnc,PayloadEnc], ., SignWith),
  create_signature(Header, SignWith, Key, SignatureEnc),
  atomic_list_concat([SignWith,SignatureEnc], ., Token).



%! create_signature(+Header:dict, +SignWith:atom, ?Key:dict, -Signature:atom) is det.

create_signature(Header, _, _, ''):-
  Header.alg == "none", !.
create_signature(Header, SignWith, Key, SignatureEnc):- !,
  hmac_algorithm_name(Header.alg, Alg), !,
  interpret_key(Header, Key, Secret),
  hmac_sha(Secret, SignWith, Hash, [algorithm(Alg)]),
  atom_codes(SignatureDec, Hash),
  base64url(SignatureDec, SignatureEnc).



%! header_claims(+Old:dict, -New:dict) is det.

header_claims(Old, New):-
  dict_add_default(Old, typ, "JWT", New).



%! payload_claims(+Old:dict, -New:dict) is det.

payload_claims(Old, New):-
  dict_add_default(Old, iss, "SWI-Prolog", Tmp),
  get_time(Now0),
  Now is floor(Now0),
  dict_add_default(Tmp, iat, Now, New).
