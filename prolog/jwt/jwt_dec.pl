:- encoding(utf8).
:- module(
  jwt_dec,
  [
    jwt_dec/3 % +Token, ?Key, -Payload
  ]
).

/** <module> JSON Web Tokens (JWT): Decoding

@author Wouter Beek
@tbd Support alg=RS256 once Prolog supports RSASSA-PKCS1-v1_5 using SHA-256.
@tbd Support alg=RS384 once Prolog supports RSASSA-PKCS1-v1_5 using SHA-384.
@tbd Support alg=RS512 once Prolog supports RSASSA-PKCS1-v1_5 using SHA-512.
@tbd Support alg=ES256 once Prolog supports ECDSA using P-256 and SHA-256.
@tbd Support alg=ES384 once Prolog supports ECDSA using P-384 and SHA-384.
@tbd Support alg=ES512 once Prolog supports ECDSA using P-512 and SHA-512.
@tbd Support alg=PS256 once Prolog supports RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
@tbd Support alg=PS384 once Prolog supports RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
@tbd Support alg=PS512 once Prolog supports RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
@version 2015/06
*/

:- use_module(library(apply)).
:- use_module(library(base64)).
:- use_module(library(http/json)).
:- use_module(library(sha)).

:- use_module(library(jwt/jwt_util)).





%! jwt_dec(+Token:atom, ?Key:dict, -Payload:dict) is semidet.

jwt_dec(Token, Key, Payload):-
  atomic_list_concat([HeaderEnc,PayloadEnc,_], '.', Token),
  base64url(HeaderDec, HeaderEnc),
  atom_json_dict(HeaderDec, Header),
  verify_signature(Header, Key, Token),
  base64url(PayloadDec, PayloadEnc),
  atom_json_dict(PayloadDec, Payload),
  verify_payload(Payload).



%! verify_audience(+Payload:dict) is semidet.

verify_audience(Payload):-
  get_dict(aud, Payload, Audience),
  (   is_list(Audience)
  ->  \+ memberchk("SWI-Prolog", Audience)
  ;   Audience \== "SWI-Prolog"
  ), !,
  print_message(warning, format("SWI-Prolog does not belong to the audience (aud).")),
  fail.
verify_audience(_).



%! verify_expiration_time(+Payload:dict) is semidet.

verify_expiration_time(Payload):-
  get_time(Now),
  Payload.exp =< Now, !,
  print_message(warning, format("Expiration time (exp) has exceeded.")),
  fail.
verify_expiration_time(_).



%! verify_not_before(+Payload:dict) is semidet.

verify_not_before(Payload):-
  get_dict(nbf, Payload, NotBefore),
  get_time(Now),
  Now < NotBefore, !,
  print_message(warning, format("The ‘Not Before’ claim (nbf) was not met.")),
  fail.
verify_not_before(_).



%! verify_payload(+Payload:dict) is semidet.

verify_payload(Payload):-
  verify_audience(Payload),
  verify_expiration_time(Payload),
  verify_not_before(Payload).



%! verify_signature(+Header:dict, +Key, +Token:atom) is semidet.
%! verify_signature(+Header:dict, -Key, +Token:atom) is semidet.

verify_signature(Header, _, _):-
  Header.alg == "none", !.
verify_signature(Header, Key, Token):-
  hmac_algorithm_name(Header.alg, Alg), !,
  atomic_list_concat([HeaderEnc,PayloadEnc,SignatureEnc], ., Token),
  atomic_list_concat([HeaderEnc,PayloadEnc], ., SignWith),
  interpret_key(Header, Key, Secret),
  hmac_sha(Secret, SignWith, Hash, [algorithm(Alg)]),
  atom_codes(SignatureDec, Hash),
  base64url(SignatureDec, SignatureEnc).
