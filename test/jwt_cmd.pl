:- module(
  jwt_cmd,
  [
    jwt_cmd_dec/3, % +Token:atom
                   % +Key:dict
                   % -Payload:dict
    jwt_cmd_enc/4 % +Header:dict
                  % +Payload:dict
                  % +Key:dict
                  % -Token:atom
  ]
).

/** <module> JSON Web Tokens (JWT): Command-line tool

Operates a command line tool (PyJWT) for encoding/decoding JWTs
from within Prolog.

@author Wouter Beek
@see [PyJWT](https://github.com/jpadilla/pyjwt)
@version 2015/06
*/

:- use_module(library(apply)).
:- use_module(library(base64)).
:- use_module(library(http/json)).
:- use_module(library(pairs)).
:- use_module(library(process)).
:- use_module(library(readutil)).

:- use_module(jwt_util).



jwt_cmd_dec(Token, Key, Payload):-
  key_param(Key, KeyParam),
  setup_call_cleanup(
    process_create(path(jwt), [KeyParam,Token], [stdout(pipe(Out))]),
    (
      read_stream_to_atom(Out, A),
      atom_json_dict(A, Payload)
    ),
    close(Out)
  ).


jwt_cmd_enc(Header, Payload, Key, Token):-
  alg_param(Header, AlgParam),
  key_param(Key, KeyParam),
  dict_pairs(Payload, _, Pairs1),
  pairs_keys_values(Pairs1, Keys, Values),
  maplist(payload_param, Keys, Values, PayloadParams),
  setup_call_cleanup(
    process_create(
      path(jwt),
      [AlgParam,KeyParam|PayloadParams],
      [stdout(pipe(Out))]
    ),
    (
      read_stream_to_atom(Out, Token1),
      atom_concat('b\'', Token2, Token1),
      atom_concat(Token, '\'\n', Token2)
    ),
    close(Out)
  ).



% HELPERS %

alg_param(H, AlgParam):-
  long_param(alg, H.get(alg), AlgParam).


long_param(N, V, Param):-
  format(atom(Param), '--~w=~w', [N,V]).


payload_param(N, V0, A):-
  (   is_dict(V0)
  ->  atom_json_dict(V, V0, [])
  ;   V = V0
  ),
  format(atom(A), '~a=~a', [N,V]).


key_param(Key, KeyParam):-
  interpret_key(Key, Secret),
  long_param(key, Secret, KeyParam).


read_stream_to_atom(Stream, A):-
  read_stream_to_codes(Stream, Cs),
  atom_codes(A, Cs).
