:- module(
  jwt_util,
  [
    atom_json_dict/2, % ?Atom;atom
                      % ?Json:dict
    interpret_key/2 % +Key:dict
                    % -Secret:string
  ]
).

/** <module> JSON Web Tokens (JWT): Utilities

@author Wouter Beek
@version 2015/06
*/

:- use_module(library(base64)).
:- use_module(library(http/json)).





%! atom_json_dict(+Atom:atom, +Json:dict) is semidet.
%! atom_json_dict(+Atom:atom, -Json:dict) is det.
%! atom_json_dict(-Atom:atom, +Json:dict) is det.

atom_json_dict(Atom, Json):-
  atom_json_dict(Atom, Json, []).



%! interpret_key(+Key:dict, -Secret:string) is det.

interpret_key(Key, Secret):-
  interpret_key(Key.kty, Key, Secret).

%! interpret_key(+Type:string, +Key:dict, -Secret:string) is det.

interpret_key("oct", Key, Key.k).
