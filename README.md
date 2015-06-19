**plJwt**
=========

A library that brings JSON Web Token (JWT) support
to [SWI-Prolog](http://www.swi-prolog.org).

Version 0.1.0

Licensed under the Lesser General Public License Vers. 3, June 2007,
see license.txt

[SWI-Prolog](http://www.swi-prolog.org) ships with an excellent Web framework.
This library builds on that work.

Install
=======

Other than having a normal SWI-Prolog install, the only installation step is to clone this repository from [Github](https://github.com/wouterbeek/plJwt) or install through [SWI-Prolog's built-in packaging system](http://www.swi-prolog.org/pack/list):

```prolog
?- pack_install(plJwt).
```



Run tests
=========

The test are run in the following way:

```bash
$ swipl test/jwt_test.pl
?- weblog_demo.
```

