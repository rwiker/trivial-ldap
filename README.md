Introduction
============

One-two, one-two... is this thing working?

This is Kevin Montuori's *trivial-ldap*, with a few modifications.

A few years back, I needed some mechanism for querying AD servers, as
part of a custom content connector for the FAST ESP search engine. I
found trivial-ldap, and was soon using it to good effect.

After having used trivial-ldap for a while, I made some modifications,
and asked Kevin to review them, and integrate them if he felt that
they added value. Unfortunately, Kevin is too busy to spend time
on trivial-ldap, so he graciously let me publish whatever changes I
had.

Changes
=======

LDAP Filter Parser
------------------

The LDAP filter parser has been rewritten from scratch, using
*cl-yacc*. This makes filter parsing somewhat faster, and should also
make it easier to maintain. The downside is one more dependency.

Attribute Naming
----------------

The original code used symbols in the current package to name LDAP
attributes. This has changed, and all attribute names are now interned
in the keyword package. So, something like

    (ldap:attr-value *entry* 'cname)

should now be

    (ldap:attr-value *entry* :cname)

and so on. Note: this is probably only important when working with an
LDAP entry, as that is the only place where we use symbol identity for
matching.

Binary Attributes
-----------------

There was a tacit assumption in the trivial-ldap code that all
attributes are UTF-8 encoded strings, while in reality they can be
7-bit ASCII (USASCII), UTF-8 or even binary. There is now a mechanism
in place for giving hints to trivial-ldap that certain attributes
should be treated as binary values --- such attributes will be
returned as lists of (unsigned-byte 8), instead of as unicode
strings.

The interface to this mechanism is

    (ldap:attribute-binary-p <attribute-name>) => <generalized-boolean>

and

    (setf (ldap:attribute-binary-p <attribute-name>) <generalized-boolean>)


List Equivalents
----------------

Search filters and values can be specified as lists instead of as
strings. This has two advantages:

* Binary values can be specified (lists of octet values will not be
  treated as UTF-8 sequences).

* It is not necessary to build string representations of a filter just
  to have the filter parser deconstruct it back to the representation
  that should be natural for Lisp.

* Values can be specified as octet lists, strings or symbols --
  when a symbols is specified, the actual value used is whatever

    (symbol-name <symbol>) evaluates to.

### Examples:

    (ldap:search *ldap* '(and (= objectclass person) (= cname "rayw")))


