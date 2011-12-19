Introduction
============

One-two, one-two... is this thing working?

This is Kevin Montuori's *trivial-ldap*, with a few modifications.

A few years back, I needed some mechanism for querying AD servers, as
part of a custom content connector for the FAST ESP search engine. I
found trivial-ldap, and was quickly using it to good effect.

After having used trivial-ldap for a while, I made some modifications,
and asked Kevin to review them, and integrate them if he felt that
they added value. Unfortunately, Kevin is too busy to spend time
on trivial-ldap, so he basically let me publish whatever changes I
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



