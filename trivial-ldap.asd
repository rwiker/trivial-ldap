(defpackage :trivial-ldap-system (:use #:cl #:asdf))
(in-package :trivial-ldap-system)


(defsystem :trivial-ldap
  :version "0.93"
  :author "Kevin Montuori"
  :maintainer "Raymond Wiker <rwiker@gmail.com>"
  :licence "Clarified Artistic License"
  :description "TRIVIAL-LDAP is a one file, all Common Lisp client implementation of parts of RFC 2261."
  :components ((:file "trivial-ldap"))
  :depends-on (usocket cl+ssl yacc))
