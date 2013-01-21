(asdf:defsystem :trivial-ldap
  :version "0.94"
  :author "Kevin Montuori"
  :maintainer "Raymond Wiker <rwiker@gmail.com>"
  :licence "Clarified Artistic License"
  :description "TRIVIAL-LDAP is a one file, all Common Lisp client implementation of parts of RFC 2261."
  :components ((:file "package") 
               (:file "trivial-ldap" :depends-on ("package")))
  :depends-on (#:usocket #:cl+ssl #:yacc))
