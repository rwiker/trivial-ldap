(defpackage :trivial-ldap
  (:use #:common-lisp)
  (:nicknames #:ldap)
  (:shadow #:delete #:search)
  (:export
   ; mod types.
   #:delete #:replace #:add 
   ; search option symbols
   #:base #:sub #:one #:never #:search #:find #:always
   ; objects.
   #:entry #:ldap
   ; methods.
   #:user #:pass #:base #:debugflag #:host #:port #:rdn #:dn #:attrs #:compare
   #:sslflag #:reuse-connection #:rebind
   #:bind #:unbind #:abandon #:add #:delete #:moddn #:search 
   #:new-entry-from-list #:replace-attr #:del-attr #:add-attr #:modify
   #:attr-list #:attr-value #:new-entry #:new-ldap #:ldif #:change-rdn
   #:response #:results-pending-p #:next-search-result
   ; convenience macros
   #:dosearch #:ldif-search
   ; utilities
   #:escape-string #:unescape-string
   #:attribute-binary-p
   #:probably-binary-field-error
   #:skip-entry
   #:handle-as-binary
   #:handle-as-binary-and-add-known
   #:listify-filter))