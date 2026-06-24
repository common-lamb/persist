(defpackage :persist
  (:use #:cl #:uiop)
  (:local-nicknames (:depot :org.shirakumo.depot))
  (:export #:persisted
           #:*program-name*
           #:*depot*
           #:*config*
           #:*config-common*
           #:*config-dev*
           #:*config-prod*
           #:*config-force-refresh*
           #:*config-clobber-cache*
           #:config-merge
           #:with-config
           #:initialize
           #:persisted
           ))
