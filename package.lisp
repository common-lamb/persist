(defpackage :persist
  (:use :cl :uiop)
  (:export #:persist
           #:initialize
           #:reconfigure
           #:*configuration*
           #:*cache-dir*
           #:*program-name*))
