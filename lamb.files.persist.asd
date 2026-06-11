(defsystem "lamb.files.persist"
  :description "on disk persistent memoization for expensive computations"
  :author "common-lamb (https://github.com/common-lamb)"
  :version "0.0.1"
  :license "MIT"
  :depends-on (
               :alexandria
               :journal
               :str
               :depot
               :cl-binary-store
               :ironclad
               :filesystem-utils
               :pathname-utils
               :file-attributes
               )
  :serial t
  :components ((:file "package")
               (:file "payload")))
