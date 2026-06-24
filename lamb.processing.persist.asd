(defsystem "lamb.processing.persist"
  :description "persistent memoization for expensive computations"
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
               :crypto-shortcuts
               :filesystem-utils
               :pathname-utils
               :file-attributes
               :log4cl ;logging
               :try ; testing
               )
  :serial t
  :components ((:file "package")
               (:static-file "README.org")
               (:module "src"
                 :components((:file "persist")))))
