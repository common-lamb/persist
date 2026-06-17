
;; ==== persist

(in-package :persist)

(declaim (optimize sb-c:store-source-form)) ;; necessary before compilation happens

;; ==== global parameters

(defvar *unset-program-name* "unset-program-name"
  "program-name when not explicitly set by user. universal to all instances of persist")

(defparameter *program-name* *unset-program-name*
  "prefixed to files in cache dir <program-name>_function_Ha5H.bin")

;; ==== configuration

(defparameter *config* '() "active configuration")

(defparameter *config-common*
  `(
    ;;:application-root ,(asdf:component-pathname (asdf:find-system :persist))
    :cache-directory ,(if (uiop:getenv "TMPDIR")
                         (merge-pathnames "persist/"
                                          (uiop:getenv "TMPDIR"))
                         (merge-pathnames "persist/"
                                          #P"/tmp/"))
    :force-recalculation nil ;; when t do not return cache hits
    :eviction-active t ;; t or nil to activate eviction
    :max-cache-size-tb 0.25 ;; specify the cache size in Tb scale
    :evict-other-programs nil ;;  DANGER: if t eviction operates on all cache contents
    :log-level :info
    :debug nil ;; true or nil
    :depot-backend :file-system ;; &&& to be used for sqlite and ipfs when implemented
    ))

(defparameter *config-dev*
  '(
    :debug t
    :log-level :debug
    :force-recalculation t
    :max-cache-size-tb 0.0001
    ))

(defparameter *config-prod*
  '(
    :max-cache-size-tb 0.25
    ))

(defparameter *config-force-refresh*
  '(
    :force-recalculation t
    :eviction-active t
    :evict-other-programs t
    ))

(defun config-merge (config-super config-sub)
  "merges plists
config-super keywords will be found before any keywords also found in config-sub"
  `(,@config-super ,@config-sub))

(defun config (&key kw (config *config*))
  "fetches current configuration or a specific value"
  (assert (not (null config)) (config) "config must be set")
  (if kw
      (progn
        (assert (not (null (find kw config))) (kw)
                "keyword not found in config ~%~S not an element of ~%~S" kw config)
        (getf config kw))
      config))

;; &&& with config macro
;; (let ((*config* *config-dev*))
;;   (cache-file-pathname 'add1 '(1)))

;; ==== argument literal hashes
(defun hash-arg (arg)
  (cryptos:md5 (format nil "~S" arg)))

(defun hash-2-args (arg1 arg2)
  (cryptos:md5 (format nil "~S~S" (hash-arg arg1) (hash-arg arg2))))

(defun hash-args (args)
  "takes an arbitrary list of args
  reduce to a hash of hashes"
  (case (length args)
    (0 (cryptos:md5 ""))
    (1 (hash-arg (first args)))
    (otherwise (reduce #'hash-2-args args))))

;; ==== file content hashes
(defun hash-file (file)
   (ironclad:byte-array-to-hex-string
    (ironclad:digest-file :md5 file)))

(defun hash-2-files (file1 file2)
  (cryptos:md5 (format nil "~S~S" (hash-file file1) (hash-file file2))))

(defun hash-files (args)
  "takes an arbitrary list of args
   filters for files that exist
   hashes the contents of the files"
  (let ((files (remove-if-not #'uiop:file-exists-p args)))
    (case (length files)
      (0 (cryptos:md5 ""))
      (1 (hash-file (first files)))
      (otherwise (reduce #'hash-2-files files)))))

;; ==== function hashes

(defun ensure-function-object (fun &key (sym-in-only t) (fun-out-only t))
  "converts symbol to function. with optional enforcement of inputs and outputs"
  (let ((function-object (cond
                           ((functionp fun) fun)
                           ((fboundp fun) (symbol-function fun))
                           ;; nil if no way to find function
                           )))
    ;; ensure fun passed as symbol 'fun
    ;;(because #'fun will resolve the function at a point in time,
    ;; we want the symbol to dynamically respond to definition changes)
    (when (and sym-in-only
               (not (symbolp fun)))
      (error "~&fun must be passed as a symbol: ~S" fun))
    ;; enforce functions only
    ;; &&& add an error if fun-object is a macro
    (when (and fun-out-only
               (not (functionp function-object)))
      (error "~&fun must be function bound: ~S" fun))
    function-object))

(defun hash-function (fun)
  "
takes a function (or macro or symbol)
hashes the string representation of the lambda form and the output of describe
a strong but not perfect guarantee
sensitive to changes in arg list, documentation strings, and the literal text of the body
sensitive to whether the function is compiled or evaluated, to whether it is passed as 'function or #'function
not sensitive to comments
requires (declaim (optimize sb-c:store-source-form)) to be set
"
  ;; (defun normalize-asm-line (line)
  ;;   "normalize dissassembly chiefly by removing hexadecimal and other variable content"
  ;;   (let* (;; drop leading semicolon space
  ;;          (line (str:replace-first "^; " "" line :regex t))
  ;;          ;; drop hexadecimal offsets (hex address changes)
  ;;          (line (str:replace-first "^[0-9A-F][0-9A-F]:" "" line :regex t))
  ;;          ;; ;; drop internal hexadecimal adresses
  ;;          ;; (line (str:replace-all "\\[#x[0-9A-F]+\\]" "[]" line :regex t))
  ;;          ;; drop additional hexadecimal addresses
  ;;          (line (str:replace-all "#x[0-9A-F]+" "HEXADDR" line :regex t))
  ;;          ;; drop whitespace
  ;;          (line (str:trim line)))
  ;;     line))

  ;; (let* ((disassembly (with-output-to-string (s)
  ;;                       (let ((*standard-output* s))
  ;;                         (disassemble fun))))
  ;;        (lines (str:lines disassembly))
  ;;        (lines-normed (mapcar #'normalize-asm-line lines))
  ;;        (disassembly-normed (str:unlines lines-normed))))

  (let* (
         ;; attempt to coerce fun to function object
         (function-object (ensure-function-object fun))
         (lambda-form (when function-object
                        (function-lambda-expression function-object)))
         (normalized-string-form (with-standard-io-syntax
                                   (let ((*print-circle* t))
                                     (write-to-string lambda-form))))
         ;; in case of macros and symbols
         (description (with-output-to-string (s)
                        (let ((*standard-output* s))
                          (describe fun))))
         )
    (cryptos:md5 (concatenate 'string normalized-string-form description))))

;; ==== form hash
(defun hash-form (fun &optional args)
  (cryptos:md5 (format nil "~S~S~S"
                       (hash-function fun)
                       (hash-args args)
                       (hash-files args))))

;; ==== tests for hashing

(defun add1 (a) (+ a 1))

;; when evaluated
;; (hash-function #'add1)
;; => error
;; (hash-form #'add1)
;; => error
;; (hash-function 'add1)
;; => "f09ae336824a4b1bc3ac6da69cfd74aa"
;; (hash-form 'add1)
;; => "9f82192449e53a77f8f21ccda5de4981"
;; (hash-form 'add1 '(1))
;; => "06897111455f9802e01dcc2a2bad51ee"

;; (persist (add1 1))
;; => lookup:
;;  #P"/tmp/persist/unset-program-name_ADD1_06897111455f9802e01dcc2a2bad51ee.bin"

;; when compiled
;; (hash-function #'add1)
;; => error
;; (hash-form #'add1)
;; => error
;; (hash-function 'add1)
;; => "e56fd69091d2266f39e9cf128616ade9"
;; (hash-form 'add1)
;; => "1d099fd3d1731b10f5151c6855eb5759"
;; (hash-form 'add1 '(1))
;; => "03d40f64c5f5b4ed458876c6322e76d8"
;; (persist (add1 1))
;; => lookup:
;;  #P"/tmp/persist/unset-program-name_ADD1_03d40f64c5f5b4ed458876c6322e76d8.bin"

;; ==== file name generation

(defun function-name (fun)
  (let* (
         (function-object (ensure-function-object fun))
         (function-string (write-to-string function-object))
         (drop-curlys (str:replace-all "{.*}" "" function-string :regex t))
         (just-name
           (str:replace-first "^#<FUNCTION " ""
                              (str:replace-first ">$" ""
                                                 drop-curlys
                                                 :regex t)
                              :regex t))
         (sanitized (str:remove-punctuation just-name :replacement "")
                    ))
    sanitized))

(defun cache-file-pathname (fun args &key (program-name *program-name*))
  "creates a pathname for the binary memoization"
  ;; &&& warn if program name not set
  (let ((cache-dir (config :kw :cache-directory))
        (hash (hash-form fun args))
        (function-name (function-name fun)))
    (make-pathname :directory (pathname-directory cache-dir)
                   ;; program-name.fun-name.HA4h.bin
                   :name (format nil "~A_~A_~A" program-name function-name hash)
                   :type "bin")))

;; ==== lookup
(defun lookup (cache-file-name &key (config *config*))
  "cache-file-name: pathname in cache"
  (format t "~&lookup:~& ~S" cache-file-name)
  ;; &&&  :force-overwrite true, no action, nil will force calculation
  (unless (config :kw :force-recalculation)
    ;; use depot to search for filepath &&&
    ;; return hit &&&
    )
  ;; &&& can now use config to force recalculation
  )

;; ==== reuse
(defun reuse (hit &key (config *config*))
  "hit: whatever the pathname becomes when found in depot"
  (format t "~&reuse:~& ~S" hit)
  ;; &&& what does depot return
  ;; &&& annotate reuse in depot attributes
  ;; &&& unpack binary to annotated result
  ;; (let ((result-form (getf annotated-result :result-form))))
  ;; &&& to handle multiple values
  ;; (apply #'values result-form)
  (format nil "result"))

;; ==== calculate
(defun calculate (fun args &key (config *config*))
  (format t "~&calculate:~& ~S~& ~S" fun args )
  (let (t-before t-after t-delta result-form)
    (setf t-before (local-time:now))
    ;; do fuction call, as list with multiple values
    (setf result-form (multiple-value-list (apply fun args)))
    (setf t-after (local-time:now))
    ;; delta time before and after run
    (setf t-delta (local-time:timestamp-difference t-after t-before)) ;; &&& local-time
    ;; returning a plist of annotations and result
    (list :time t-delta :result-form result-form)))

;; ==== record
(defun record (cache-file-name annotated-result &key (config *config*))
  (format t "~&record:~& ~S~& ~S" cache-file-name annotated-result)
  (let ((result-form (getf annotated-result :result-form))))
  ;; &&& pack binary of result-form
  ;; &&& create cache entry possibly overwriting
  ;; &&& annotate cache entry with time to compute
  ;; &&& add to cache
  (format nil "cached"))

;; ==== yield
(defun yield (annotated-result)
  (format t "~&yield:~& ~S" annotated-result)
  ;; give result back to user
  (let ((result-form (getf annotated-result :result-form)))
    ;; handle mulitiple values
    (apply #'values result-form)))

;; ==== memoization

(defmacro persist (form)
  "Form memoization"
  (let ((fun (car form))
        (args (cdr form)))
    `(let ((cache-file-name (cache-file-pathname ',fun ',args)))
       (if-let ((hit (lookup cache-file-name)))
         (reuse hit)
         (let ((annotated-result (calculate ',fun ',args)))
           (record cache-file-name annotated-result)
           (yield annotated-result))))))

(persist (+ 1 2 3))

;; &&& logging at info
;; &&& logging at debug
;; &&& tests


;; ==== &&& use depot to control the cache
;; ==== &&& use cl-binary-store to pack and unpack cache contents

;; add sqlite backend to depot
;; add ipfs backend to depot



;; ==== initialization &&&
(setf *config* (config-merge *config-dev* *config-common*))


;; ==== eviction &&&

;; independent process of memoization
;;   in own thread
;;     start/restart with initialization
;;   watches cache for new file write
;;   calculates depot size
;;   when over threshold
;;   evicts oldest of *program-name* and "un-named"
;;   optionally
;;     compute time added to depot attribute
;;     offset is: longest compute time shifts more recent by half of age ranking span


;; ====  &&& share mine notes
;; beam should be a separate menu
;; evaluate symbol
;; beam function
;; highlight opposite paren forward
;; jump cursor by forms
;; live pinned evaluation
;; file and repl side by side not up down
;; vim!


;; &&& macro eval-once is let over lambda that caches
