(in-package :persist)
;; necessary before function compilation happens
(declaim (optimize sb-c:store-source-form))

;; ==== global parameters

(defvar *unset-program-name* "unset-program-name"
  "program-name when not explicitly set by user. universal to all instances of persist. cache entries with this program name are always candidates for eviction")

(defparameter *program-name* *unset-program-name*
  "prefixed to files in cache dir <program-name>_function_Ha5H.bin")

;; global depot
(defparameter *depot* nil
  "the active depot")

;; ==== configuration

(defparameter *config* '() "global active configuration")

(defun find-cache-dir ()
  "attempts to get temp dir from environment"
  (let ((tempdir (if (uiop:getenv "TMPDIR")
                     (uiop:getenv "TMPDIR")
                     #P"/tmp/")))
    (assert (uiop:directory-exists-p tempdir) (tempdir)
            "~&the temporary directory does not exist: ~S~&" tempdir)
    ;; return the cache dir, which is ensured to exist and its parent to preexist
    (ensure-directories-exist (merge-pathnames "persist/" tempdir))))

(defparameter *config-common*
  `(
    :cache-directory ,(find-cache-dir)
    :force-recalculation nil ;; when t do not return cache hits
    :eviction-active t ;; t or nil to activate eviction
    :max-cache-size-tb 0.25 ;; specify the cache size in Tb scale
    :evict-other-programs nil ;;  DANGER: if t eviction operates on all cache contents
    :log-level :info
    :debug nil ;; t or nil
    :depot-backend :file-system ;; TODO to be used for sqlite and ipfs when implemented
    ))

(defparameter *config-dev*
  '(
    :debug t
    :log-level :debug
    :force-recalculation nil
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
    ))

(defparameter *config-clobber-cache*
  '(
    :force-recalculation t
    :eviction-active t
    :evict-other-programs t
    ))

;; TODO make a separate simple config/data switcher "context"
(defun config-print (config)
  "pretty prints plists"
  (loop for (key value) on config by #'cddr
        do (format t "~&~S ~S~&" key value)))

(defun config-merge (config-super config-sub)
  "merges plists
config-super keywords will be found before any keywords also found in config-sub"
  ;; TODO merge replacing values, not just prepend
  `(,@config-super ,@config-sub))

(defun config-get (kw &optional (config *config*))
  "fetches a specific value, defaults to global *config*"
  (progn
    (assert (not (null (find kw config))) (kw)
            "keyword not found in config ~%~S not an element of ~%~S" kw config)
    (getf config kw)))

(defmacro with-config (config &body body)
  "redefines global *config* for the scope of the body"
  `(let ((*config* ,config))
     ,@body))

;; ==== initialization
(defun initialize-logging (&key (log-level :info))
  "initializes logging"
  ;; one file no rolling backup
  (log:config :daily "persist.log" :backup nil) ;; &&& better filename
  (log:config log-level))

(defun initialize-depot (cache-directory)
  (let* ((dir (pathname-directory-pathname cache-directory))
         (depot (depot:from-pathname dir)))
    (setf *depot* depot)))

(defun initialize (&key (added-config nil) (program-name *unset-program-name*))
  "initializes persistence config, logs, parameters etc"
  (setf *config* (config-merge added-config *config-common*))
  (format t "~&using config:~&" )
  (config-print *config*)
  ;;
  (initialize-logging :log-level (config-get :log-level))
  (initialize-depot (config-get :cache-directory) )
  ;; initialize-eviction
  (setf *program-name* program-name)
  ;; warnings for less than ideal states
  (when (and added-config
             (not (equal added-config
                  *config-prod*)))
    (warn "~&added a non production configuration: ~S" added-config))
  (when (string= *program-name* *unset-program-name*)
    (warn "~& unset *program-name*~&  any cache files ~A_*.bin are always candidates for eviction" *unset-program-name*)))

;; ==== argument hashes

(defun hash-arg (arg)
  "hashes the argument"
  (log:trace "args: ~S" arg)
  (cryptos:md5 (format nil "~S" arg)))

(defun hash-2-args (arg1 arg2)
  "hashes 2 arguments"
  (log:trace "args: ~S ~S" arg1 arg2)
  (cryptos:md5 (format nil "~S~S" (hash-arg arg1) (hash-arg arg2))))

(defun hash-args (args)
  "takes an arbitrary list of args
  reduce to a hash of hashes"
  (log:trace "args: ~S" args)
  (case (length args)
    (0 (cryptos:md5 ""))
    (1 (hash-arg (first args)))
    (otherwise (reduce #'hash-2-args args))))

;; ==== file content hashes
(defun hash-file (file)
  "hash the contents of a file, as pathnames alone are not a strong enough guarantee of identity of a computation"
  (log:trace "args: ~S" file)
  (ironclad:byte-array-to-hex-string
   (ironclad:digest-file :md5 file)))

(defun hash-2-files (file1 file2)
  (log:trace "args: ~S" file1 file2)
  (cryptos:md5 (format nil "~S~S" (hash-file file1) (hash-file file2))))

(defun hash-files (args)
  "takes an arbitrary list of args
   filters for files that exist
   hashes the contents of the files"
  (log:trace "args: ~S" args)
  (let ((files (remove-if-not #'uiop:file-exists-p args)))
    (case (length files)
      (0 (cryptos:md5 ""))
      (1 (hash-file (first files)))
      (otherwise (reduce #'hash-2-files files)))))

;; ==== function hashes
(defun ensure-function-object (fun &key (sym-in-only t) (fun-out-only t))
  "converts symbol to function. with optional enforcement of inputs and outputs"
  (log:trace "args: ~S ~S ~S" fun sym-in-only fun-out-only)
  (let ((function-object (cond
                           ((functionp fun) fun)
                           ((fboundp fun) (symbol-function fun))
                           ;; nil if no way to find function
                           )))
    ;; ensure fun passed as symbol 'fun
    ;;(#'fun will resolve the function object at a point in time,
    ;; we want the symbol to dynamically respond to definition changes)
    (when (and sym-in-only
               (not (symbolp fun)))
      (error "~&fun must be passed as a symbol: ~S" fun))
    ;; enforce functions only
    ;; TODO maybe add an error if fun-object is a macro
    (when (and fun-out-only
               (not (functionp function-object)))
      (error "~&fun must be function bound: ~S" fun))
    function-object))

(defun hash-function (fun)
  "
takes a function (or macro or symbol)
hashes both the string representations of the lambda form and the output of describe
this is a strong but not perfect guarantee of function identity
it it sensitive to changes in function name, arg list, documentation strings, and the literal text of the body of the function
it is sensitive to whether the function is compiled or evaluated, to whether it is passed as 'function or #'function
it is not sensitive to comments
requires (declaim (optimize sb-c:store-source-form)) to be set to guarantee lambda form is stored when functions are compiled
"
  ;; normalizing assembly would be stronger than the strings approach
  ;; however this requires knowledge of compiler optimizations
  ;; in particular the opcode of generic functions changes between compilations
  ;;
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

  (let* (;; lambda form to normalized string
         (function-object (ensure-function-object fun))
         (lambda-form (function-lambda-expression function-object))
         (normalized-string-form (with-standard-io-syntax
                                   (let ((*print-circle* t))
                                     (write-to-string lambda-form))))
         ;;description to string, in case of macros
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

;; ==== file name generation
(defun function-name (fun)
  "converts functions to a string, normalized for filename purposes"
  (log:trace "~&args: ~S" fun)
  (let* ((function-object (ensure-function-object fun))
         (function-string (write-to-string function-object))
         (drop-curlys (str:replace-all "{.*}" "" function-string :regex t))
         (just-name
           (str:replace-first "^#<FUNCTION " ""
                              (str:replace-first ">$" ""
                                                 drop-curlys
                                                 :regex t)
                              :regex t))
         (sanitized (str:remove-punctuation just-name :replacement "")))
    sanitized))

(defun cache-file-pathname (fun args &key (program-name *program-name*) (depot *depot*))
  "creates a pathname for the memoization binary"
  (log:trace "~&args: ~S ~S ~S" fun args program-name)
  (let ((cache-dir (depot:to-pathname depot))
        (hash (hash-form fun args))
        (function-name (function-name fun)))
    (make-pathname :directory (pathname-directory cache-dir)
                   ;; program-name_fun-name_HA4h.bin
                   :name (format nil "~A_~A_~A" program-name function-name hash)
                   :type "bin")))

;; ==== memoization operations
(defun lookup (cache-file-name &key (config *config*) (depot *depot*))
  " checks if a result is already in cache
cache-file-name: pathname potentially in cache"
  (log:trace "~&args: ~S ~S" cache-file-name (config-get :force-recalculation))
  ;; &&& config calls to local config
  (if (config-get :force-recalculation)
      ;; when :force-recalculation true, do no action,
      ;; returning nil forces calculation at the memoization macro
      (progn
        (log:warn "forcing recalculation")
        nil)
      ;; use depot to search for a file
      (let* ((name (pathname-name cache-file-name))
             (type (pathname-type cache-file-name))
             (hits (depot:query-entries depot :name name :type type))
             (hit (first hits)))
        (when (< 1 (length hits))
          (error "~&there should only be one hit! hits: ~S" hits))
        (log:trace "~&hits: ~S" hits)
        (log:debug "~&hit: ~S" hit)
        hit)))

(defun reuse (hit &key (config *config*))
  "reuses a cache hit, unwrapping any encoding and annotation and multiple values
hit: an entry found in depot, an annotated result"
  (log:trace "~&args: ~S" hit)
  (let* ((pathname (depot:to-pathname hit))
         ;; read content of hit
         ;; TODO cl-binary-store restore here
         (annotated-result (read-from-string
                            (depot:with-open (transaction hit :input 'character)
                              (depot:read-from transaction 'character))) )
         (check-sum (getf annotated-result :result-form-crc32))
         (result-form (getf annotated-result :result-form))
         (result-string (write-to-string result-form)))
    ;; for safety use checksum to validate result form remains unmodified
    (if (string= check-sum (cryptos:crc32 result-string))
        (log:debug  "the result-form-crc32 and result-form form match")
        ;; TODO handle error, calculate
        (error "the result-form-crc32 and result-form do not match, the result form could be modified"))
    (log:warn "~&reusing cached calculation: ~S" hit)
    ;; update time attribute
    (setf (org.shirakumo.file-attributes:modification-time pathname)
          (get-universal-time))
    (log:trace "~&annotated-result: ~S" annotated-result)
    ;; return result, handle multiple values
    (apply #'values result-form)))

(defun calculate (fun args &key (config *config*))
  "executes the function call, captures multiple values, annotates the result"
  (log:trace "~&args: ~S ~S" fun args )
  (log:info "~&calculating: (apply ~S ~S))" fun args)
  (let* ((t-before (local-time:now))
         ;; do fuction call, as list with multiple values
         (result-form (multiple-value-list (apply fun args)))
         (t-after (local-time:now))
         (result-string (write-to-string result-form))
         (check-sum (cryptos:crc32 result-string))
         ;; delta time before and after run
         (t-delta (local-time:timestamp-difference t-after t-before)))
    ;; add any annotations before the result-form
    (list :time t-delta :fun fun :args args :result-form-crc32 check-sum :result-form result-form)))

(defun record (cache-file-name annotated-result &key (config *config*) (depot *depot*))
  "records an annotated result to the depot"
  (log:trace "~&args: ~S ~S" cache-file-name annotated-result)
  (let* (
         ;; create cache entry
         (id (pathname-name cache-file-name))
         (type (pathname-type cache-file-name))
         (entry (depot:make-entry depot :id id :type type))
         ;; pull apart annotations
         ;; (result-form (getf annotated-result :result-form))
         ;; (t-delta (getf annotated-result :time))
         )
    ;; create cache entry, write annotated result
    ;; can overwrite prior cache-file-name if it exists
    (log:info "~&recording to cache: ~S" entry)
    (depot:with-open (transaction entry :output 'character)
      (depot:write-to transaction
                      ;; TODO cl-binary-store store here
                      (write-to-string annotated-result)))
    ;; TODO use annotations to update entry attributes
    (log:trace "~&depot: ~S" depot)
    (log:trace "~&id: ~S" id)
    (log:trace "~&type: ~S" type)
    (log:trace "~&entry: ~S" entry)
    ;; return
    entry))

(defun use (annotated-result)
  "unpacks an annotated result, returning values to the user"
  (log:trace "~&args: ~S" annotated-result)
  ;; give result back to user
  (let ((result-form (getf annotated-result :result-form)))
    ;; handle multiple values
    (apply #'values result-form)))

;; ==== memoization macro

(defmacro persisted (form)
  "function call memoization
document: you should persist only pure and referentially transparent functions
document: the side effect of only the persisted function call will be supressed on sucessful hits, side effects of arguments will occur, unless of course they are also persisted at some point.
"
  (log:trace "~&args: ~S" form)
  (let* ((fun (car form))
        (literal-args (cdr form))
        ;; allow side-effects from arguments to happen at the expected time
        (evaluated-args (mapcar #'eval literal-args)))
    `(let ((cache-file-name (cache-file-pathname ',fun ',evaluated-args)))
       (if-let ((hit (lookup cache-file-name)))
         (reuse hit)
         (let ((annotated-result (calculate ',fun ',evaluated-args)))
           (record cache-file-name annotated-result)
           (use annotated-result))))))

;; ====  TODO eviction

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
;; (depot:delete-entry entry)

;; TODO tests
;; TODO consider use cl-binary-store to pack and unpack cache contents
;; TODO add sqlite backend to depot
;; TODO add ipfs backend to depot

;; ====  TODO share mine usage notes
;; beam type ops should be in a separate menu
;; beam (evaluate) symbol
;; beam (compile) function
;; highlight opposite paren forward
;; navigate cursor by parens
;; editor and repl split as columns not horizontal
;; editor, REPL, tree columns on screen in order R to L like keys ERT
;; vim bindings!

;; ==== for testing

;; (defun add1 (a) (+ a 1)) ;; (defun add1 (a) (+ a 1))

;; (initialize :added-config *config-dev* :program-name "testing")
;; (initialize :added-config *config-prod* :program-name "testing")
;; (initialize :program-name "testing")
;; (persisted (add1 1))
