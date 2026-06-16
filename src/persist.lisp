(in-package :persist)

(declaim (optimize sb-c:store-source-form)) ;; necessary before compilation happens

;; ==== parameters

(defparameter *program-name* "un-named"
  "prefixed to files in cache dir <program>.function.Ha5H.bin")
;; &&& make a warning if unset

(defparameter *cache-dir*
  (if (uiop:getenv "TMPDIR")
      (merge-pathnames "persist/"
        (uiop:getenv "TMPDIR"))
      (merge-pathnames "persist/"
        #P"/tmp/")))

;; ==== beam notes
;; beam should be a separate menu
;; evaluate symbol
;; beam function
;; highlight opposite paren forward
;; jump cursor by forms
;; live pinned evaluation
;; file and repl side by side not up down
;; vim!

;; ==== argument literal hashes
(defun hash-arg (arg)
  (cryptos:md5 (format nil "~S" arg)))

(defun hash-2-args (arg1 arg2)
  (cryptos:md5 (format nil "~S~S" (hash-arg arg1) (hash-arg arg2))))

(defun hash-args (&rest args)
  "takes an arbitrary list of args
  reduce to a hash of hashes"
  (case (length args)
    (0 (cryptos:md5 ""))
    (1 (hash-arg (first args))) ;; &&& is this running the list or just the literal?
    (otherwise (reduce #'hash-2-args args))))

;; ==== file content hashes
(defun hash-file (file)
   (ironclad:byte-array-to-hex-string
    (ironclad:digest-file :md5 file)))

(defun hash-2-files (file1 file2)
  (cryptos:md5 (format nil "~S~S" (hash-file file1) (hash-file file2))))

(defun hash-files (&rest args)
  "takes an arbitrary list of args
   filters for files that exist
   hashes the contents of the files"
  (let ((files (remove-if-not #'uiop:file-exists-p args)))
    (case (length files)
      (0 (cryptos:md5 ""))
      (1 (hash-file (first files)))
      (otherwise (reduce #'hash-2-files files)))))

;; ==== function hashes







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
         (function-object (cond
                            ((functionp fun) fun)
                            ((fboundp fun) (symbol-function fun))
                            ;; nil if no way to find function
                            ))

         (lambda-form (when function-object
                        (function-lambda-expression function-object)
                        ;; nil if no function-object
                        ))
         (normalized-string-form (with-standard-io-syntax
                                   (let ((*print-circle* t))
                                     (write-to-string lambda-form))))
         ;; "NIL" if no function-object

         ;; in case of macros and symbols
         (description (with-output-to-string (s)
                        (let ((*standard-output* s))
                          (describe fun))))
         )
    (cryptos:md5 (concatenate 'string normalized-string-form description))))

;; ==== form hashes
(defun hash-form (fun &rest args)
  (cryptos:md5 (format nil "~S~S~S"
                       (hash-function fun)
                       (hash-args args)
                       (hash-files args))))

;; ==== testing hashes

(defun add1 (a) (+ a 1))

;; when evaluated
(hash-function #'add1)
;; => "479f583d1cf670e8f4ab63bfd3499c37"
(hash-function 'add1)
;; => "f09ae336824a4b1bc3ac6da69cfd74aa"
(hash-form #'add1)
;; => "b028cc4b0bfae8845b0cd4669fab1fe1"
(hash-form 'add1)
;; => "2167fdde66c2adfc5fb273de3136458f"

;; when compiled
(hash-function #'add1)
;; => "662081b04f977cb00ed29c82b114b2ef"
(hash-function 'add1)
;; => "41bfa566537988f2a02159f41ddb2ec6"
(hash-form #'add1)
;; => "0b5454bbbe37e83a2016a6d56c1b8f5e"
(hash-form 'add1)
;; => "8e64773b396813818378b2f01e45c433"

;; ====

(defun function-name (fun)
  (let* (
         (function-object (cond
                            ((functionp fun) fun)
                            ((fboundp fun) (symbol-function fun))
                            ;; nil if no way to find function
                            ))
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

(defun cache-file-pathname (cache-dir program-name fun &rest args)
  "creates a pathname for the binary memoization"
  (let ((hash (hash-form fun args)))
    (make-pathname :directory (pathname-directory cache-dir)
                   ;; program-name_fun-name_HA4h.bin
                   :name (format nil "~A_~A_~A" program-name (function-name fun) hash)
                   :type "bin"
                   )))

I want to eat a pizza


;; ==== eviction &&&

;; independent process of read and memoize
;;   in own thread, start/restart with initialization
;;   watches cache for new file write
;;   calculates depot size
;;   when over threshold
;;   evicts oldest of *program-name* and "un-named"
;;   optionally
;;     compute time added to depot attribute
;;     offset is: longest compute time shifts more recent by half of age ranking span
