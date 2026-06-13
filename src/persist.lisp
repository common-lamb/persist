
(defparameter *program-name* "program"
  "prefixed to files in cache dir <program>.function.Ha5H.bin")
(defparameter *cache-dir*
  (if (uiop:getenv "TMPDIR")
      (merge-pathnames "persist/"
        (uiop:getenv "TMPDIR"))
      (merge-pathnames "persist/"
        #P"/tmp/")))

;; beam should be a separate menu
;; evaluate symbol
;; beam function
;; highlight opposite paren forward
;; jump cursor by forms
;; live pinned evaluation
;; file and repl side by side not up down
;; vim!

;;&&& something is changing between compilations
(defun hash-function (fun)
  "takes a function
  hashes the string representation of the assembly"
  (let* ((disassembly (with-output-to-string (s)
                  (let ((*standard-output* s))
                    (disassemble fun))))
          ;; normalize lines of assembly (memory location)
          (lines (str:lines disassembly))
          (lines-normed (mapcar #'normalize-asm-line lines))
          (disassembly-normed (str:unlines lines-normed))
          )
    (print disassembly-normed)
    (cryptos:md5 disassembly-normed)))



(defun add (a) (+ a a))
(defun add1 (a) (+ a a))
(hash-function #'add1)
;;(hash-function #'add1)

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

(defun hash-form (fun &rest args)
    (cryptos:md5 (format nil "~S~S~S"
                       (print (hash-function fun))
                       (print (hash-args args))
                       (print (hash-files args)))))


;;(disassemble 'add1)
;;(hash-function (function add1))
;;(hash-function #'add1)
(hash-function 'add1)
;;(hash-function (quote add1))


(hash-form 'add1)

(defun normalize-asm-line (line)
  (let* (;; drop leading semicolon space
         (line (str:replace-first "^; " "" line :regex t))
         ;; drop hexadecimal offsets (hex address changes)
         (line (str:replace-first "^[0-9A-F][0-9A-F]:" "" line :regex t))
         ;; ;; drop internal hexadecimal adresses
         ;; (line (str:replace-all "\\[#x[0-9A-F]+\\]" "[]" line :regex t))
         ;; drop additional hexadecimal addresses
         (line (str:replace-all "#x[0-9A-F]+" "" line :regex t))
         ;; drop whitespace
         (line (str:trim line)))
    line))
