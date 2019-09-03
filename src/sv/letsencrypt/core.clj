(ns sv.letsencrypt.core
  (:require [clojure.java.io :as io]
            [sv.letsencrypt.pem-to-keystore :as pem-to-keystore]))

;; Concept:
;;
;; Provides the tools to use https://letsencrypt.org to receive a
;; SSL/TLS certificate for a domain.
;;
;; Letsencrypt supports a few kinds of challenges that allows you to
;; prove that you are the owner of a domain.
;;
;; At the moment this namespace supports the http-01 challenge of
;; Letsencrypt.
;;
;; It uses the [acme4j](https://github.com/shred/acme4j) library and
;; the implementation in this namespace is roughly based on this
;; example:
;; https://github.com/shred/acme4j/blob/master/acme4j-example/src/main/java/org/shredzone/acme4j/ClientTest.java

(def key-size
  ;; the default key size:
  2048)

(defn new-session
  "Creates a new `org.shredzone.acme4j.Session` for the letsencrypt
   endpoint. This should be used for the real website."
  []
  (org.shredzone.acme4j.Session.
   "acme://letsencrypt.org/"))

(defn new-staging-session
  "Creates a new `org.shredzone.acme4j.Session` for the letsencrypt
   staging endpoint. This should be used for testing."
  []
  (org.shredzone.acme4j.Session.
   "acme://letsencrypt.org/staging"))

(defn find-or-register-account
  "Finds an existing letsencrypt account or creates a new one for the
   registration of the `session` (`org.shredzone.acme4j.Session`)."
  [session account-key-pair]
  (-> (org.shredzone.acme4j.AccountBuilder.)
      (.agreeToTermsOfService)
      (.useKeyPair account-key-pair)
      (.create session)))

(defn load-or-create-key-pair
  "Loads the `java.security.KeyPair` from the `file`. Creates a new
   KeyPair and saves it to the `file`, if it does not exists yet."
  [file]
  (if (.exists file)
    (-> file
        (io/reader)
        (org.shredzone.acme4j.util.KeyPairUtils/readKeyPair))
    (let [key-pair (org.shredzone.acme4j.util.KeyPairUtils/createKeyPair key-size)]
      (org.shredzone.acme4j.util.KeyPairUtils/writeKeyPair key-pair
                                                           (java.io.FileWriter. file))
      key-pair)))

(defn load-or-create-key-pairs
  "Loads or creates the `:user-key-pair` and the `:domain-key-pair`."
  [{:keys [user-key-file domain-key-file] :as context}]
  (assoc context
         :user-key-pair (load-or-create-key-pair user-key-file)
         :domain-key-pair (load-or-create-key-pair domain-key-file)))

(defn create-order
  "Orders the certificate."
  [{:keys [domains user-key-pair domain-key-pair staging] :as context}]
  (let [session (if staging
                  (new-staging-session)
                  (new-session))
        account (find-or-register-account session
                                          user-key-pair)
        order (-> account
                  (.newOrder)
                  (.domains domains)
                  (.create))]
    (assoc context
           :session session
           :account account
           :order order)))

(defn prepare-files
  "Adds file objects to the `context` that are required for the
   letsencrypt process. All files are located in the given
   `:folder`. Remove this function from the stack, if you like to
   define other file locations."
  [{:keys [folder] :as context}]
  (.mkdirs (io/file folder))
  (assoc context
         :user-key-file (io/file folder
                                 "user.key")
         :domain-key-file (io/file folder
                                   "domain.key")
         :domain-csr-file (io/file folder
                                   "domain.csr")
         :domain-chain-file (io/file folder
                                     "domain-chain.crt")
         :keystore-file (io/file folder
                                 "keystore.jks")))

(defn get-http-challenges
  "Extracts all http challenges from the order."
  [order]
  (doall
   (map
    (fn [authorization]
      (.findChallenge authorization
                      "http-01"))
    (.getAuthorizations order))))

(defn get-http-challenge-data
  "Extracts the data from the `http-challenge` that is required to fulfill it."
  [http-challenge]
  {:token (.getToken http-challenge)
   :authorization (.getAuthorization http-challenge)})

(defn handle-http-challenge
  "Invokes the `:fulfill-http-challenge` from the `context` with the
  data of the first `http-challenge` that is found in the current
  `order`. The `:fulfill-http-challenge` function should take care
  that the corresponding web server answers with the correct
  `http-challenge` data."
  [{:keys [order fulfill-http-challenge] :as context}]
  (let [http-challenge (first (get-http-challenges order))
        http-challenge-data (get-http-challenge-data http-challenge)]
    (fulfill-http-challenge http-challenge-data)
    (assoc context
           :challenge
           http-challenge)))

(defn start-challenge
  "Starts the `challenge` and gets the updated status up to 10 times
   until the challenge has been fulfilled (VALID) or has
   failed (INVALID). Throws an exception for the cases, where the
   challenge was not fulfilled."
  [{:keys [challenge] :as context}]
  (.trigger challenge)
  (let [max-attempts 10
        sleep-ms 3000]
    (loop [attempts 0]
      (let [status (.getStatus challenge)]
        (if (= status org.shredzone.acme4j.Status/VALID)
          context
          (if (= attempts max-attempts)
            (throw (ex-info "challenge failed: maximum attempts reached"
                            {:attempts attempts
                             :challenge challenge}))
            (if (= status org.shredzone.acme4j.Status/INVALID)
              (throw (ex-info "challenge failed: status is invalid"
                              {:challenge challenge}))
              (do
                (Thread/sleep sleep-ms)
                (.update challenge)
                (recur (inc attempts))))))))))

(defn certificate-signing-request
  "Generates a Certificate Signing Request (CSR) for the `domain` and
   the `domain-key-pair` (`java.security.KeyPair`). Adds the CSR as
   byte array to the `context`."
  [{:keys [domains domain-key-pair] :as context}]
  (let [csrb (org.shredzone.acme4j.util.CSRBuilder.)]
    (.addDomains csrb domains)
    (.sign csrb domain-key-pair)
    (assoc context
           :csr-encoded (.getEncoded csrb)
           :csrb csrb)))

(defn store-csr-file
  "Stores the CSR to the `:domain-csr-file`."
  [{:keys [csrb domain-csr-file] :as context}]
  (.write csrb
          (java.io.FileWriter. domain-csr-file))
  context)

(defn execute-order
  "Executes the `order` after the letsencrypt challenge has been
   fulfilled. Waits up to 30 seconds until the order is done or throws
   an exception as timeout."
  [{:keys [order csr-encoded] :as context}]
  (.execute order
            csr-encoded)
  (loop [attempts 10]
    (if (zero? attempts)
      (throw (ex-info "order timeout"
                      context))
      (condp = (.getStatus order)
        org.shredzone.acme4j.Status/VALID
        (assoc context
               :order-executed true)
        org.shredzone.acme4j.Status/INVALID
        (throw (ex-info "order failed"
                        context))
        ;; default:
        (do
          (Thread/sleep 3000)
          (.update order)
          (recur (dec attempts)))))))

(defn get-certificate
  "Receives the certificate from letsencrypt."
  [{:keys [order] :as context}]
  (let [certificate (.getCertificate order)]
    (assoc context
           :certificate certificate)))

(defn store-certificate
  "Stores the certificate in the `:domain-chain-file`."
  [{:keys [certificate domain-chain-file] :as context}]
  (with-open [writer (java.io.FileWriter. domain-chain-file)]
    (.writeCertificate certificate
                       writer))
  context)

(defn create-keystore
  "Also creates a `keystore.jks` that can be used for Java web servers
   like Jetty to provide SSL/TLS."
  [{:keys [domain-key-file domain-chain-file keystore-file] :as context}]
  (let [keystore-data (pem-to-keystore/convert-pem-to-p12
                       {:pem-file domain-key-file
                        :password (:password context
                                             "secret")
                        :certificat-file domain-chain-file})]
    (with-open [out (java.io.FileOutputStream. keystore-file)]
      (.write out
              keystore-data))
    context))

(def letsencrypt-via-http-stack
  ;; The full stack of functions which is necessary to receive a
  ;; certificate from letsencrypt by fulfilling a http-challenge:
  [prepare-files
   load-or-create-key-pairs
   create-order
   handle-http-challenge
   start-challenge
   certificate-signing-request
   store-csr-file
   execute-order
   get-certificate
   store-certificate
   create-keystore
   ])

(defn- compose
  "Same as `clojure.core/comp` but reverse the arguments / `fns`."
  [fns]
  (apply comp (reverse fns)))

(defn letsencrypt-via-http
  "Executes the http-challenge to receive a SSL/TLS certificate from
   letsencrypt. The `context` needs a `folder` that contains the
   relevant files for the letsencrypt process. If the folder is empty
   it creates the required files."
  [context]
  ((compose letsencrypt-via-http-stack)
   context))

(comment
  ;; Example usage:

  (def sample-context
    {:folder (io/file "example-results")
     :domains ["example.com"]
     ;;:staging true
     :fulfill-http-challenge (fn [http-challenge-data]
                               (println "http-challenge-data:")
                               (prn http-challenge-data)
                               (println "press a key to continue")
                               (read))})

  (def dev-letsencrypt-via-http-stack
    (map
     (fn [f]
       (fn [context]
         (println "step:"
                  (class f))
         (f context)))
     letsencrypt-via-http-stack))

  (def result-context
    ((compose dev-letsencrypt-via-http-stack)
     sample-context))

  (create-keystore result-context)
  )
