(ns sv.letsencrypt.ring-handler
  (:require [clojure.string :as str]))

;; Concept:
;;
;; Provides a Ring handler that can fulfill a letsencrypt
;; http-challenge.

(def ^:private
  acme-challenge-path
  "/.well-known/acme-challenge/")

(defn ring-handler
  "Expects a function `:sv.letsencrypt/get-authorization` that takes one
   argument `{:token \"*the letsencrypt token*\"}` and returns a map
   `{:authorization \"*the corresponding letsencrypt authorization
   string*\"\". Fulfills a letsencrypt http-challenge by returning the
   right autherization string for the given token."
  [{:keys [sv.letsencrypt/get-authorization]} request]
  (when (and (:request-method request)
             :get
             (str/starts-with? (:uri request)
                              acme-challenge-path))
    (let [token (str/replace (:uri request)
                             acme-challenge-path
                             "")]
      (when-let [authorization (:authorization (get-authorization {:token token}))]
        {:status 200
         :headers {"Content-Type" "text/plain"}
         :body authorization}))))
