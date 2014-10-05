(ns ring.middleware.hmac-check
  (:use [clojure.pprint])
  (:import [org.apache.commons.codec.binary Base64 Hex]
           [org.apache.commons.codec DecoderException]
           [java.util Arrays]))

(defn hmac
  ([algorithm msg key]
    (hmac algorithm msg key "UTF8"))
  ([algorithm msg key encoding]
    (let [key (javax.crypto.spec.SecretKeySpec. (.getBytes key "UTF8") algorithm)
          mac (doto (javax.crypto.Mac/getInstance algorithm)
                (.init key))]
      (.doFinal mac (.getBytes msg encoding)))))

(defn wrap-hmac-check
  "Function used to add the hmac-check middleware to the Ring stack. By default
  this will check POST requests for a Hex encoded digest and if wrong overwrite
  the response as 403 forbidden.

    - algorithm should be an algorithm string, for example HmacSHA512
    - secret key should be a string, or function which takes the request and
        returns a string
    - header-field should be the key for the hmac in the header (takes
        precedence over hmac-accessor-fn)
    - hmac-accessor-fn optionally used to supply a function to retrieve the
        hmac instead of using header-field
    - forbidden-handler [reason req], digest-decoder [digest], pred [req] and
      message [req] are functions that can be overwritten to change default
      behavior"
  [handler {:keys [algorithm header-field secret-key hmac-accessor-fn
                   forbidden-handler digest-decoder pred message]
            :or {forbidden-handler (fn [reason req]
                                     {:status 403
                                      :body (str "403 Forbidden - " reason)})
                 pred (fn [req] (= :post (:request-method req)))
                 digest-decoder (fn [digest] (-> digest char-array Hex/decodeHex))
                 message (fn [req] (slurp (:body req)))}}]
  {:pre [(every? identity [algorithm
                           (or header-field hmac-accessor-fn)
                           secret-key])]}
  (fn [req]
    (if (pred req)
      (let [given-hmac (or (get (:headers req) header-field)
                           (and hmac-accessor-fn (hmac-accessor-fn req)))
            secret (or (and (fn? secret-key) (secret-key req))
                       secret-key)
            our-hmac (hmac algorithm (message req) secret)]
        (try
          (if (Arrays/equals (digest-decoder given-hmac) our-hmac)
            (handler req)
            (forbidden-handler "Incorrect HMAC" req))
          (catch DecoderException e
            (forbidden-handler (str "Invalid HMAC (" (.getMessage e) ")") req))))
      (handler req))))
