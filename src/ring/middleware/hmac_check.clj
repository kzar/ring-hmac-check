(ns ring.middleware.hmac-check
  (:import [org.apache.commons.codec.binary Base64 Hex]
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
  "Function used to add the hmac-check middleware to the Ring stack. By default this will
  check POST requests for a Hex encoded digest and if wrong overwrite the response as 403 forbidden.
    - algorithm should be a algorithm string, for example HmacSHA512
    - header-field should be the key for the hmac in the header
    - forbidden-handler, digest-decoder and pred are functions that can be overwritten to change
      default behavoir"
  [handler {:keys [algorithm header-field secret-key forbidden-handler digest-decoder pred]
            :or {forbidden-handler (fn [req]
                                     {:status 403 :body "403 Forbidden - Incorrect HMAC"})
                 pred (fn [req] (= :post (:request-method req)))
                 digest-decoder (fn [digest] (-> digest char-array Hex/decodeHex))}}]
  {:pre [(every? identity [algorithm header-field secret-key])]}
  (fn [req]
    (handler
     (if (pred req)
       (let [given-hmac (get (:headers req) header-field)
             our-hmac (hmac algorithm (:body req) secret-key)]
         (if (Arrays/equals (digest-decoder given-hmac) our-hmac)
           req
           (forbidden-handler req)))
       req))))
