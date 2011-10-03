(ns ring.middleware.hmac-check
  (:import [org.apache.commons.codec.binary Base64]
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
  [handler {:keys [algorithm header-field secret-key forbidden-handler pred]
            :or [forbidden-handler (fn [req]
                                     {:status 403 :body "403 Forbidden - Incorrect HMAC"})
                 pred (fn [req] (= :post (:request-method req)))]}]
  {:pre [(every? identity [algorithm header-field secret-key])]}
  (fn [req]
    (handler
     (if (pred req)
       (let [given-hmac (Base64/decodeBase64 (header-field (:header req)))
             our-hmac (hmac algorithm (:body req) secret-key)]
         (if (Arrays/equals given-hmac our-hmac)
           req
           (forbidden-handler req)))
       req))))