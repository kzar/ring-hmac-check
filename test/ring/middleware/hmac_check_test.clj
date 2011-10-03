(ns ring.middleware.hmac-check-test
  (:import [org.apache.commons.codec.binary Base64]
           [java.util Arrays])
  (:use clojure.test
        ring.middleware.hmac-check))

; Test the HMAC function works
(deftest hmac-sha512
  (is (Arrays/equals (hmac "HmacSHA512" "hello world" "test")
         (Base64/decodeBase64 "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw=="))))

(def hmac-check-handler (wrap-hmac-check identity {:algorithm "HmacSHA512" :header-field "AUTH-HMAC"
                                                   :secret-key "very-secret-key"}))

; Test that valid requets are left alone
;(deftest valid-request
;  (hmac-check-handler 