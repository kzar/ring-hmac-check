(ns ring.middleware.hmac-check-test
  (:import [org.apache.commons.codec.binary Base64 Hex]
           [java.util Arrays])
  (:use clojure.test
        ring.middleware.hmac-check))

(def hmac-check-handler (wrap-hmac-check identity {:algorithm "HmacSHA512" :header-field "AUTH-HMAC"
                                                   :secret-key "very-secret-key"}))

(def request {:uri "/"
              :request-method :post
              :server-port 80
              :server-name "dave.inadub.co.uk"
              :remote-addr "localhost"
              :scheme :http
              :headers {"AUTH-HMAC" "dcb14db632d96a3a4dd9259c858242b037b3e95bd569744097231aa0c042ff147b927d0a4704e82732a250717851e89e64421793f259185c0675a64694966da3"}
              :body "This is the test body"})


(deftest hmac-sha512
  (is (Arrays/equals (hmac "HmacSHA512" "test" "hello world")
                     (-> "f39526a1625c5ef672f250037d3b9669e2c6d38c8e19c30344ff04a4fb048ea556befd34ce6dc8fbc7667c76e33c6053bf603ab5760b6e55ce9ab5f1d2274035" char-array Hex/decodeHex))))

(deftest valid-request
  (is (= (hmac-check-handler request) request)))

(deftest invalid-request
  (let [request (assoc request :body "This is a different test body")
        response (hmac-check-handler request)]
    (is (= (:status response) 403))
    (is (= (:body response) "403 Forbidden - Incorrect HMAC"))))