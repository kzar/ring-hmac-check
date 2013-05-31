(ns ring.middleware.hmac-check-test
  (:import [org.apache.commons.codec.binary Base64 Hex]
           [java.util Arrays])
  (:use clojure.test
        ring.util.test
        ring.middleware.hmac-check)
  (:require [clojure.string :as st]))

;;;;; Helper function ;;;;;

(defn req-to-map
  "Test function for parsing query string parameters"
  [request]
  (-> request
      :querystring
      (.split "&|=")
      (->> (map-indexed (fn [n x] (if (even? n) (keyword x) x))))
      (->> (apply hash-map))))

;;;;; Mocking ;;;;;

(def hmac-header-handler
  (wrap-hmac-check identity {:algorithm "HmacSHA512" 
                             :header-field "AUTH-HMAC"
                             :secret-key "very-secret-key"}))

(def test-body-auth-mac "dcb14db632d96a3a4dd9259c858242b037b3e95bd569744097231aa0c042ff147b927d0a4704e82732a250717851e89e64421793f259185c0675a64694966da3")
(def request-post {:uri "/"
              :request-method :post
              :server-port 80
              :server-name "dave.inadub.co.uk"
              :remote-addr "localhost"
              :scheme :http
              :headers {"AUTH-HMAC" test-body-auth-mac}
              :body (string-input-stream "This is the test body")})

(def hmac-querystring-handler
  (wrap-hmac-check identity {:algorithm "HmacSHA512" 
                             :hmac-accessor-fn 
                               (fn [req] (-> req req-to-map :signature))
                             :pred (fn [req] true)
                             :message (fn [req] 
                                        (str (:uri req)
                                             (st/upper-case
                                               (name (:request-method req)))))
                             :secret-key "very-secret-key"}))

(def get-auth-mac "ed68b03183b620e082dcb65c23008d769cca21b7adb3e6cdf63dd2600c90f0cf59a9d057cd8a972037995a1367560d14cc62424db7d54d08df6a2ecd5f87ed6a")
(def request-get {:uri "/foo/bar"
              :request-method :get
              :querystring (str "foo=1&bar=2&access-key-id=test&signature="
                                get-auth-mac)
              :server-port 80
              :server-name "dave.inadub.co.uk"
              :remote-addr "localhost"
              :scheme :http
              :headers {}
              ;; Empty body, since this is a GET
              :body (string-input-stream "")})

;;;;; Tests ;;;;;

(deftest hmac-sha512
  (is (Arrays/equals (hmac "HmacSHA512" "test" "hello world")
                     (-> "f39526a1625c5ef672f250037d3b9669e2c6d38c8e19c30344ff04a4fb048ea556befd34ce6dc8fbc7667c76e33c6053bf603ab5760b6e55ce9ab5f1d2274035" char-array Hex/decodeHex))))

(deftest valid-post-request
  (is (= (hmac-header-handler request-post) request-post)))

(deftest invalid-post-request
  (let [request (assoc request-post :body (string-input-stream "another body"))
        response (hmac-header-handler request)]
    (is (= (:status response) 403))
    (is (= (:body response) "403 Forbidden - Incorrect HMAC"))))

(deftest valid-get-request
  (is (= (hmac-querystring-handler request-get) request-get)))

(deftest invalid-get-request
  (let [request (assoc request-get :uri (string-input-stream "/another/uri"))
        response (hmac-querystring-handler request)]
    (is (= (:status response) 403))
    (is (= (:body response) "403 Forbidden - Incorrect HMAC"))))
