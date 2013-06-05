(defproject ring-hmac-check "0.2.0"
  :description "Ring middleware for HMAC checking."
  :dependencies [[org.clojure/clojure "1.3.0"]
                 [commons-codec/commons-codec "1.4"]]
  :profiles {
    :dev {
      :dependencies [[swank-clojure "1.3.3-SNAPSHOT"]
                     [ring/ring-devel "1.1.1"]]}})
