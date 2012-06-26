# `ring-hmac-check`

[Ring](http://github.com/mmcgrana/ring) middleware that checks POST requests have a valid HMAC of the HTTP POST body in the header.

### Usage

#### With Noir - in server.clj
      (server/add-middleware wrap-hmac-check {:algorithm "HmacSHA512" :header-field "AUTH-HMAC"
                                              :secret-key "FIXME put key here"})

## License

Copyright (C) 2011 Dave Barker

Code distributed under the Eclipse Public License, the same as Clojure.

