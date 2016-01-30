# hmac-express

A simple middleware to be used with express. It checks if the HMAC digest encoded in hex of the body is equal to the value of the one provided through the query string.

	npm install hmac-express

# Getting Started

This middleware requires three parameters when it is created. The first two are the algorith and the secret key that will be used by the createHmac function of the crypto library. The third one is the name of the query parameter containing the HMAC digest to check.

``` javascript
var middleware = require("hmac-express")("sha-256", "secret", "token")

app.get("/", middleware, function(request, response) {
	response.send("Hello")
})

```

# License
Copyright (c) 2016 Gautier TANGUY

MIT License