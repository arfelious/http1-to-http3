## http1-to-http3
This is a http proxy in C that attempts to use HTTP/3 first for all requests in an attempt to circumvent blocks. You can pass the port to use as the first argument, it will be 9703 by default.

This project was created to provide an HTTP proxy for HTTrack and wasn't tested besides that. It is primarily intended for testing environments and should not be used in production.