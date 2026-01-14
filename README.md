## http1-to-http3
This is a http proxy in C that attempts to use HTTP/3 first for all requests in an attempt to circumvent certain blocks. You can pass the port to use as the first argument, it will be 9703 by default.

### Building
```bash
# Standard build
make

# For pre-resolving dns on windows
make CFLAGS="-DPRERESOLVE_DNS -Wall -O3"
```

### Usage
```bash
./http1-to-http3 [PORT]
```


This project was created to provide an HTTP proxy for HTTrack and wasn't tested beyond that. It is primarily intended for testing environments and should not be used in production.