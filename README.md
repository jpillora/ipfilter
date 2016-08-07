# ipfilter

An IP Filter package in Go (golang)

[![GoDoc](https://godoc.org/github.com/jpillora/ipfilter?status.svg)](https://godoc.org/github.com/jpillora/ipfilter)  [![CircleCI](https://circleci.com/gh/jpillora/ipfilter.svg?style=shield)](https://circleci.com/gh/jpillora/ipfilter)

### Install

```
go get github.com/jpillora/ipfilter
```

### Features

* Simple
* Thread-safe
* IPv4 / IPv6 support
* Subnet support
* HTTP middleware
* [GeoLite2](https://dev.maxmind.com/geoip/geoip2/geolite2/) support for country-based blocking

### Usage

**Country-block HTTP Middleware**

```go
myHandler := http.Handler(...)
myProtectedHandler := ipfilter.Wrap(myHandler, ipfilter.Options{
    //block requests from China and Russia by IP
    BlockedISOCodes: []string{"CN", "RU"},
})
http.ListenAndServe(":8080", myProtectedHandler)
```

**Country-block stand-alone**

```go
f, err := ipfilter.New(ipfilter.Options{
    BlockedISOCodes: []string{"CN"},
})

f.Blocked("116.31.116.51") //=> true (CN)
f.Allowed("216.58.199.67") //=> true (US)
```

**Allow your LAN only**

```go
f, err := ipfilter.New(ipfilter.Options{
    AllowedIPs: []string{"192.168.0.0/24"},
    BlockByDefault: true,
})
//only allow 192.168.0.X IPs
f.Allowed("192.168.0.42") //=> true
f.Allowed("10.0.0.42") //=> false
```

... and with dynamic list updates

```go
//and allow 10.X.X.X
f.AllowIP("10.0.0.0/8")
f.Allowed("10.0.0.42") //=> true
f.Allowed("203.25.111.68") //=> false
//and allow everyone in Australia
f.AllowCode("AU")
f.Allowed("203.25.111.68") //=> true
```

#### Issues

* Due to the nature of IP address allocation, determining location based of a
  single IP address is quite difficult (if you're not Google) and is therefore
  not very reliable. For this reason `BlockByDefault` is off by default.
* IP DB lookups take on the order of `5µs` to perform, though the initial load
  into memory takes takes about `350ms` so be wary of excessive `ipfilter.New` use.

#### Todo

* Use a good algorithm to perform faster prefix matches
* Investigate reliability of other detectable attributes
* Add TOR/anonymizer filter options
* Add great-circle distance filter options ("allow 500KM radius from code/lat,lon")

#### Credits

* github.com/oschwald/maxminddb-golang
* This software uses GeoLite2 data created by MaxMind, available from http://www.maxmind.com

#### MIT License

Copyright © 2016 &lt;dev@jpillora.com&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
