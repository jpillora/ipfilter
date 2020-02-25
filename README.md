# ipfilter

A package for IP Filtering in Go (golang)

[![GoDoc](https://godoc.org/github.com/jpillora/ipfilter?status.svg)](https://pkg.go.dev/github.com/jpillora/ipfilter?tab=doc)  [![Tests](https://github.com/jpillora/ipfilter/workflows/Tests/badge.svg)](https://github.com/jpillora/ipfilter/actions?workflow=Tests)

### Install

```
go get github.com/jpillora/ipfilter
```

### Features

* Simple
* Thread-safe
* IPv4 / IPv6 support
* Subnet support
* Location filtering (via [phuslu/geoip](https://github.com/phuslu/geoip)
* Simple HTTP middleware

### Usage

**Country-block HTTP middleware**

```go
h := http.Handler(...)
myProtectedHandler := ipfilter.Wrap(h, ipfilter.Options{
    //block requests from China and Russia by IP
    BlockedCountries: []string{"CN", "RU"},
})
http.ListenAndServe(":8080", myProtectedHandler)
```

**Country-block stand-alone**

```go
f, err := ipfilter.New(ipfilter.Options{
    BlockedCountries: []string{"CN"},
})

f.Blocked("116.31.116.51") //=> true (CN)
f.Allowed("216.58.199.67") //=> true (US)
```

**Async allow LAN hosts middleware**

```go
f, err := ipfilter.New(ipfilter.Options{
    BlockByDefault: true,
})

go func() {
	time.Sleep(15 * time.Second)
	//react to admin change....
	f.AllowIP("192.168.0.23")
}()

h := http.Handler(...)
myProtectedHandler := f.Wrap(h)
http.ListenAndServe(":8080", myProtectedHandler)
```

**Allow your entire LAN only**

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
f.AllowCountry("AU")
f.Allowed("203.25.111.68") //=> true
```

**Check with `net.IP`**

```go
f.NetAllowed(net.IP{203,25,111,68}) //=> true
```

**Low-level single IP to country**

```go
f.IPToCountry("203.25.111.68") //=> "AU"
f.NetIPToCountry(net.IP{203,25,111,68}) //=> "AU"
```

**Advanced HTTP middleware**

Make your own with:

```go
func (m *myMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//use remote addr as it cant be spoofed
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	//show simple forbidden text
	if !m.IPFilter.Allowed(ip) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}
```

#### Issues

* Due to the nature of IP address allocation, determining location based of a
  single IP address is quite difficult (if you're not Google) and is therefore
  not very reliable. For this reason `BlockByDefault` is off by default.
* IP DB lookups take on the order of `5µs` to perform, though the initial load from disk
  into memory takes takes about `350ms` so be wary of excessive `ipfilter.New` use.

#### Todo

* Use a good algorithm to perform faster prefix matches
* Investigate reliability of other detectable attributes
* Add TOR/anonymizer filter options
* Add great-circle distance filter options (e.g. Allow 500KM radius from code/lat,lon)

#### Credits

* This site or product includes IP2Location LITE data available from http://www.ip2location.com

#### Change log

* v1.0.0 Use MaxMindDB IP data
* v1.1.0 Use IP2Location LITE IP data