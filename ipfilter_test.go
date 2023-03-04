package ipfilter_test

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jpillora/ipfilter"
	"github.com/stretchr/testify/assert"
)

const (
	egUS = "52.92.180.128"
	egAU = "49.189.50.1"
	egCN = "116.31.116.51"
)

func TestSingleIP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be allowed")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestSingleIPNewNoDB(t *testing.T) {
	f := ipfilter.NewNoDB(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockByDefault: true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be allowed")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestSingleIPBlocked(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		BlockedIPs: []string{"222.25.118.1"},
	})
	assert.False(t, f.Allowed("222.25.118.1"), "[1] should be blocked")
	assert.True(t, f.Blocked("222.25.118.1"), "[2] should be allowed")
	assert.False(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be blocked")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 1}), "[4] should be allowed")
	assert.True(t, f.Allowed("222.25.118.2"), "[5] should be allowed")
	f.ToggleDefault(false)
	assert.False(t, f.Allowed("222.25.118.2"), "[6] should be blocked")

}

func TestSingleIPNewLazy(t *testing.T) {
	f := ipfilter.NewLazy(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be allowed")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestSubnetIP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"10.0.0.0/16"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("10.0.0.1"), "[1] should be allowed")
	assert.True(t, f.Allowed("10.0.42.1"), "[2] should be allowed")
	assert.True(t, f.Blocked("10.42.0.1"), "[3] should be blocked")
}

func TestManualCountryCode(t *testing.T) {
	assert.Equal(t, ipfilter.IPToCountry(egAU), "AU")
	assert.Equal(t, ipfilter.IPToCountry(egUS), "US")
}

func TestCountryCodeWhiteList(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedCountries: []string{"AU"},
		BlockByDefault:   true,
	})
	f.IPToCountry("AU")
	assert.True(t, f.Allowed(egAU), "[1] should be allowed")
	assert.True(t, f.Blocked(egUS), "[2] should be blocked")
	assert.True(t, f.IPToCountry(egUS) == "US", "[3] should equal the US")
	assert.True(t, f.NetIPToCountry(net.ParseIP(egAU)) == "AU", "[4] should equal the AU")
}

func TestCountryCodeBlackList(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		BlockedCountries: []string{"RU", "CN"},
	})
	assert.True(t, f.Allowed(egAU), "[1] AU should be allowed")
	assert.True(t, f.Allowed(egUS), "[2] US should be allowed")
	assert.True(t, f.Blocked(egCN), "[3] CN should be blocked")
}

func TestDynamicList(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{})
	assert.True(t, f.Allowed(egCN), "[1] CN should be allowed")
	f.BlockCountry("CN")
	assert.True(t, f.Blocked(egCN), "[2] CN should be blocked")
}

func TestServeHTTP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		TrustProxy:     false,
	})
	router := mux.NewRouter()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/service/", nil)
	req.RemoteAddr = "222.25.118.1:8080"
	w := httptest.NewRecorder()
	f.Wrap(router).ServeHTTP(w, req)
	resp := w.Result()
	assert.True(t, resp.StatusCode != http.StatusForbidden, "[1] should be allowed")
}

func TestServeHTTPForbidden(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"127.0.0.1"},
		BlockByDefault: true,
		TrustProxy:     false,
	})
	router := mux.NewRouter()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/service/", nil)
	req.RemoteAddr = "222.25.118.1:8080"
	w := httptest.NewRecorder()
	f.Wrap(router).ServeHTTP(w, req)
	resp := w.Result()
	assert.True(t, resp.StatusCode == http.StatusForbidden, "[1] should not be allowed")
}

func TestServeHTTPProxy(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		TrustProxy:     true,
	})
	router := mux.NewRouter()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/service/", nil)
	req.RemoteAddr = "125.0.0.1:8080"
	req.Header.Add("X-Real-Ip", "222.25.118.1")
	w := httptest.NewRecorder()
	f.Wrap(router).ServeHTTP(w, req)
	resp := w.Result()
	assert.True(t, resp.StatusCode != http.StatusForbidden, "[1] should be allowed")
}

func TestServeHTTPLocalhost(t *testing.T) {
	router := mux.NewRouter()
	handler := ipfilter.Wrap(router, ipfilter.Options{
		AllowedIPs:     []string{"127.0.0.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
	})
	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/service/", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	resp := w.Result()
	assert.True(t, resp.StatusCode != http.StatusForbidden, "[1] should be allowed")
}

func TestServeHTTPProxyLocal(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.2"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		TrustProxy:     true,
	})
	router := mux.NewRouter()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/service/", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	req.Header.Add("X-Forwarded-For", "222.25.118.2")
	w := httptest.NewRecorder()
	f.Wrap(router).ServeHTTP(w, req)
	resp := w.Result()
	assert.True(t, resp.StatusCode != http.StatusForbidden, "[1] should be allowed")
}

// gRPC testing support
var (
	unaryInfo = &grpc.UnaryServerInfo{
		FullMethod: "TestService.UnaryMethod",
	}
	streamInfo = &grpc.StreamServerInfo{
		FullMethod:     "TestService.StreamMethod",
		IsServerStream: true,
	}
)

type testServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss *testServerStream) Context() context.Context {
	return ss.ctx
}

func TestUnaryServerInterceptor(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"127.0.0.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	unaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "output", nil
	}
	ctx := context.Background()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("failed to parse TCP Addr: %v", err)
	}
	pd := &peer.Peer{Addr: addr}
	ctx = peer.NewContext(ctx, pd)
	_, err = f.IPFilterUnaryServerInterceptor()(ctx, "xyz", unaryInfo, unaryHandler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnaryServerInterceptorBlocked(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	unaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "output", nil
	}
	ctx := context.Background()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("failed to parse TCP Addr: %v", err)
	}
	pd := &peer.Peer{Addr: addr}
	ctx = peer.NewContext(ctx, pd)
	_, err = f.IPFilterUnaryServerInterceptor()(ctx, "xyz", unaryInfo, unaryHandler)
	if err == nil {
		t.Fatalf("unexpected. request should've failed")
	}
}

func TestUnaryServerInterceptorNoIP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	unaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "output", nil
	}
	ctx := context.Background()
	_, err := f.IPFilterUnaryServerInterceptor()(ctx, "xyz", unaryInfo, unaryHandler)
	if err == nil {
		t.Fatalf("unexpected. request should've failed")
	}
}

func TestStreamServerInterceptor(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"127.0.0.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	streamHandler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}
	ctx := context.Background()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("failed to parse TCP Addr: %v", err)
	}
	pd := &peer.Peer{Addr: addr}
	ctx = peer.NewContext(ctx, pd)
	testService := struct{}{}
	testStream := &testServerStream{ctx: ctx}
	err = f.IPFilterStreamServerInterceptor()(testService, testStream, streamInfo, streamHandler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStreamServerInterceptorBlocked(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	streamHandler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}
	ctx := context.Background()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("failed to parse TCP Addr: %v", err)
	}
	pd := &peer.Peer{Addr: addr}
	ctx = peer.NewContext(ctx, pd)
	testService := struct{}{}
	testStream := &testServerStream{ctx: ctx}
	err = f.IPFilterStreamServerInterceptor()(testService, testStream, streamInfo, streamHandler)
	if err == nil {
		t.Fatalf("unexpected. request should've failed")
	}
}

func TestStreamServerInterceptorNoIP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	streamHandler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}
	ctx := context.Background()
	testService := struct{}{}
	testStream := &testServerStream{ctx: ctx}
	err := f.IPFilterStreamServerInterceptor()(testService, testStream, streamInfo, streamHandler)
	if err == nil {
		t.Fatalf("unexpected. request should've failed")
	}
}

func TestUnaryServerInterceptorProxy(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		TrustProxy:     true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	unaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "output", nil
	}
	ctx := context.Background()
	md := metadata.Pairs("x-real-ip", "222.25.118.1")
	ctx = metadata.NewIncomingContext(ctx, md)
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("failed to parse TCP Addr: %v", err)
	}
	pd := &peer.Peer{Addr: addr}
	ctx = peer.NewContext(ctx, pd)
	_, err = f.IPFilterUnaryServerInterceptor()(ctx, "xyz", unaryInfo, unaryHandler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStreamServerInterceptorProxy(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		TrustProxy:     true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	streamHandler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}
	ctx := context.Background()
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("failed to parse TCP Addr: %v", err)
	}
	md := metadata.Pairs("x-forward-ip", "222.25.118.1")
	ctx = metadata.NewIncomingContext(ctx, md)
	pd := &peer.Peer{Addr: addr}
	ctx = peer.NewContext(ctx, pd)
	testService := struct{}{}
	testStream := &testServerStream{ctx: ctx}
	err = f.IPFilterStreamServerInterceptor()(testService, testStream, streamInfo, streamHandler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnaryServerInterceptorProxyBlocked(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"127.0.0.1"},
		BlockedIPs:     []string{"222.25.118.2"},
		BlockByDefault: true,
		TrustProxy:     true,
		Logger:         log.New(os.Stderr, "", 0),
	})
	unaryHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "output", nil
	}
	ctx := context.Background()
	md := metadata.Pairs("x-forward-for", "222.25.118.1")
	ctx = metadata.NewIncomingContext(ctx, md)
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("failed to parse TCP Addr: %v", err)
	}
	pd := &peer.Peer{Addr: addr}
	ctx = peer.NewContext(ctx, pd)
	_, err = f.IPFilterUnaryServerInterceptor()(ctx, "xyz", unaryInfo, unaryHandler)
	if err == nil {
		t.Fatalf("unexpected. request should've failed")
	}
}
