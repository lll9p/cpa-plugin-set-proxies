package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct {
    uint32_t abi_version;
    void* host_ctx;
    cliproxy_host_call_fn call;
    cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct {
    uint32_t abi_version;
    cliproxy_plugin_call_fn call;
    cliproxy_plugin_free_fn free_buffer;
    cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static cliproxy_host_api stored_host;
static void store_host(const cliproxy_host_api* host) { stored_host = *host; }
static int call_host(const char* method, const uint8_t* request, size_t len, cliproxy_buffer* response) {
    return stored_host.call(stored_host.host_ctx, method, request, len, response);
}
static void free_host(cliproxy_buffer response) {
    if (response.ptr != NULL) stored_host.free_buffer(response.ptr, response.len);
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"unsafe"

	"cpa-plugin-set-proxies/internal/plugin"
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, api *C.cliproxy_plugin_api) C.int {
	if host == nil || api == nil || host.abi_version != 1 || host.call == nil || host.free_buffer == nil {
		return 1
	}
	C.store_host(host)
	plugin.SetHostCall(callHost)
	api.abi_version = 1
	api.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	api.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	api.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

func callHost(method string, payload any) (json.RawMessage, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("encode host request")
	}
	name := C.CString(method)
	defer C.free(unsafe.Pointer(name))
	request := C.CBytes(raw)
	defer C.free(request)
	var response C.cliproxy_buffer
	code := C.call_host(name, (*C.uint8_t)(request), C.size_t(len(raw)), &response)
	defer C.free_host(response)
	if code != 0 || response.ptr == nil || response.len > 64<<20 {
		return nil, errors.New("host callback failed")
	}
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(C.GoBytes(response.ptr, C.int(response.len)), &envelope) != nil || !envelope.OK {
		return nil, errors.New("invalid host callback response")
	}
	return envelope.Result, nil
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, length C.size_t, response *C.cliproxy_buffer) C.int {
	if response == nil {
		return 1
	}
	response.ptr, response.len = nil, 0
	if method == nil || length > 64<<20 || (length != 0 && request == nil) {
		return 1
	}
	raw, err := plugin.HandleMethod(C.GoString(method), C.GoBytes(unsafe.Pointer(request), C.int(length)))
	if err != nil {
		raw = []byte(`{"ok":false,"error":{"code":"plugin_error","message":"Plugin request failed"}}`)
	}
	if len(raw) != 0 {
		response.ptr = C.CBytes(raw)
		response.len = C.size_t(len(raw))
	}
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	C.free(ptr)
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() { plugin.Quiesce() }
