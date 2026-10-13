//go:build windows

package hpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const custodyPrefix = "zrotext-candidate-native-"
const silent = 0x40

// CustodyError reports operation/status only, never private aliases or key data.
type CustodyError struct {
	Operation string
	Status    uint32
}

func (e *CustodyError) Error() string {
	return fmt.Sprintf("native protected custody %s: %08x", e.Operation, e.Status)
}

type ncryptAPI struct{ dll *syscall.DLL }

func nativeAPI() (*ncryptAPI, error) {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	var path [32768]uint16
	n, _, _ := kernel.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)))
	if n == 0 || n >= uintptr(len(path)) {
		return nil, ErrProtectedUnavailable
	}
	dll, e := syscall.LoadDLL(filepath.Join(syscall.UTF16ToString(path[:n]), "ncrypt.dll"))
	if e != nil {
		return nil, ErrProtectedUnavailable
	}
	return &ncryptAPI{dll}, nil
}

// Keep converted pointers alive through this syscall forwarding frame.
//
//go:uintptrescapes
func (a *ncryptAPI) call(name string, args ...uintptr) error {
	p, e := a.dll.FindProc(name)
	if e != nil {
		return ErrProtectedUnavailable
	}
	code, _, _ := p.Call(args...)
	if uint32(code) != 0 {
		return &CustodyError{name, uint32(code)}
	}
	return nil
}
func wide(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic("internal wide value")
	}
	return p
}
func (a *ncryptAPI) property(h uintptr, name string) (uint32, error) {
	var value, size uint32
	e := a.call("NCryptGetProperty", h, uintptr(unsafe.Pointer(wide(name))), uintptr(unsafe.Pointer(&value)), 4, uintptr(unsafe.Pointer(&size)), silent)
	if e != nil {
		return 0, e
	}
	if size != 4 {
		return 0, ErrProtectedUnavailable
	}
	return value, nil
}

// HardwareRecipient owns only handles it opens or creates in the PCP namespace.
// Its unexported qualification cannot be supplied as a caller boolean.
// HardwareRecipient owns native handles and must not be copied after first use.
// Use pointers and Close to release handles; Delete removes only its owned key.
type HardwareRecipient struct {
	mu                sync.Mutex
	api               *ncryptAPI
	provider, key     uintptr
	name              string
	qualified, closed bool
}

func startHardware() (*HardwareRecipient, error) {
	a, e := nativeAPI()
	if e != nil {
		return nil, e
	}
	r := &HardwareRecipient{api: a}
	e = a.call("NCryptOpenStorageProvider", uintptr(unsafe.Pointer(&r.provider)), uintptr(unsafe.Pointer(wide("Microsoft Platform Crypto Provider"))), 0)
	if e == nil {
		var impl uint32
		impl, e = a.property(r.provider, "Impl Type")
		if e == nil && impl&1 == 0 {
			e = ErrProtectedUnavailable
		}
	}
	if e == nil {
		e = a.call("NCryptIsAlgSupported", r.provider, uintptr(unsafe.Pointer(wide("ECDH_P256"))), 0)
	}
	if e != nil {
		r.Close()
		return nil, e
	}
	return r, nil
}

// ProbeHardware checks capability without creating keys. It is not qualification.
func ProbeHardware() error {
	r, e := startHardware()
	if e == nil {
		r.Close()
	}
	return e
}

// CreateHardware requires a durable private receipt callback before creation.
// No overwrite/import/provisioning policy or software provider is attempted.
func CreateHardware(recordPending func(string) error) (*HardwareRecipient, error) {
	if recordPending == nil {
		return nil, ErrShape
	}
	r, e := startHardware()
	if e != nil {
		return nil, e
	}
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		r.Close()
		return nil, e
	}
	r.name = custodyPrefix + hex.EncodeToString(random[:])
	if e = recordPending(r.name); e != nil {
		r.Close()
		return nil, e
	}
	e = r.api.call("NCryptCreatePersistedKey", r.provider, uintptr(unsafe.Pointer(&r.key)), uintptr(unsafe.Pointer(wide("ECDH_P256"))), uintptr(unsafe.Pointer(wide(r.name))), 0, silent)
	created := e == nil
	if e == nil {
		var policy uint32
		e = r.api.call("NCryptSetProperty", r.key, uintptr(unsafe.Pointer(wide("Export Policy"))), uintptr(unsafe.Pointer(&policy)), 4, 0)
	}
	if e == nil {
		e = r.api.call("NCryptFinalizeKey", r.key, silent)
	}
	if e == nil {
		e = r.qualify()
	}
	if e != nil {
		if created && r.key != 0 {
			if cleanup := r.api.call("NCryptDeleteKey", r.key, 0); cleanup != nil {
				r.Close()
				return nil, cleanup
			}
			r.key = 0
		}
		r.Close()
		return nil, e
	}
	r.qualified = true
	return r, nil
}
func OpenHardware(name string, expected []byte) (*HardwareRecipient, error) {
	suffix := strings.TrimPrefix(name, custodyPrefix)
	decoded, e := hex.DecodeString(suffix)
	if e != nil || len(decoded) != 16 || name != custodyPrefix+hex.EncodeToString(decoded) || len(expected) != 65 {
		return nil, ErrShape
	}
	if _, e = ecdh.P256().NewPublicKey(expected); e != nil {
		return nil, ErrShape
	}
	r, e := startHardware()
	if e != nil {
		return nil, e
	}
	r.name = name
	e = r.api.call("NCryptOpenKey", r.provider, uintptr(unsafe.Pointer(&r.key)), uintptr(unsafe.Pointer(wide(name))), 0, silent)
	if e == nil {
		e = r.qualify()
	}
	if e == nil {
		var public []byte
		public, e = r.public()
		if e == nil && !bytes.Equal(public, expected) {
			e = ErrAuthentication
		}
	}
	if e != nil {
		r.Close()
		return nil, e
	}
	r.qualified = true
	return r, nil
}
func (r *HardwareRecipient) qualify() error {
	policy, e := r.api.property(r.key, "Export Policy")
	if e != nil {
		return e
	}
	if policy != 0 {
		return ErrProtectedUnavailable
	}
	var size uint32
	e = r.api.call("NCryptExportKey", r.key, 0, uintptr(unsafe.Pointer(wide("ECCPRIVATEBLOB"))), 0, 0, 0, uintptr(unsafe.Pointer(&size)), silent)
	status, ok := e.(*CustodyError)
	if !ok || (status.Status != 0x80090010 && status.Status != 0x8009000a) {
		return ErrProtectedUnavailable
	}
	public, e := r.public()
	if e != nil {
		return e
	}
	peer, e := ecdh.P256().GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	pk, e := ecdh.P256().NewPublicKey(public)
	if e != nil {
		return e
	}
	expected, e := peer.ECDH(pk)
	if e != nil {
		return e
	}
	defer clear(expected)
	actual, e := r.exchange(peer.PublicKey().Bytes())
	if e != nil {
		return e
	}
	defer clear(actual)
	if !bytes.Equal(expected, actual) {
		return ErrAuthentication
	}
	return nil
}
func (r *HardwareRecipient) public() ([]byte, error) {
	if r.closed || r.key == 0 {
		return nil, ErrProtectedUnavailable
	}
	var blob [72]byte
	var size uint32
	e := r.api.call("NCryptExportKey", r.key, 0, uintptr(unsafe.Pointer(wide("ECCPUBLICBLOB"))), 0, uintptr(unsafe.Pointer(&blob[0])), 72, uintptr(unsafe.Pointer(&size)), silent)
	if e != nil {
		return nil, e
	}
	if size != 72 || binary.LittleEndian.Uint32(blob[:4]) != 0x314b4345 || binary.LittleEndian.Uint32(blob[4:8]) != 32 {
		return nil, ErrProtectedUnavailable
	}
	public := append([]byte{4}, blob[8:]...)
	if _, e = ecdh.P256().NewPublicKey(public); e != nil {
		return nil, ErrShape
	}
	return public, nil
}
func (r *HardwareRecipient) PublicPoint() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.qualified {
		return nil, ErrProtectedUnavailable
	}
	return r.public()
}
func (r *HardwareRecipient) Alias() string { r.mu.Lock(); defer r.mu.Unlock(); return r.name }
func (r *HardwareRecipient) exchange(enc []byte) ([]byte, error) {
	if r.closed || r.key == 0 {
		return nil, ErrProtectedUnavailable
	}
	if len(enc) != 65 || enc[0] != 4 {
		return nil, ErrShape
	}
	if _, e := ecdh.P256().NewPublicKey(enc); e != nil {
		return nil, ErrShape
	}
	var peer, agreement uintptr
	var raw [32]byte
	var size uint32
	blob := make([]byte, 72)
	binary.LittleEndian.PutUint32(blob, 0x314b4345)
	binary.LittleEndian.PutUint32(blob[4:], 32)
	copy(blob[8:], enc[1:])
	defer func() {
		clear(raw[:])
		if agreement != 0 {
			_ = r.api.call("NCryptFreeObject", agreement)
		}
		if peer != 0 {
			_ = r.api.call("NCryptFreeObject", peer)
		}
	}()
	e := r.api.call("NCryptImportKey", r.provider, 0, uintptr(unsafe.Pointer(wide("ECCPUBLICBLOB"))), 0, uintptr(unsafe.Pointer(&peer)), uintptr(unsafe.Pointer(&blob[0])), 72, silent)
	if e == nil {
		e = r.api.call("NCryptSecretAgreement", r.key, peer, uintptr(unsafe.Pointer(&agreement)), silent)
	}
	if e == nil {
		e = r.api.call("NCryptDeriveKey", agreement, uintptr(unsafe.Pointer(wide("TRUNCATE"))), 0, uintptr(unsafe.Pointer(&raw[0])), 32, uintptr(unsafe.Pointer(&size)), 0)
	}
	if e != nil {
		return nil, e
	}
	if size != 32 {
		return nil, ErrProtectedUnavailable
	}
	out := make([]byte, 32)
	for i := range out {
		out[i] = raw[31-i]
	}
	return out, nil
}
func (r *HardwareRecipient) OpenCEK(public, enc, info, aad, ct []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.qualified || r.closed || len(info) > 36864 || len(aad) > 36864 || len(ct) != 48 {
		return nil, ErrProtectedUnavailable
	}
	actual, e := r.public()
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(actual, public) {
		return nil, ErrAuthentication
	}
	dh, e := r.exchange(enc)
	if e != nil {
		return nil, e
	}
	defer clear(dh)
	return openSharedCEK(dh, public, enc, info, aad, ct)
}
func (r *HardwareRecipient) close() {
	if r.api == nil {
		r.closed = true
		return
	}
	if !r.closed {
		r.qualified = false
		if r.key != 0 {
			_ = r.api.call("NCryptFreeObject", r.key)
		}
		if r.provider != 0 {
			_ = r.api.call("NCryptFreeObject", r.provider)
		}
		r.closed = true
		_ = r.api.dll.Release()
	}
}
func (r *HardwareRecipient) Close() { r.mu.Lock(); defer r.mu.Unlock(); r.close() }

// Delete removes only this exact opened/created handle; no prefix enumeration.
func (r *HardwareRecipient) Delete() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.qualified || r.closed {
		return ErrProtectedUnavailable
	}
	if e := r.api.call("NCryptDeleteKey", r.key, 0); e != nil {
		return e
	}
	r.key = 0
	r.close()
	return nil
}
func OpenHardwareArchive02(input []byte, historical, current *Manifest, custody *HardwareRecipient, context ArchiveContext) (string, error) {
	if custody == nil {
		return "", ErrProtectedUnavailable
	}
	return openArchive02(input, historical, current, context, custody.OpenCEK)
}
