// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package secp256k1

import "C"
import "unsafe"

// Callbacks for converting libsecp256k1 internal faults into
// recoverable Go panics.

//export vetSecp256k1GoPanicIllegal
func vetSecp256k1GoPanicIllegal(msg *C.char, data unsafe.Pointer) {
	panic("illegal argument: " + C.GoString(msg))
}

//export vetSecp256k1GoPanicError
func vetSecp256k1GoPanicError(msg *C.char, data unsafe.Pointer) {
	panic("internal error: " + C.GoString(msg))
}
