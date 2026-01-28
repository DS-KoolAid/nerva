// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pluginutils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
)

func Send(conn net.Conn, data []byte, timeout time.Duration) error {
	// Try to set write deadline. On Linux, the kernel's SCTP implementation
	// doesn't support SO_SNDTIMEO (send timeout), which causes SetWriteDeadline
	// to return "operation not supported" error. This is a known kernel limitation,
	// not a bug in our code or the Go SCTP library.
	//
	// We log the error but proceed with the write operation anyway. The write will
	// still work correctly; it just won't have kernel-level timeout protection.
	// Most SCTP operations complete quickly, and application-level timeouts provide
	// adequate protection against hangs.
	//
	// See: https://man7.org/linux/man-pages/man7/sctp.7.html
	// SO_RCVTIMEO (read timeout) is supported, but SO_SNDTIMEO is not.
	err := conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		// Log the warning but don't fail the operation
		log.Printf("Warning: failed to set write deadline (may be SCTP): %v", err)
	}
	length, err := conn.Write(data)
	if err != nil {
		return &WriteError{WrappedError: err}
	}
	if length < len(data) {
		return &WriteError{
			WrappedError: fmt.Errorf(
				"Failed to write all bytes (%d bytes written, %d bytes expected)",
				length,
				len(data),
			),
		}
	}
	return nil
}

func Recv(conn net.Conn, timeout time.Duration) ([]byte, error) {
	response := make([]byte, 4096)
	// Try to set read deadline. On Linux, the kernel's SCTP implementation
	// may not fully support SO_RCVTIMEO (read timeout) via the Go SCTP library,
	// which can cause SetReadDeadline to return "operation not supported" error.
	//
	// We log the error but proceed with the read operation anyway. The read will
	// still work correctly; it just won't have kernel-level timeout protection.
	//
	// See: https://man7.org/linux/man-pages/man7/sctp.7.html
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		log.Printf("Warning: failed to set read deadline (may be SCTP): %v", err)
	}
	length, err := conn.Read(response)
	if err != nil {
		var netErr net.Error
		if (errors.As(err, &netErr) && netErr.Timeout()) ||
			errors.Is(err, syscall.ECONNREFUSED) { // timeout error or connection refused
			return []byte{}, nil
		}
		return response[:length], &ReadError{
			Info:         hex.EncodeToString(response[:length]),
			WrappedError: err,
		}
	}
	return response[:length], nil
}

func SendRecv(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	err := Send(conn, data, timeout)
	if err != nil {
		return []byte{}, err
	}
	return Recv(conn, timeout)
}
