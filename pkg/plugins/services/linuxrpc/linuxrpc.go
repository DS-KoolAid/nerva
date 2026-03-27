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

package linuxrpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
The RPC service takes two main operations we care about: call and dump.

Call verify that the service is running and will return the version of rpc running
Dump dumps a list of all registered rpc endpoints in a list, with each entry having the following structure:

RPCB
Program: Portmap (100000)
Version: 4
Network Id: tcp6
	length: 4
	contents: tcp6
Universal Address: ::.0.111
	length: 8
	contents: ::.0.111
Owner of this Service: superuser
	length: 9
	contents: superuser
	fill bytes: opaque data
Value follows: Yes

Bytes are padded to 4 bytes
*/

type RPCPlugin struct{}

const RPC = "RPC"

func init() {
	plugins.RegisterPlugin(&RPCPlugin{})
}

func (p *RPCPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	rpcService := plugins.ServiceRPC{}

	check, err := DetectRPCInfoService(conn, &rpcService, timeout)
	if check && err != nil {
		return nil, nil
	}
	if err == nil {
		return plugins.CreateServiceFrom(target, rpcService, false, "", plugins.TCP), nil
	}
	return nil, err
}

func DetectRPCInfoService(conn net.Conn, lookupResponse *plugins.ServiceRPC, timeout time.Duration) (bool, error) {
	callPacket := []byte{
		0x80, 0x00, 0x00, 0x28, 0x72, 0xfe, 0x1d, 0x13,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x86, 0xa0, 0x00, 0x01, 0x97, 0x7c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	callResponseSignature := []byte{
		0x72, 0xfe, 0x1d, 0x13, 0x00, 0x00, 0x00, 0x01,
	}

	dumpPacket := []byte{
		0x80, 0x00, 0x00, 0x28, 0x3d, 0xd3, 0x77, 0x29,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, callPacket, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	if !bytes.Contains(response, callResponseSignature) {
		return true, &utils.InvalidResponseError{Service: RPC}
	}

	response, err = utils.SendRecv(conn, dumpPacket, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	return true, parseRPCInfo(response, lookupResponse)
}

// readUint32 safely reads a big-endian uint32 from the front of buf.
// Returns the value, the remaining buffer, and false if buf is too short.
func readUint32(buf []byte) (uint32, []byte, bool) {
	if len(buf) < 4 {
		return 0, buf, false
	}
	v := binary.BigEndian.Uint32(buf[0:4])
	return v, buf[4:], true
}

// readPaddedString reads a 4-byte length prefix, then that many bytes
// (padded to a 4-byte boundary) from buf. Returns the string, the
// remaining buffer, and false if the data is truncated or invalid.
func readPaddedString(buf []byte) (string, []byte, bool) {
	if len(buf) < 4 {
		return "", buf, false
	}
	rawLen := int(binary.BigEndian.Uint32(buf[0:4]))
	buf = buf[4:]
	if rawLen < 0 || rawLen > len(buf) {
		return "", buf, false
	}
	s := string(buf[0:rawLen])
	// advance past the 4-byte-padded length
	padded := rawLen
	for padded%4 != 0 {
		padded++
	}
	if padded > len(buf) {
		return "", buf, false
	}
	return s, buf[padded:], true
}

func parseRPCInfo(response []byte, lookupResponse *plugins.ServiceRPC) error {
	if len(response) < 0x20 {
		return fmt.Errorf("invalid rpc length")
	}
	response = response[0x20:]

	valueFollows := 1
	for valueFollows == 1 {
		tmp := plugins.RPCB{}

		var v uint32
		var s string
		var ok bool

		// Program (4 bytes) + Version (4 bytes) = need at least 8
		v, response, ok = readUint32(response)
		if !ok {
			return nil
		}
		tmp.Program = int(v)

		v, response, ok = readUint32(response)
		if !ok {
			return nil
		}
		tmp.Version = int(v)

		s, response, ok = readPaddedString(response)
		if !ok {
			return nil
		}
		tmp.Protocol = s

		s, response, ok = readPaddedString(response)
		if !ok {
			return nil
		}
		tmp.Address = s

		s, response, ok = readPaddedString(response)
		if !ok {
			return nil
		}
		tmp.Owner = s

		v, response, ok = readUint32(response)
		if !ok {
			return nil
		}
		valueFollows = int(v)

		lookupResponse.Entries = append(lookupResponse.Entries, tmp)
	}

	return nil
}

func (p *RPCPlugin) PortPriority(i uint16) bool {
	return i == 111
}

func (p *RPCPlugin) Name() string {
	return RPC
}
func (p *RPCPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *RPCPlugin) Priority() int {
	return 300
}
