package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

/*
 * GoSRxProxy is a struct that represents a connection to the SRx server.
 * It contains the connection object, ASN, identifier, input and output buffers,
 * IP address, SKI, and callback functions for verification and synchronization.
 * Setup function:
 */

type GoSRxProxy struct {
	con              net.Conn
	conStatus        bool
	ASN              int
	identifier       string
	InputBuffer      []string
	OutputBuffer     []string
	IP               string
	SKI              string
	onVerify         func(string)
	onSync           func()
	UpdateIdentifier int
}

func NewGoSRxProxy(asn int, ip, ski string, onVerify func(string), onSync func()) (*GoSRxProxy, error) {
	p := &GoSRxProxy{
		ASN:              asn,
		IP:               ip,
		SKI:              ski,
		InputBuffer:      make([]string, 0),
		OutputBuffer:     make([]string, 0),
		onVerify:         onVerify,
		onSync:           onSync,
		UpdateIdentifier: 1,
	}

	if !p.connectToSRxServer(ip) {
		return nil, fmt.Errorf("failed to connect to SRx server")
	}

	return p, nil
}

func (p *GoSRxProxy) connectToSRxServer(ip string) bool {
	server := ip + ":17900"
	for {
		conn, err := net.Dial("tcp", server)
		if err == nil {
			p.con = conn
			p.conStatus = true
			fmt.Println("[i] Connected to SRx server:", server)
			p.sendHello()
			var wg sync.WaitGroup
			wg.Add(1)
			go p.ProxyBackgroundThread(&wg)
			return true
		}
	}
}

func (p *GoSRxProxy) sendHello() bool {
	fmt.Println("[i] Sending Hello message to SRx server...")
	hello := HelloMessage{
		PDU:              fmt.Sprintf("%02x", PDU_SRXPROXY_HELLO),
		Version:          "0003",
		reserved:         "00",
		zero:             "00000000",
		length:           "00000000",
		proxy_identifier: "00000001",
		ASN:              fmt.Sprintf("%08x", int64(p.ASN)),
		SKI:              p.SKI,
	}

	length := len(hello.PDU+hello.Version+hello.reserved+hello.zero+hello.length+hello.proxy_identifier+hello.ASN+hello.SKI) / 2
	hello.length = fmt.Sprintf("%08x", length)

	hexString := structToString(hello)
	bytes, _ := hex.DecodeString(hexString)
	_, err := p.con.Write(bytes)
	if err != nil {
		fmt.Println("[!] Failed to send Hello message:", err)
		return false
	}
	return true
}

func (proxy *GoSRxProxy) ProxyBackgroundThread(wg *sync.WaitGroup) bool {
	defer wg.Done()
	con := proxy.con
	response := make([]byte, 1024)
	for {
		n, err := con.Read(response)
		if err != nil {
			fmt.Println("Lost TCP connection.")
			fmt.Println(err)
			wg.Add(1)
			proxy.connectToSRxServer(proxy.IP)
			err = nil
			return false
		}
		serverResponse := hex.EncodeToString(response[:n])
		wg.Add(1)
		proxy.processInput(serverResponse, wg)
	}
	return true
}

/*
 * processInput is a function that processes the input from the SRx server.
 * It parses the PDU and calls the appropriate handler function based on the PDU type.
 * It also handles the case where the input is split into multiple packets.
 */

func (proxy *GoSRxProxy) processInput(st string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Println("[i] Processing input from SRx server:", st)
	packet_PDU := st[0:2]
	pdu, _ := strconv.ParseInt(packet_PDU, 16, 0)
	received_packet_length := int64(len(st) / 2)
	internal_packet_length, _ := strconv.ParseInt(st[16:24], 16, 0)
	to_process := st[0 : internal_packet_length*2]
	fmt.Println("[i] Received PDU:", packet_PDU, "Length:", received_packet_length, "Internal Length:", internal_packet_length)
	switch pdu {
	case PDU_SRXPROXY_HELLO_RESPONSE:
		fmt.Println("[i] Received PDU_SRXPROXY_HELLO_RESPONSE")
		proxy.handleHelloResponse(to_process)
	case PDU_SRXPROXY_SYNC_REQUEST:
		fmt.Println("[i] Received PDU_SRXPROXY_SYNC_REQUEST")
		proxy.sendSigtraGenerationRequest()
		//proxy.sendSigtraValidationRequest()
	case PDU_SRXPROXY_ERROR:
		fmt.Println("[!] Received PDU_SRXPROXY_ERROR")
	case PDU_SRXPROXY_VERI_NOTIFICATION:
		fmt.Println("[i] Received PDU_SRXPROXY_VERI_NOTIFICATION")
	case PDU_SRXPROXY_GOODBYE:
		fmt.Println("[i] Received PDU_SRXPROXY_GOODBYE")
	case PDU_SRXPROXY_SIGN_NOTIFICATION:
		fmt.Println("[i] Received PDU_SRXPROXY_SIGN_NOTIFICATION")
	case PDU_SRXPROXY_SIGTRA_SIGNATURE_RESPONSE:
		fmt.Println("[i] Received SigTra Signature Response")
		fmt.Println("[i] SigTra Signature Response: ", st)
	case PDU_SRXPROXY_SIGTRA_VALIDATION_RESPONSE:
		fmt.Println("[i] Received SigTra Validation Response")
		fmt.Println("[i] SigTra Validation Response: ", st)
	default:
		fmt.Println("[!] Unknown PDU:", packet_PDU)
	}

	if received_packet_length > internal_packet_length {
		fmt.Println("[i] Received packet length is greater than internal packet length")
		next_packet := st[internal_packet_length*2:]
		wg.Add(1)
		proxy.processInput(next_packet, wg)
	}
}

func (proxy *GoSRxProxy) handleHelloResponse(st string) {
	hmsg := HelloResponseMessage{
		PDU:              st[0:2],
		version:          st[2:6],
		reserved:         st[6:8],
		zero:             st[8:16],
		length:           st[16:24],
		proxy_identifier: st[24:32],
	}
	proxy.identifier = hmsg.proxy_identifier
}

/*
 * Update validation and signature gerneration
 */

func buildSigtraBlock() SigBlock {
	sigBlock := SigBlock{
		prefixLength: "0a",
		prefix:       "00000000",
		asPathLength: "00",
		asPath:       "00000000",
		pkiIDType:    "00",
		pkiID:        "00000000",
		timestamp:    "00000000",
		signature:    "00000000",
		OTCFlags:     "00",
		OTCField:     "00000000",
	}

	return sigBlock
}

func (proxy *GoSRxProxy) sendSigtraValidationRequest() {
	// SRx Basic Header
	hdr := SRxHeader{
		PDU:        fmt.Sprintf("%02x", PDU_SRXPROXY_SIGTRA_VALIDATION_REQUEST),
		Reserved16: "0000",
		Reserved8:  "00",
		Reserved32: "00000000",
		Length:     "00000000",
	}

	vr := SigTraValReq{
		signatureID: "12345678",
		blockCount:  "02",
		blocks:      "",
	}

	for i := 0; i < 2; i++ {
		// Create a new block
		block := buildSigtraBlock()
		block_string := structToString(block)
		vr.blocks += block_string
	}

	fmt.Println("Blocks: ", vr.blocks)
	hdr_length := len(hdr.PDU) + len(hdr.Reserved16) + len(hdr.Reserved8) + len(hdr.Reserved32) + len(hdr.Length)
	vr_length := len(vr.blockCount) + len(vr.blocks)
	total_length := hdr_length + vr_length
	total_length = total_length / 2
	hdr.Length = fmt.Sprintf("%08x", total_length)

	header, _ := hex.DecodeString(structToString(hdr))
	body, _ := hex.DecodeString(structToString(vr))

	bytes := make([]byte, len(header)+len(body))
	copy(bytes, header)
	copy(bytes[len(header):], body)
	fmt.Println("Bytes: ", bytes)
	fmt.Println("Length: ", len(bytes))
	_, err := proxy.con.Write(bytes)
	if err != nil {
		fmt.Println("[i] Sending SRXPROXY_SIGTRA__VALIDATION_REQUEST Failed: ", err)
	}
}

// This function sends a SigTraGenRequest to the SRx-Server
// It is used to request the generation of a signature for a given prefix
// and a given number of peers
func (proxy *GoSRxProxy) sendSigtraGenerationRequest() {
	// SRx Basic Header
	hdr := SRxHeader{
		PDU:        fmt.Sprintf("%02x", PDU_SRXPROXY_SIGTRA_GENERATION_REQUEST),
		Reserved16: "0000",
		Reserved8:  "00",
		Reserved32: "00000000",
		Length:     "00000000",
	}

	// Packet to request signature generation
	sr := SigTraGenRequest{
		SignatureID:    "00000000",
		PrefixLength:   "00",
		Prefix:         "00000000",
		ASPathLength:   "00",
		ASPath:         "00000000",
		Timestamp:      "0000000000000000",
		OTCField:       "00000000",
		PeerListLength: "00",
		PeerList:       "",
	}

	// DEMO GENERATION FOR ALL FIELDS:
	sr.SignatureID = "00034101"

	// fake prefix
	prefixLen := 16
	prefixAddr := net.ParseIP("15.64.5.0")

	tmp := hex.EncodeToString(prefixAddr)
	sr.Prefix = tmp[len(tmp)-8:]
	sr.PrefixLength = strconv.FormatInt(int64(prefixLen), 16)

	// fake as_path
	length := 2
	sr.ASPathLength = fmt.Sprintf("%02x", length)
	sr.ASPath = fmt.Sprintf("%08x", int64(65002)) + fmt.Sprintf("%08x", int64(65003))

	// fill in the rest of the AS path with 0
	for i := length; i < 16; i++ {
		sr.ASPath += "00000000"
	}
	fmt.Println("Lenght of ASPath: ", len(sr.ASPath)/8)

	// fake pkiid
	sr.PKIIDType = "01"
	sr.PKIID = "0000000000100000000200000000000000000100"

	// fake timestamp
	timestamp := uint32(time.Now().Unix())
	sr.Timestamp = fmt.Sprintf("%08x", timestamp)

	// fake OTCFlags
	sr.OTCFlags = "01"
	sr.OTCField = fmt.Sprintf("%08x", int64(65003))

	// fake peer list
	numberOfPeers := 2
	sr.PeerListLength = fmt.Sprintf("%02x", numberOfPeers)
	sr.PeerList = fmt.Sprintf("%08x", int64(65004)) + fmt.Sprintf("%08x", int64(65005))
	// fill in the rest of the AS path with 0
	for i := numberOfPeers; i < 16; i++ {
		sr.PeerList += "00000000"
	}

	hdr_length := len(hdr.PDU) + len(hdr.Reserved16) + len(hdr.Reserved8) + len(hdr.Reserved32) + len(hdr.Length)
	sr_length := len(sr.SignatureID) + len(sr.PrefixLength) + len(sr.Prefix) + len(sr.ASPathLength) + len(sr.ASPath) + len(sr.PKIIDType) + len(sr.PKIID) + len(sr.Timestamp) + len(sr.OTCFlags) + len(sr.OTCField) + len(sr.PeerListLength) + len(sr.PeerList)

	total_length := hdr_length + sr_length
	total_length = total_length / 2

	fmt.Println("Total Length calculated: ", total_length)
	fmt.Println("Header Length: ", hdr_length)
	fmt.Println("SigTraGenRequest Length: ", sr_length)
	hdr.Length = fmt.Sprintf("%08x", total_length)

	hexString_hdr := structToString(hdr)
	hexString_sr := structToString(sr)

	bytes_sr, _ := hex.DecodeString(hexString_sr)
	bytes_hdr, _ := hex.DecodeString(hexString_hdr)

	bytes := make([]byte, len(bytes_hdr)+len(bytes_sr))
	copy(bytes, bytes_hdr)
	copy(bytes[len(bytes_hdr):], bytes_sr)

	printHeader(hdr)
	printSigtraGenReq(sr)

	fmt.Println("Hex String: ", hexString_sr, " length; ", len(hexString_sr))
	fmt.Println("Hex String: ", hexString_hdr, " length; ", len(hexString_hdr))

	_, err := proxy.con.Write(bytes)
	if err != nil {
		fmt.Println("[i] Sending SRXPROXY_SIGTRA_GENERATION_REQUEST Failed: ", err)
	}
}

// Send a test verification request to the srx-server
// Create a Validation message for an incoming BGP UPDATE message
// inputs: BGP peer, the message and message data
func validate(proxy *GoSRxProxy) {
	id := 1

	// Create new message for each path
	vm := VerifyMessage{
		PDU:                  "03",
		OriginResultSource:   "01",
		PathResultSource:     "01",
		ASPAResultSource:     "01",
		reserved:             "01",
		ASPathType:           "02",
		ASRelationType:       "04",
		Length:               "00000044",
		OriginDefaultResult:  "03",
		PathDefaultResult:    "03",
		ASPADefaultResult:    "03",
		prefix_len:           "18",
		request_token:        fmt.Sprintf("%08X", id) + "03",
		prefix:               "00000000",
		origin_AS:            "0000fdec",
		length_path_val_data: "00000000",
		bgpsec_length:        "0000",
		afi:                  "0000",
		num_of_hops:          "0000",
		safi:                 "00",
		prefix_len_bgpsec:    "00",
		ip_pre_add_byte_a:    "00000000",
		ip_pre_add_byte_b:    "00000000",
		ip_pre_add_byte_c:    "00000000",
		ip_pre_add_byte_d:    "00000000",
		local_as:             "00000000",
		as_path_list:         "",
		bgpsec:               "",
	}

	// request flag for ASPA validation
	tmpFlag := 128

	// 1 ROA
	// 2 BGPsec
	// 4 Transitive
	// 8 ASPA
	tmpFlag += 4
	vm.Flags = fmt.Sprintf("%02X", tmpFlag)

	// fake as_path
	asList := [4]string{"65000", "65001", "65002", "65003"}
	for _, asn := range asList {
		hexValue := fmt.Sprintf("%08X", asn)
		vm.as_path_list += hexValue

	}

	// fake prefix
	prefixLen := 16
	prefixAddr := net.ParseIP("15.64.5.0")

	tmp := hex.EncodeToString(prefixAddr)
	vm.prefix = tmp[len(tmp)-8:]
	vm.prefix_len = strconv.FormatInt(int64(prefixLen), 16)
	vm.origin_AS = fmt.Sprintf("%08X", asList[len(asList)-1])

	vm.num_of_hops = fmt.Sprintf("%04X", len(asList))
	tmpInt := 4 * len(asList)
	vm.Length = fmt.Sprintf("%08X", 61+tmpInt)
	vm.length_path_val_data = fmt.Sprintf("%08X", tmpInt)
	vm.origin_AS = fmt.Sprintf("%08X", 65000)
	vm.local_as = fmt.Sprintf("%08X", 65002)

	request_as_string := structToString(vm)
	// printValReq(vm)
	validate_call(proxy, request_as_string)
}

func validate_call(proxy *GoSRxProxy, input string) {
	fmt.Println("Sending Validate Request")
	connection := proxy.con
	bytes2, err := hex.DecodeString(input)
	_, err = connection.Write(bytes2)
	if err != nil {
		fmt.Println(err)
	}

}
