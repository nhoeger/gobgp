package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type GoSRxProxy struct {
	//client       *RPKIManager
	con                  net.Conn
	conStatus            bool
	ASN                  int
	InputBuffer          []string
	OutputBuffer         []string
	IP                   string
	VerifyNotifyCallback func(*VerifyNotify)
	SyncNotifyCallback   func()
}

// send validation call to SRx-Server
func validate_call(proxy *GoSRxProxy, input string) {
	connection := proxy.con
	bytes2, err := hex.DecodeString(input)
	_, err = connection.Write(bytes2)
	if err != nil {
		log.Fatal(err)
	}

}

// Sends Hello message to SRx-Server
// ASN becomes the identifier of the proxy
func sendHello(proxy GoSRxProxy, SKI string) {
	// Convert the ASN to a hex value
	converted_asn := fmt.Sprintf("%08x", int64(proxy.ASN))

	// Prepare the hello message
	hm := HelloMessage{
		PDU:              HelloPDU,
		Version:          "0003",
		reserved:         "00",
		zero:             "00000000",
		length:           "00000000",
		proxy_identifier: converted_asn,
		ASN:              converted_asn,
		SKI:              SKI,
	}

	// Get the length in bytes
	length := len(hm.PDU) + len(hm.Version) + len(hm.reserved) + len(hm.zero) + len(hm.length) + len(hm.proxy_identifier) + len(hm.ASN) + len(hm.SKI)
	length = length / 2
	hm.length = fmt.Sprintf("%08x", length)

	// Convert HelloMessage to hex and send it
	hexString := structToString(hm)
	bytes, _ := hex.DecodeString(hexString)
	_, err := proxy.con.Write(bytes)
	if err != nil {
		log.Fatal("[!] Sending Hello Failed: ", err)
	}
}

// New Proxy instance
func createSRxProxy(AS int, ip string, SKI string, VNC func(*VerifyNotify), SC func()) GoSRxProxy {
	log.Info("[i] Creating Proxy")
	var wg sync.WaitGroup
	wg.Add(1)
	pr := GoSRxProxy{
		ASN:                  AS,
		IP:                   ip,
		VerifyNotifyCallback: VNC,
		SyncNotifyCallback:   SC,
	}
	pr.connectToSrxServer(ip)
	sendHello(pr, SKI)
	return pr
}

// Establish a TCP connection with the SRx-Server
// If no IP is provided, the proxy tries to reach localhost:17900
func (proxy *GoSRxProxy) connectToSrxServer(ip string) {
	connectionCounter := 1
	server := fmt.Sprintf("%s:17900", ip)
	log.Debug("Trying to connect to SRx-Server.")
	log.Debug("SRxServer Address: ", ip)
	if len(ip) != 0 {
		server = ip + ":17900"
	}
	var conn net.Conn
	var err error
	for connectionCounter < 4 {
		connectionCounter += 1
		conn, err = net.Dial("tcp", server)
		if err != nil {
			log.Debug("[!] Connection to Server failed! Trying to connect...")
			time.Sleep(2 * time.Second)
		} else {
			log.Info("[i] Connection to SRx-Server established")
			proxy.con = conn
			proxy.conStatus = true
			break
		}
	}
	if err != nil {
		log.Fatal(fmt.Sprintf("Connection Failed. Please ensure that the SRx-Server at %s is running.", ip))
	}
}

func (proxy *GoSRxProxy) proxyBackgroundThread(wg *sync.WaitGroup) {
	defer wg.Done()
	con := proxy.con
	response := make([]byte, 1024)
	for {
		n, err := con.Read(response)
		if err != nil {
			log.Info("Lost TCP connection.")
			log.Info(err)
			wg.Add(1)
			proxy.connectToSrxServer(proxy.IP)
			err = nil
			return
		}
		serverResponse := hex.EncodeToString(response[:n])
		wg.Add(1)
		proxy.processInput(serverResponse, wg)
		// log.Debug("Server Input: ", serverResponse)
	}
}

// process messages from the SRx-Server according to their PDU field
func (proxy *GoSRxProxy) processInput(st string, wg *sync.WaitGroup) {
	defer wg.Done()
	PDU := st[:2]
	log.Info("------> Received PDU: ", PDU)
	if PDU == HelloRepsonsePDU {
		log.Debug("Received Hello Response")
		if len(st) > 32 {
			log.Debug("More than just the Hello message")
			wg.Add(1)
			proxy.processInput(st[32:], wg)
		}
	}
	if PDU == SyncMessagePDU {
		log.Debug("Received Sync Request")
		proxy.SyncNotifyCallback()
		if len(st) > 24 {
			wg.Add(1)
			proxy.processInput(st[24:], wg)
		}
	}
	if PDU == VerifyNotifyPDU {
		log.Debug("Processing Validation Input")
		if len(st) > 40 {
			proxy.verifyNotifyCallback(st[:40])
			wg.Add(1)
			proxy.processInput(st[40:], wg)
		} else {
			proxy.verifyNotifyCallback(st)
		}
	}
	if PDU == TransitivePDU {
		log.Info("Received Transitive Message")
	}
	fmt.Println("Processing Input: ", st)
}

// Convert data structures to string before sending
func structToString(data interface{}) string {
	value := reflect.ValueOf(data)
	numFields := value.NumField()
	returnString := ""
	for i := 0; i < numFields; i++ {
		field := value.Field(i)
		returnString += field.String()
	}
	return returnString
}

// Convert the input string into VerifyNotify
// Parse VerifyNotify to RPKIManager
func (proxy *GoSRxProxy) verifyNotifyCallback(input string) {
	vn := VerifyNotify{
		PDU:              input[:2],
		ResultType:       input[2:4],
		OriginResult:     input[4:6],
		PathResult:       input[6:8],
		ASPAResult:       input[8:10],
		ASConesResult:    input[10:12],
		Zero:             input[12:16],
		Length:           input[16:24],
		RequestToken:     input[24:32],
		UpdateIdentifier: input[32:40],
	}
	proxy.VerifyNotifyCallback(&vn)
}

func (proxy *GoSRxProxy) createV4Request(method SRxVerifyFlag, token int, defRes SRxDefaultResult, prefix IPPrefix, AS32 int, list ASPathList, data *BGPsecData) {
	fmt.Println("Creating V4 Request")

	request := VerifyMessage{
		PDU:                  VerifyReqeustIPv4PDU,
		Flags:                fmt.Sprintf("%02X", method),
		OriginResultSource:   fmt.Sprintf("%02X", defRes.resSourceROA),
		PathResultSource:     fmt.Sprintf("%02X", defRes.resSourceBGPsec),
		ASPAResultSource:     fmt.Sprintf("%02X", defRes.resSourceASPA),
		ASConesResultSource:  fmt.Sprintf("%02X", defRes.resSourceASCones),
		ASPathType:           fmt.Sprintf("%02X", list.ASType),
		ASRelationType:       fmt.Sprintf("%02X", list.Relation),
		OriginDefaultResult:  fmt.Sprintf("%02X", defRes.resSourceROA),
		PathDefaultResult:    fmt.Sprintf("%02X", defRes.resSourceBGPsec),
		ASPADefaultResult:    fmt.Sprintf("%02X", defRes.resSourceASPA),
		prefix_len:           fmt.Sprintf("%02X", prefix.length),
		request_token:        fmt.Sprintf("%02X", token),
		ASConesDefaultResult: fmt.Sprintf("%02X", defRes.resSourceASCones),
		prefix:               fmt.Sprintf("%02X", prefix.address.String()),
		origin_AS:            fmt.Sprintf("%08X", AS32),
	}

	// Check if any BGPsec data were parsed
	// If so: Prepare BGPsec fields of V4 Request
	if data != nil {
		request.bgpsec_length = fmt.Sprintf("%08X", data.NumberOfHops*4+data.AttrLength)
		request.num_of_hops = fmt.Sprintf("%04X", data.NumberOfHops)
		request.bgpsec_length = fmt.Sprintf("%04X", data.AttrLength)
		request.afi = fmt.Sprintf("%02X", data.afi)
		request.safi = fmt.Sprintf("%02X", data.safi)
		request.local_as = fmt.Sprintf("%02X", data.localAS)
	}

	request.Length = fmt.Sprintf("%08X", 61+(data.NumberOfHops*4+data.AttrLength))

	log.Debug(request)
	log.Debug("Finished creation")
}

func (proxy *GoSRxProxy) verifyUpdate(localID int, ROA bool, BGPsec bool, ASPA bool, ASCones bool, result SRxDefaultResult, prefix IPPrefix, AS int, data *BGPsecData, list ASPathList) {
	if !proxy.conStatus {
		log.Fatal("Abort verify, not connected to SRx server!")
		return
	}

	var method SRxVerifyFlag = 0

	if ROA {
		method |= SRX_FLAG_ROA
	}
	if BGPsec {
		method |= SRX_FLAG_BGPSEC
	}
	if ASPA {
		method |= SRX_FLAG_ASPA
	}
	if ASCones {
		method |= SRX_FLAG_ASCONE
	}
	if localID != 0 {
		method |= SRX_FLAG_REQUEST_RECEIPT
	}

	/*BGPsecLength := 0
	if data != nil {
		BGPsecLength = (data.NumberOfHops * 4) + data.AttrLength
	}
	isV4 := prefix.version == 4
	length := if isV4:

	if isV4 {

	}*/

}
