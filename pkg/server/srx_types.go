package server

import (
	"net"
)

const (
	PDU_SRXPROXY_HELLO                      = 0
	PDU_SRXPROXY_HELLO_RESPONSE             = 1
	PDU_SRXPROXY_GOODBYE                    = 2
	PDU_SRXPROXY_VERIFY_V4_REQUEST          = 3
	PDU_SRXPROXY_VERIFY_V6_REQUEST          = 4
	PDU_SRXPROXY_SIGN_REQUEST               = 5
	PDU_SRXPROXY_VERI_NOTIFICATION          = 6
	PDU_SRXPROXY_SIGN_NOTIFICATION          = 7
	PDU_SRXPROXY_DELTE_UPDATE               = 8
	PDU_SRXPROXY_PEER_CHANGE                = 9
	PDU_SRXPROXY_SYNC_REQUEST               = 10
	PDU_SRXPROXY_ERROR                      = 11
	PDU_SRXPROXY_UNKNOWN                    = 12
	PDU_SRXPROXY_REGISTER_SKI               = 13
	PDU_SRXPROXY_SIGTRA_GENERATION_REQUEST  = 14
	PDU_SRXPROXY_SIGTRA_VALIDATION_REQUEST  = 15
	PDU_SRXPROXY_SIGTRA_SIGNATURE_RESPONSE  = 16
	PDU_SRXPROXY_SIGTRA_VALIDATION_RESPONSE = 17
)

const (
	HelloPDU                 = "00"
	HelloRepsonsePDU         = "01"
	GoodByeMessagePDU        = "02"
	VerifyReqeustIPv4PDU     = "03"
	VerifyReqeustIPv6PDU     = "04"
	SignRequestPDU           = "05"
	VerifyNotifyPDU          = "06"
	SignatureNotificationPDU = "07"
	DeleteUpdatePDU          = "08"
	PeerChangePDU            = "09"
	SyncMessagePDU           = "0a"
	ErrorPacketPDU           = "0b"
	TransitivePDU            = "0e"
)

type SRxValidationResultVal string

type BGPsecDate struct {
	lengthPathValData string
	numOfHops         string
	bgpsecLength      string
	afi               string
	safi              string
	prefixLenBgpsec   string
	ipPreAddByteA     string
	ipPreAddByteB     string
	ipPreAddByteC     string
	ipPreAddByteD     string
}

type HelloMessage struct {
	PDU              string
	Version          string
	reserved         string
	zero             string
	length           string
	proxy_identifier string
	ASN              string
	SKI              string
}

type BGPsecData struct {
	NumberOfHops   int
	ASPath         []string
	AttrLength     int
	afi            int
	safi           int
	reserved       int
	localAS        string
	bgpsecPathAttr int
}

const (
	SRxRS_SRX      = 0
	SRxRS_ROUTER   = 1
	SRxRS_IGP      = 2
	SRxRS_UNKNOWN  = 3
	SRxRS_DONOTUSE = 1280
)

const (
	SRx_RESULT_VALID        SRxValidationResultVal = "0"
	SRx_RESULT_NOTFOUND     SRxValidationResultVal = "1"
	SRx_RESULT_INVALID      SRxValidationResultVal = "2"
	SRx_RESULT_UNDEFINED    SRxValidationResultVal = "3"
	SRx_RESULT_DONOTUSE     SRxValidationResultVal = "4"
	SRx_RESULT_UNKNOWN      SRxValidationResultVal = "5"
	SRx_RESULT_UNVERIFIABLE SRxValidationResultVal = "6"
)

type VerifyMessage struct {
	PDU                  string
	Flags                string
	OriginResultSource   string
	PathResultSource     string
	ASPAResultSource     string
	ASConesResultSource  string
	reserved             string
	ASPathType           string
	ASRelationType       string
	Length               string
	OriginDefaultResult  string
	PathDefaultResult    string
	ASPADefaultResult    string
	prefix_len           string
	request_token        string
	ASConesDefaultResult string
	prefix               string
	origin_AS            string
	length_path_val_data string
	num_of_hops          string
	bgpsec_length        string
	afi                  string
	safi                 string
	prefix_len_bgpsec    string
	ip_pre_add_byte_a    string
	ip_pre_add_byte_b    string
	ip_pre_add_byte_c    string
	ip_pre_add_byte_d    string
	local_as             string
	as_path_list         string
	path_attribute       string
	bgpsec               string
}

type VerifyNotify struct {
	PDU              string
	ResultType       string
	OriginResult     string
	PathResult       string
	ASPAResult       string
	ASConesResult    string
	Zero             string
	Length           string
	RequestToken     string
	UpdateIdentifier string
}

type SRxHeader struct {
	PDU        string
	Reserved16 string
	Reserved8  string
	Reserved32 string
	Length     string
}

type SigTraGenRequest struct {
	SignatureID    string
	PrefixLength   string
	Prefix         string
	ASPathLength   string
	ASPath         string
	OriginAS       string
	Timestamp      string
	OTCField       string
	PeerListLength string
	PeerList       string
	requestingAS   string
	blockCount     string
}

/*type SigTraValReq struct {
	signatureID string
	blockCount  string
	blocks      string // SigBlocks
}*/

type SigTraValReq struct {
	signatureID string
	blockCount  string
	prefixLen   string
	prefix      string
	asPathLen   string
	asPath      string
	otcField    string
	blocks      string
}

type SigBlock struct {
	id              string
	signatureLength string
	signature       string
	timestamp       string
	ski             string
	creatingAS      string
	nextAS          string
}

/*type SigBlock struct {
	prefixLength string
	prefix       string
	asPathLength string
	asPath       string
	pkiIDType    string
	pkiID        string
	timestamp    string
	signature    string
	OTCFlags     string
	OTCField     string
}*/

type SkiMessage struct {
	PDU             string
	Version         string
	length          string
	proxyIdentifier string
	ski             string
}

type SRxResult struct {
	ROAResult     int
	BGPsecResult  int
	ASPAResult    int
	ASConesResult int
}

type SRxResultSource int

const (
	SRxRSSRx      SRxResultSource = 0
	SRxRSRouter   SRxResultSource = 1
	SRxRSIGP      SRxResultSource = 2
	SRxRSUnknown  SRxResultSource = 3
	SRxRSDoNotUse SRxResultSource = 128
)

type SRxDefaultResult struct {
	resSourceROA     SRxResultSource
	resSourceBGPsec  SRxResultSource
	resSourceASPA    SRxResultSource
	resSourceASCones SRxResultSource
	result           SRxResult
}

type SRxVerifyFlag int

const (
	SRX_FLAG_ROA                    SRxVerifyFlag = 1
	SRX_FLAG_BGPSEC                 SRxVerifyFlag = 2
	SRX_FLAG_ASPA                   SRxVerifyFlag = 4
	SRX_FLAG_ASCONE                 SRxVerifyFlag = 8
	SRX_FLAG_ROA_AND_ASPA           SRxVerifyFlag = SRX_FLAG_ROA | SRX_FLAG_ASPA
	SRX_FLAG_ROA_AND_ASCONE         SRxVerifyFlag = SRX_FLAG_ROA | SRX_FLAG_ASCONE
	SRX_FLAG_ROA_AND_BGPSEC         SRxVerifyFlag = SRX_FLAG_ROA | SRX_FLAG_BGPSEC
	SRX_FLAG_BGPSEC_AND_ASPA        SRxVerifyFlag = SRX_FLAG_BGPSEC | SRX_FLAG_ASPA
	SRX_FLAG_ROA_BGPSEC_ASPA        SRxVerifyFlag = SRX_FLAG_ROA | SRX_FLAG_BGPSEC | SRX_FLAG_ASPA
	SRX_FLAG_ROA_BGPSEC_ASPA_ASCONE SRxVerifyFlag = SRX_FLAG_ROA | SRX_FLAG_BGPSEC | SRX_FLAG_ASPA | SRX_FLAG_ASCONE
	SRX_FLAG_REQUEST_RECEIPT        SRxVerifyFlag = 128
)

type HelloResponseMessage struct {
	PDU              string
	version          string
	reserved         string
	zero             string
	length           string
	proxy_identifier string
}

type ASTypeDef int

const (
	ASSet            ASTypeDef = 1
	ASSequence       ASTypeDef = 2
	ASConfedSequence ASTypeDef = 3
	ASConfedSet      ASTypeDef = 4
)

type ASRelType int

const (
	unknown       ASRelType = 0
	customer      ASRelType = 1
	provider      ASRelType = 2
	sibling       ASRelType = 3
	lateral       ASRelType = 4
	makeEnum32Bit ASRelType = 0xffffffff
)

type IPPrefix struct {
	length  int
	version int
	address net.IP
}

type ASPathList struct {
	length   int
	ASes     []int
	ASType   ASTypeDef
	Relation ASRelType
}
