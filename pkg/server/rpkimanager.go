package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type RPKIManager struct {
	AS            int
	Proxy         *GoSRxProxy
	StartTime     time.Time
	Ready         *bool
	Server        *BgpServer
	SKI           string
	CurrentUpdate int
	PendingUpdate []*SRxTuple
}

type SRxTuple struct {
	local_id   int
	srx_id     string
	peer       *peer
	fsmMsg     *fsmMsg
	bgpMsg     *bgp.BGPMessage
	origin     bool
	aspa       bool
	std_val    bool
	sig_val    bool
	prefixAddr net.IP
	prefixLen  int
	ASPathList []int
	signatures []string
}

// NewRPKIManager Create new RPKI manager instance
// Input: pointer to BGPServer
func NewRPKIManager(s *BgpServer) (*RPKIManager, error) {
	// s.logger.Info("[i] Creating new RPKI Manager", nil)
	// ASN := int(s.bgpConfig.Global.Config.As)
	ASN := 65000
	rm := &RPKIManager{
		AS:        ASN,
		Server:    s,
		StartTime: time.Now(),
		Ready:     new(bool),
		Proxy:     nil,
		SKI:       "",
	}
	*rm.Ready = true
	return rm, nil
}

// SetSRxServer Parses the IP address of the SRx-Server
// Proxy can establish a connection with the SRx-Server and sends a hello message
// Thread mandatory to keep proxy alive during runtime
func (rm *RPKIManager) SetSRxServer(ip string) error {
	rm.Proxy, _ = NewGoSRxProxy(rm.AS, ip, rm.SKI, nil, nil)
	return nil
}

// SetSKI sets the SKI of the RPKIManager
func (rm *RPKIManager) SetSKI(SKI string) error {
	fmt.Println("Setting SKI", SKI)
	if len(SKI) != 40 {
		fmt.Println("SKI is not 40 characters long")
		return nil
	}
	rm.SKI = SKI
	return nil
}

func (rm *RPKIManager) SetAS(as uint32) error {
	if rm.AS != 0 {
		return fmt.Errorf("AS was already configured")
	}
	rm.AS = int(as)
	return nil
}

// Validate incoming BGP update message
func (rm *RPKIManager) ValidateUpdate(signatures string) error {
	new_pending_update := SRxTuple{
		local_id: rm.CurrentUpdate,
		std_val:  false,
		sig_val:  false,
	}
	rm.CurrentUpdate += 1

	fmt.Println("Validating BGP update message")
	if len(signatures) != 0 {
		rm.ValidateSignature(signatures)
	}
	fmt.Println(new_pending_update.local_id)
	return nil
}

// Generate signatures
func (rm *RPKIManager) GenerateSignature(peer *peer, paths []*table.Path, notification *bgp.BGPMessage) {
	// Prepare everything for signature generation for each path
	// Iterate over all paths
	for _, path := range paths {
		// Extract prefix
		prefixLen := 0
		prefixAddr := net.ParseIP("0.0.0.0")
		pathString := path.String()
		words := strings.Fields(pathString)
		for _, word := range words {
			for j, ch := range word {
				if ch == '/' {
					tmpPref, _ := strconv.Atoi(word[j+1:])
					prefixLen = tmpPref
					prefixAddr = net.ParseIP(word[:j])
				}
			}
		}

		prefix_length := prefixLen
		prefix_version := 4
		prefix_address := prefixAddr
		fmt.Printf("Prefix length: %d\n", prefix_length)
		fmt.Printf("Prefix version: %d\n", prefix_version)
		fmt.Printf("Prefix address: %s\n", prefix_address)

		// Extract AS path
		asList := path.GetAsList()
		fmt.Printf("AS path: %s\n", asList)

		// Extract the next hop
		nextHop := peer.AS()
		fmt.Printf("Next hop: %s\n", nextHop)

		// Generate timestamp
		timestamp := uint32(time.Now().Unix())

		// TODO: Add OTC functionality
		otcField := fmt.Sprintf("%08x", int64(65000))

		rm.Proxy.sendSigtraGenerationRequest(prefix_address, prefix_length, asList, timestamp, otcField, peer)
	}
}

// Validate signatures
func (rm *RPKIManager) ValidateSignature(signatures string) {
	fmt.Println("Validating signatures")
}

func (rm *RPKIManager) validate(peer *peer, m *bgp.BGPMessage, e *fsmMsg) {
	fmt.Println("Validating BGP update message!!!!!!!!!!!!!!!!")
	// Iterate over all paths in the update message
	for _, path := range e.PathList {
		// Create a new SRxTuple for each path
		update := SRxTuple{
			local_id: rm.CurrentUpdate,
			srx_id:   "",
			peer:     peer,
			fsmMsg:   e,
			bgpMsg:   m,
			origin:   !rm.Server.bgpConfig.Global.Config.ROA,
			aspa:     !rm.Server.bgpConfig.Global.Config.ASPA,
		}
		var flag SRxVerifyFlag
		var reqRes SRxDefaultResult
		var prefix IPPrefix
		//var ASN int
		var ASlist ASPathList

		flag = 128
		if update.origin {
			flag += 1
		}
		if update.aspa {
			flag += 4
		}

		reqRes.resSourceBGPsec = SRxRSUnknown
		reqRes.resSourceROA = SRxRSUnknown
		reqRes.resSourceASPA = SRxRSUnknown
		srxRes := SRxResult{
			ROAResult:    3,
			BGPsecResult: 3,
			ASPAResult:   3,
		}
		reqRes.result = srxRes

		prefixLen := 0
		prefixAddr := net.ParseIP("0.0.0.0")
		pathString := path.String()
		words := strings.Fields(pathString)
		for _, word := range words {
			for j, ch := range word {
				if ch == '/' {
					tmpPref, _ := strconv.Atoi(word[j+1:])
					prefixLen = tmpPref
					prefixAddr = net.ParseIP(word[:j])
				}
			}
		}

		prefix.length = prefixLen
		prefix.version = 4
		prefix.address = prefixAddr

		var array []int
		asList := path.GetAsList()
		for i, asn := range asList {
			ASlist.length = i
			ASlist.ASes = append(array, int(asn))
			ASlist.ASType = ASSequence
			ASlist.Relation = unknown
		}
		rm.PendingUpdate = append(rm.PendingUpdate, &update)
		rm.CurrentUpdate = (rm.CurrentUpdate % 10000) + 1

		// Print the SRxTuple for debugging
		fmt.Printf("SRxTuple: %+v\n", update)
		fmt.Printf("Prefix: %+v\n", prefix)
		fmt.Printf("ASPathList: %+v\n", ASlist)
		fmt.Printf("Prefix Length: %d\n", prefixLen)

		fmt.Printf("Request Result: %+v\n", reqRes)
		fmt.Printf("SRx Result: %+v\n", srxRes)
		fmt.Println("Pending updates:", len(rm.PendingUpdate))
	}
}
