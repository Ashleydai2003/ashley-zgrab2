// Package rdp provides a zgrab2 module that scans for RDP servers.
// Default Port: 3389 (TCP)
//
// The --tls flag tells the scanner to wrap the entire connection in a TLS session.
//
// The --send-security-protocol flag tells the scanner to send the security protocol command.
//
// The --send-client-protocol flag tells the scanner to send the client protocol command.
package rdp

// TODO: why do we need these packages?
import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// ErrInvalidResponse is returned when the server returns an invalid or unexpected response.
var ErrInvalidResponse = zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("invalid response for RDP"))

// TODO: add more fields to the ScanResults struct as we go
// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// SecurityProtocol indicates which security protocol is being used
	// Examples: Standard RDP security protocol, TLS/SSL, CredSSP
	// Note: This is sent with the negotiation response
	// in Remote Desktop Protocol
	SecurityProtocol string `json:"security_protocol,omitempty"`

	// TODO: should probably make this name shorted
	// Note: This is sent with the negotiation response
	// in Remote Desktop Protocol -> Flags
	ExtentededClientDataBlockSupported bool `json:"extended_client_data_block_supported,omitempty"`

	// TODO: should probably make this name shorted
	// Note: This is sent with the negotiation response
	// in Remote Desktop Protocol -> Flags
	// GraphicPipelinesExtensionProtocalSupported indicates if the server supports the graphic pipelines extension protocol
	GraphicPipelinesExtensionProtocalSupported bool `json:"graphic_pipelines_extension_protocal_supported,omitempty"`

	// TODO: should probably make this name shorted
	// Note: This is sent with the negotiation response
	// in Remote Desktop Protocol -> Flags
	// RestrictedAdminModeSupported indicates if the server supports the restricted admin mode
	RestrictedAdminModeSupported bool `json:"restricted_admin_mode_supported,omitempty"`

	// Neg response reserved? Didn't get it with my Wireshark request

	// TODO: should probably make this name shorted
	// Note: This is sent with the negotiation response
	// in Remote Desktop Protocol -> Flags
	// RestrictedAuthenticationModeSupported indicates if the server supports the restricted authentication mode
	RestrictedAuthenticationModeSupported bool `json:"restricted_authentication_mode_supported,omitempty"`

	// TODO: consider if this is needed or even makes sense
	// ImplicitTLS is true if the connection was wrapped in TLS
	// true if --force-tls is set and false if not
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard TLS log if TLS is used
	// contains information about TLS version, cipher suite, and other TLS details
	// handled by zgrab2.TLSLog struct
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// TODO: understand these flags and tailor them to the RDP protocol
// Flags holds the command-line configuration for the RDP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	// TODO: why are we using TLSFlags?
	zgrab2.TLSFlags `group:"TLS Options"`

	// TODO: SendSecurityProtocol indicates that the client should send the security protocol negotiation request
	SendSecurityProtocol bool `long:"send-security-protocol" description:"Send the security protocol negotiation request"`

	// TODO: ForceTLS indicates that the entire connection should be wrapped in a TLS session
	ForceTLS bool `long:"force-tls" description:"Perform a TLS handshake immediately upon connecting"`

	// TODO: Verbose indicates that there should be more verbose logging
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// TODO: implement?
// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner is main struct that implements the zgrab2.Scanner interface
// Created once per scan session and reused for multiple targets
type Scanner struct {
	// Contains the configuration for the RDP scan
	config *Flags
	// Contains TCP connections, TLS connections, and other configuration
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// RegisterModule registers the zgrab2 module and makes it rdp available as a command
func RegisterModule() {
	// creates a new Module instance
	var module Module
	// registers the module with the zgrab2 framework
	// 3389 is the default port for RDP
	// rdp is the command name and short description
	// &module is a pointer to the Module instance
	_, err := zgrab2.AddCommand("rdp", "rdp", module.Description(), 3389, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object
func (module *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// TODO: tailor this description as more is added
// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for RDP (Remote Desktop Protocol) servers. By default, the scanner will attempt to " +
		"establish a connection and perform the RDP protocol negotiation. If TLS is enabled, the connection " +
		"will be wrapped in a TLS session. The scanner can optionally specify the security protocol " +
		"in the negotiation request."
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(_ []string) error {
	// Check for mutually exclusive TLS options
	if flags.ForceTLS && flags.SendSecurityProtocol {
		return errors.New("cannot use --force-tls and --send-security-protocol at the same time")
	}
	return nil
}

// TODO: implement a more helpful help message
// Help returns the RDP module's help string
func (flags *Flags) Help() string {
	return "Probe for RDP servers and perform protocol negotiation."
}

// Init initializes the scanner with the given flags and dialer group config.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		// indicates that the scanner needs a separate L4 dialer
		NeedSeparateL4Dialer: true,
		// configures the base flags
		BaseFlags: &f.BaseFlags,
		// enable TLS (?) flag
		TLSEnabled: f.ForceTLS,
		// configures the TLS flags
		TLSFlags: &f.TLSFlags,
	}
	return nil
}

// InitPerSender initializes the scanner for a given sender
// Called once per sender
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan
func (scanner *Scanner) Protocol() string {
	return "rdp"
}

// GetDialerGroupConfig returns the dialer group configuration for the scanner
// dialer group config was set in Init function
func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// For RDP, you'll need different helper functions that deal with:
// RDP protocol negotiation
// RDP security protocol handling
// RDP connection state management
// RDP message formatting
// Note: RDP uses binary protocol messages rather than text-based responses

// Scan performs the RDP scan without authentication.
//  1. Open a TCP connection to the target IP address and port (default 3389)
//  2. If --force-tls is set, perform a TLS handshake
//  3. Perform RDP protocol negotiation (X.224)
//  4. If --send-security-protocol is set, specify the security protocol (embedded in the RDP Negotiation Request)
//  5. If --send-client-protocol is set, send client protocol negotiation (TODO: huh?)
//  6. Close the connection
//
// Note: We stop before authentication to gather information without logging in
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	// TODO: Send Client Hello after negotiation (maybe) (TLS)

	// Get the TCP Layer (4) dialer from dialer group
	// RDP requires TCP, so we need an L4 dialer
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. RDP requires a L4 dialer")
	}

	// TODO: if TLS is enabled, wrap the TCP connection in a TLS session (?)

	// Establish TCP connection to target
	// Convert target.IP to string since JoinHostPort expects string
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// Defer connection cleanup to ensure the connection is closed after we're done
	// This is important to prevent resource leaks
	defer zgrab2.CloseConnAndHandleError(conn)

	// Create a new ScanResults instance to store scan data
	result := &ScanResults{}

	// Build RDP Negotiation Request
	// This creates a binary packet with:
	// 1. TPKT header (4 bytes)
	// 2. X.224 header (3 bytes)
	// 3. X.224 connection request (3 bytes)
	// 4. RDP Negotiation Request (8 bytes)
	negotiationRequest := buildRDPNegotiationRequest()

	// Send the RDP Negotiation Request to the server
	// Write sends the entire buffer to the connection
	_, err = conn.Write(negotiationRequest)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("failed to send RDP negotiation request: %w", err)
	}

	// Read the response from the server
	// We allocate a 1024-byte buffer to store the response
	// This should be enough for a typical RDP negotiation response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("failed to read RDP negotiation response: %w", err)
	}

	// Parse the negotiation response
	// This will extract the protocol type, flags, and selected protocol
	parsed, parseErr := parseRDPNegotiationResponse(response[:n])
	if parseErr != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, result, fmt.Errorf("failed to parse RDP negotiation response: %w", parseErr)
	}

	// Convert the selected protocol to a string representation
	// RDP protocol types:
	// 0x00000000 - Standard RDP security
	// 0x00000001 - SSL/TLS
	// 0x00000002 - CredSSP
	// 0x00000003 - SSL/TLS + CredSSP (Hybrid)
	protocolStr := getProtocolString(parsed.SelectedProtocol)
	result.SecurityProtocol = protocolStr

	// Parse the flags from the response
	// Each bit in the flags byte represents a different capability
	result.ExtentededClientDataBlockSupported = parsed.Flags&0x01 != 0
	result.GraphicPipelinesExtensionProtocalSupported = parsed.Flags&0x02 != 0
	result.RestrictedAdminModeSupported = parsed.Flags&0x04 != 0
	result.RestrictedAuthenticationModeSupported = parsed.Flags&0x08 != 0

	return zgrab2.SCAN_SUCCESS, result, nil
}

// Helper function to convert protocol number to string
func getProtocolString(protocol uint32) string {
	switch protocol {
	case 0x00000000:
		return "Standard RDP security"
	case 0x00000001:
		return "SSL/TLS"
	case 0x00000002:
		return "CredSSP"
	case 0x00000003:
		return "SSL/TLS + CredSSP (Hybrid)"
	default:
		return fmt.Sprintf("Unknown protocol (0x%08x)", protocol)
	}
}

func buildRDPNegotiationRequest() []byte {
	return []byte{
		// TPKT header (4 bytes)
		0x03, 0x00, 0x00, 0x13, // Version = 3, Reserved = 0, Length = 19 bytes

		// X.224 header (7 bytes)
		0x0e,       // Length of remaining X.224 data
		0xe0,       // CR TPDU code
		0x00, 0x00, // DST-REF (0x0000)
		0x00, 0x00, // SRC-REF (0x0000)
		0x00, // Class 0

		// RDP Negotiation Request (8 bytes)
		0x01, 0x00, // Type: 0x01 (RDP Negotiation Request)
		0x08, 0x00, // Length: 8 bytes
		0x0b, 0x00, 0x00, 0x00, // RequestedProtocols: SSL | HYBRID | RDSTLS (0x0B) LE
	}
}

// Helper function to parse RDP Negotiation Response
type RDPNegotiationResponse struct {
	Type             byte   // Response type (0x02 = Response, 0x03 = Failure)
	Flags            byte   // Capability flags
	SelectedProtocol uint32 // The protocol selected by the server
}

func parseRDPNegotiationResponse(data []byte) (*RDPNegotiationResponse, error) {
	// Sanity check: Minimum length for full header + response
	// TPKT(4) + X.224(3) + X.224(3) + RDP(8) = 18 bytes minimum
	if len(data) < 19 {
		return nil, errors.New("response too short")
	}

	// RDP Negotiation Response starts at byte 11
	// This is after the TPKT and X.224 headers
	responseType := data[11]
	if responseType == 0x03 { // 0x03 = Failure
		return nil, fmt.Errorf("received RDP Negotiation Failure")
	}
	if responseType != 0x02 { // 0x02 = Response
		return nil, fmt.Errorf("unexpected response type: 0x%02x", responseType)
	}

	// Parse the response structure
	return &RDPNegotiationResponse{
		Type:             data[11],
		Flags:            data[12],
		SelectedProtocol: binary.LittleEndian.Uint32(data[13:17]),
	}, nil
}

// TODO:
// First just implement getting the response from RDP Negotiation Request
// Then implement getting the response from Client Hello (TLS)
// Then implement sending the security protocol negotiation request:
// When parsing the server handshake, decode the Certificate TLS record.
// Use a Go X.509 parser (e.g., crypto/x509.ParseCertificate) to extract these fields.
