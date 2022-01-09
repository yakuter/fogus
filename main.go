package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	// Flags
	iface    = flag.String("i", "eth0", "Interface to read packets from")
	snaplen  = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
	tstype   = flag.String("t", "", "Type of timestamps to use")
	promisc  = flag.Bool("p", true, "Set promiscuous mode")
	message  = flag.String("m", "Go focus your work!", "Message to send")
	fileName = flag.String("f", "urls.txt", "File to read signatures from")

	// Response data to inject
	preData = `HTTP/1.1 200 OK
	Server: nginx
	Date: Tue, 10 Jan 2022 00:00:00 GMT
	Expires: Thu, 01 Jan 1970 00:00:00 GMT
	Content-Type: text/plain;charset=UTF-8
	Connection: keep-alive
	Vary: Accept-Encoding
	Cache-Control: no-store
	Cache-Control: no-cache
	Pragrma: no-cache`
)

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err != nil {
			if err == io.EOF {
				return
			}

			// log.Println("Error reading stream", h.net, h.transport, ":", err)
			continue
		}

		bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
		req.Body.Close()
		fmt.Println("=========")
		fmt.Printf("%s%s", req.Host, req.URL.Path)
		fmt.Println("=========")
		log.Println("Received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body")

	}
}

func main() {
	flag.Parse()

	inactive, err := pcap.NewInactiveHandle(*iface)
	if err != nil {
		log.Fatalf("could not create: %v", err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetSnapLen(*snaplen); err != nil {
		log.Fatalf("could not set snap length: %v", err)
	} else if err = inactive.SetPromisc(*promisc); err != nil {
		log.Fatalf("could not set promisc mode: %v", err)
	} else if err = inactive.SetTimeout(time.Second); err != nil {
		log.Fatalf("could not set timeout: %v", err)
	}
	if *tstype != "" {
		if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
			log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
		} else if err := inactive.SetTimestampSource(t); err != nil {
			log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
		}
	}
	inactive.SetImmediateMode(true)
	handle, err := inactive.Activate()
	if err != nil {
		log.Fatal("PCAP Activate error:", err)
	}
	defer handle.Close()

	// Set BPF filter if specified. Example: "tcp port 80"
	err = setBPF(handle, flag.Args())
	if err != nil {
		log.Fatal("BPF error:", err)
	}

	// Read all the signatures from file
	// signatures, err := getSignatures(*fileName)
	// if err != nil {
	// 	log.Fatal("Error reading signatures:", err)
	// }

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Read all the packets from the handle
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packetSource.Packets():

			if packet.NetworkLayer() == nil ||
				packet.TransportLayer() == nil ||
				packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}

			// ethlayer := packet.Layer(layers.LayerTypeEthernet)
			// eth, ok := ethlayer.(*layers.Ethernet)
			// if !ok {
			// 	continue
			// }

			// iplayer := packet.Layer(layers.LayerTypeIPv4)
			// ip, ok := iplayer.(*layers.IPv4)
			// if !ok {
			// 	continue
			// }

			tcplayer := packet.Layer(layers.LayerTypeTCP)
			tcp, ok := tcplayer.(*layers.TCP)
			if !ok {
				continue
			}

			// payload := tcp.LayerPayload()

			// if !bytes.HasPrefix(payload, []byte("GET")) {
			// 	continue
			// }

			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

			/*
				for _, sign := range signatures {
					if !bytes.Contains(payload, sign) {
						continue
					}

					resp, err := generateResponse(*eth, *ip, *tcp, *message)
					if err != nil {
						log.Println(err)
						continue
					}

					if err := handle.WritePacketData(resp); err != nil {
						log.Println(err)
						continue
					}
				}
			*/

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

func generateResponse(eth layers.Ethernet, ip layers.IPv4, tcp layers.TCP, message string) ([]byte, error) {
	neweth := layers.Ethernet{
		SrcMAC:       eth.DstMAC,
		DstMAC:       eth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	newip := layers.IPv4{
		Version:  ip.Version,
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
		TTL:      77,
		Id:       ip.Id,
		Protocol: layers.IPProtocolTCP,
	}
	newtcp := layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		PSH:     true,
		ACK:     true,
		FIN:     true,
		Seq:     tcp.Ack,
		Ack:     tcp.Seq,
		Window:  0,
	}
	err := newtcp.SetNetworkLayerForChecksum(&newip)
	if err != nil {
		return nil, err
	}

	var data bytes.Buffer
	data.WriteString(preData)
	data.WriteString("\r\n")
	data.WriteString("Content-Length: ")
	data.WriteString(strconv.Itoa(len(message)))
	data.WriteString("\r\n\r\n")
	data.WriteString(message)

	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, &neweth, &newip, &newtcp, gopacket.Payload(data.Bytes()))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func getSignatures(fileName string) ([][]byte, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		result = append(result, scanner.Bytes())
	}

	return result, scanner.Err()
}

func setBPF(handle *pcap.Handle, filter []string) error {
	if len(filter) == 0 {
		return nil
	}

	bpfFilter := strings.Join(filter, " ")
	fmt.Printf("Using BPF filter %q\n", bpfFilter)

	return handle.SetBPFFilter(bpfFilter)
}
