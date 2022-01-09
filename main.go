package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	// Flags
	iface   = flag.String("i", "eth0", "Interface to read packets from")
	snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
	tstype  = flag.String("timestamp_type", "", "Type of timestamps to use")
	promisc = flag.Bool("promisc", true, "Set promiscuous mode")
	message = flag.String("m", "Go focus your work!", "Message to send")

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

func main() {
	flag.Parse()

	inactive, err := pcap.NewInactiveHandle(*iface)
	if err != nil {
		log.Fatal("could not create: %v", err)
	}
	defer inactive.CleanUp()
	if err = inactive.SetSnapLen(*snaplen); err != nil {
		log.Fatal("could not set snap length: %v", err)
	} else if err = inactive.SetPromisc(*promisc); err != nil {
		log.Fatal("could not set promisc mode: %v", err)
	} else if err = inactive.SetTimeout(time.Second); err != nil {
		log.Fatal("could not set timeout: %v", err)
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

	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}

	file, err := os.Open("urls.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var signatures [][]byte
	for scanner.Scan() {
		signatures = append(signatures, scanner.Bytes())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		ethlayer := packet.Layer(layers.LayerTypeEthernet)
		eth, ok := ethlayer.(*layers.Ethernet)
		if !ok {
			continue
		}

		iplayer := packet.Layer(layers.LayerTypeIPv4)
		ip, ok := iplayer.(*layers.IPv4)
		if !ok {
			continue
		}

		tcplayer := packet.Layer(layers.LayerTypeTCP)
		tcp, ok := tcplayer.(*layers.TCP)
		if !ok {
			continue
		}

		payload := tcp.LayerPayload()

		if !bytes.HasPrefix(payload, []byte("GET")) {
			continue
		}

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
