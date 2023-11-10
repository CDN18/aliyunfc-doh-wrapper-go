package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

const DOH_UPSTREAM = "https://223.5.5.5/dns-query"

const (
	fcRequestID          = "x-fc-request-id"
	fcLogTailStartPrefix = "FC Invoke Start RequestId: %s" // Start of log tail mark
	fcLogTailEndPrefix   = "FC Invoke End RequestId: %s"   // End of log tail mark
)

func main() {
	fmt.Println("FC inited.")
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/dns-query", queryHandler)
	http.ListenAndServe(":9000", nil)
}

func rootHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "text/plain")
	w.Write([]byte("200 OK"))
}

func queryHandler(w http.ResponseWriter, req *http.Request) {
	// Unpack Query
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(reqBody); err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to unpack query message", http.StatusBadRequest)
		return
	}

	// Setup ECS
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
		Option: []dns.EDNS0{
			&dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        1, // IP4
				SourceNetmask: 24,
				Address:       net.ParseIP(req.Header.Get("X-Forwarded-For")),
			},
		},
	}

	// Create New Query
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               reqMsg.Id,
			RecursionDesired: true,
		},
		Question: reqMsg.Copy().Question,
		Extra:    []dns.RR{opt},
	}

	// Forward To Upstream
	httpClient := &http.Client{}
	packedMsg, err := msg.Pack()
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to pack query message during forwarding", http.StatusInternalServerError)
		return
	}
	fwdreq, err := http.NewRequest("POST", DOH_UPSTREAM, bytes.NewBuffer(packedMsg))
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to create request during forwarding", http.StatusInternalServerError)
		return
	}
	fwdreq.Header.Set("Accept", "application/dns-message")
	fwdreq.Header.Set("Content-Type", "application/dns-message")
	resp, err := httpClient.Do(fwdreq)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to forward query message", http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to read upstream response body", http.StatusInternalServerError)
		return
	}
	resp.Body.Close()

	// Pack Response
	dnsMsg := new(dns.Msg)
	err = dnsMsg.Unpack(body)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to unpack upstream response body", http.StatusInternalServerError)
		return
	}
	bytes, err := dnsMsg.Pack()
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Failed to pack final response body", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(bytes)))
	w.Write(bytes)
}
