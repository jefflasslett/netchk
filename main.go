package main

import (
	"container/list"
	"flag"
	"fmt"
	"os"

	"netchk/internal/cidr"
)

func main() {
	ip_addr_str := flag.String("ip-addr", "", "ip node address to check")
	cidr_str := flag.String("net-cidr", "", "network CIDR to check ip addresses against")
	cidr_filename := flag.String("cidr-file", "", "file listing net cidrs to check address against")

	flag.Parse()

	var ip_addr, err = cidr.AddrStrToInt(*ip_addr_str)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	cidr_list := list.New()
	if len(*cidr_str) > 0 {
		net_mask, err := cidr.CidrStrToNetMask(*cidr_str)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(-1)
		}

		cidr_list.PushFront(net_mask)
	}

	if len(*cidr_filename) > 0 {
		cidr.ParseCidrFile(*cidr_filename, cidr_list)
	}

	for cidr_el := cidr_list.Front(); cidr_el != nil; cidr_el = cidr_el.Next() {
		var net_mask cidr.NetMask = cidr_el.Value.(cidr.NetMask)

		if cidr.IpInNet(ip_addr, net_mask) {
			fmt.Printf("IP %s is in network %s\n", *ip_addr_str, net_mask.RawCidr)
		} else {
			fmt.Printf("IP %s NOT in network %s\n", *ip_addr_str, net_mask.RawCidr)
		}
	}
}

func ErrToStr(err error) string {
	if err != nil {
		return err.Error()
	} else {
		return "no error"
	}
}
