package cidr

import (
	"bufio"
	"container/list"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type NetMask struct {
	RawCidr    string
	net_number uint32
	mask       uint32
}

func ParseCidrFile(filename string, cidr_list *list.List) error {
	file, err := os.Open(filename)

	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		cidr_line := scanner.Text()
		netmask, err := CidrStrToNetMask(cidr_line)
		if err != nil {
			return err
		}

		cidr_list.PushFront(netmask)
	}
	return nil
}

func IpInNet(ip_num uint32, net_mask NetMask) bool {
	// var a, b uint32
	// a = ip_num & net_mask.mask
	// b = net_mask.net_number & net_mask.mask
	// fmt.Printf("IpInNet: mask: %08x, net_number: %08x, ip: %08x, a: %08x, b: %08x\n",
	//            net_mask.mask, net_mask.net_number, ip_num, a, b)
	// return a == b
	return (ip_num & net_mask.mask) == (net_mask.net_number & net_mask.mask)
}

func AddrStrToInt(addr_str string) (uint32, error) {
	var octets []string = strings.Split(addr_str, ".")
	var result uint32 = 0

	if len(octets) != 4 {
		return 0, errors.New(fmt.Sprintf("invalid ip4 addr: %s", addr_str))
	}

	for _, octet_str := range octets {
		octet, err := strconv.Atoi(octet_str)
		if err != nil {
			return 0, errors.New(fmt.Sprintf("invalid octet: %s: err: %s", octet_str, err.Error()))
		}

		if octet < 0 || octet > 0xff {
			return 0, errors.New(fmt.Sprintf("invalid octet: %s: not b/n 0 & 255", octet_str))
		}

		result = (result << 8) + uint32(octet)
	}

	return result, nil
}

func CidrStrToNetMask(cidr_str string) (NetMask, error) {
	result := NetMask{"", 0, 0}

	cidr_parts := strings.Split(cidr_str, "/")

	if len(cidr_parts) != 2 {
		return result, errors.New(fmt.Sprintf("CidrStrToNetMask: malformed cidr: %s", cidr_str))
	}

	net_bits, err := strconv.Atoi(cidr_parts[1])
	if err != nil {
		return result, errors.New(fmt.Sprintf("CidrStrToNetMask: malformed net bits: %s", cidr_parts[1]))
	}

	if net_bits > 32 {
		return result, errors.New(fmt.Sprintf("CidrStrToNetMask: net bits out of range: %d", net_bits))
	}

	result.mask = (uint32(0xffffffff) << (32 - net_bits))

	net_num, err := AddrStrToInt(cidr_parts[0])
	if err != nil {
		return result, errors.New(fmt.Sprintf("CidrStrToNetMask: bad net number: %d", net_num))
	}

	result.RawCidr = cidr_str
	result.net_number = net_num
	return result, nil
}
