package main

import (
	"flag"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

/*
	A simple program to check whether packets are ordered based on timestamp in a given pcap.
*/

func CheckStream(r io.Reader) (bool, error) {
	reader, err := pcapgo.NewReader(r)
	if err != nil {
		log.Println("Error opening pcap stream")
		log.Print(err)
		return false, err
	}

	_,ci, err := reader.ReadPacketData()
	if err != nil {
		log.Println("Error reading packet data")
		log.Print(err)
		return false, err
	}
	prevTs := ci.Timestamp

	for {
		_, ci, err = reader.ReadPacketData()
		if err != nil {
			//log.Println("Error reading packet data")
			break
		}
		if prevTs.After(ci.Timestamp) {
			return false, err
		}
		prevTs = ci.Timestamp
	}

	return true, nil
}

func CheckFile(file string) (bool, error) {
	fl, err := os.Open(file)
	if err != nil {
		log.Println("Error opening file")
		return false, err
	}

	defer  fl.Close()
	return CheckStream(fl)
}

func CheckUrl(url string, store bool, file string) (bool, error) {
	rsp, err := http.Get(url)
	if err != nil {
		log.Printf("Error retrieving url: %s\n", url)
		return false, err
	}

	if rsp.StatusCode != http.StatusOK {
		log.Printf("Unable to retrieve file, Server returned %s", rsp.Status)
		return false, err
	}

	isValid, err := CheckStream(rsp.Body)
	if !isValid && store {
		//Invalid file, store in local directory
		fl, err := os.Create(file)
		if err != nil {
			log.Printf("Error opening pcap file: %s", file)
			return isValid, err
		}
		defer fl.Close()

		_, err =io.Copy(fl, rsp.Body)
		if err != nil {
			log.Println("Error writing to pcap file")
		}
	}

	return true, err
}

func main()  {
	file := flag.String("f", "", "Read local file")
	url := flag.String("u", "", "Read from Url")

	flag.Parse()

	if len(*file) > 0 {

		if ok, _ := CheckFile(*file); ok {
			log.Println("No OOO packets found..")
		} else {
			log.Println("OOO packets found")
		}
	} else if len(*url) > 0 {
		tmp := strings.Split(*url, "/")
		fName := tmp[len(tmp) - 1]
		if ok, _ := CheckUrl(*url, true, fName); ok {
			log.Println("No OOO packets found..")
		} else {
			log.Println("OOO packets found")
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}

}