package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"log"
	"net/http"
	"os"
	"testing"
)

//Create a pcap with out of order time stamps
func CreateTestPacket(file string) {
	fl, err := os.Open("./Pcaps/" + file)
	if err != nil {
		log.Print(err)
		return
	}
	defer fl.Close()

	r, err := pcapgo.NewReader(fl)
	if err != nil {
		log.Print(err)
		return
	}
	wFile, err := os.Create("./Pcaps/" + "ooo-" + file)
	if err != nil {
		log.Print(err)
		return
	}

	defer wFile.Close()
	w := pcapgo.NewWriter(wFile)
	w.WriteFileHeader(r.Snaplen(), r.LinkType())
	pktCnt := 0

	var bkupCI gopacket.CaptureInfo
	var bkupD []byte

	for {
		pktCnt++
		d, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		//Skip 3rd packet
		if pktCnt == 3 {
			bkupCI = ci
			bkupD = d
			continue
		}
		w.WritePacket(ci, d)
	}

	if len(bkupD) > 0 {
		//Write the packet skipped at the end of pcap
		w.WritePacket(bkupCI, bkupD)
	}

}

func TestCheckUrl(t *testing.T) {
	type args struct {
		url   string
		store bool
		file  string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Test Url 1",
			args: args{
				url:   "http://localhost:8080/fb.pcap",
				store: false,
				file:  "fb-test.pcap",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Test Url 2: OOO packet",
			args: args{
				url:   "http://localhost:8080/ooo-fb.pcap",
				store: true,
				file:  "fb-test.pcap",
			},
			want:    false,
			wantErr: false,
		},
	}

	CreateTestPacket("fb.pcap")
	defer os.Remove("./Pcaps/ooo-fb.pcap")
	defer os.Remove("fb-test.pcap")

	fs := http.FileServer(http.Dir("./Pcaps"))
	http.Handle("/", fs)
	go http.ListenAndServe(":8080", nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckUrl(tt.args.url, tt.args.store, tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckUrl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckUrl() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckFile(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{

		{
			name: "Test File 1: original pcap",
			args: args{
				file: "Pcaps/fb.pcap",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Test File 2: ooo packets",
			args: args{
				file: "Pcaps/ooo-fb.pcap",
			},
			want:    false,
			wantErr: false,
		},
	}
	CreateTestPacket("fb.pcap")
	defer os.Remove("./Pcaps/ooo-fb.pcap")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckFile(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckFile() got = %v, want %v", got, tt.want)
			}
		})
	}

}

func TestCreateTestPacket(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "GenerateFile",
			args: args{
				file: "./Pcaps/fb.pcap",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		})
	}
	if ok, _ := CheckFile("./Pcaps/ooo-fb.pcap"); ok {
		t.Fail()
	}
}
