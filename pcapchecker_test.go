package main

import (
	"net/http"
	"testing"
)

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
			name:    "Test Url 1",
			args:    args{
				url:   "http://localhost:8080/fb.pcap",
				store: false,
				file:  "fb-test.pcap",
			},
			want:    true,
			wantErr: false,
		},
	}

	fs := http.FileServer(http.Dir("./"))
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
			name:    "Test File 1",
			args:    args{
				file: "fb.pcap",
			},
			want:    true,
			wantErr: false,
		},
	}
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