
package main

import(
	"net/http"
	"net"
	"log"
	"fmt"
	"time"
	"strings"
	b64 "encoding/base64"
	"flag"
	"os"
	"crypto/tls"
)

const (
	BrightGreen     = "\033[1;32m%s\033[0m"
	BrightYellow    = "\033[1;33m%s\033[0m"
	BrightRed       = "\033[1;31m%s\033[0m"
	WhiteUnderline  = "\033[1;4m%s\033[0m"
	ClearColor      = "\033[1;1m%s\033[0m"
)

func main() {
	identifyCommand := flag.NewFlagSet("identify", flag.ExitOnError)
	identifyHost := identifyCommand.String("t", "","Host for targeted Exchange services.")

	examplesCommand := flag.NewFlagSet("examples", flag.ExitOnError)


	if len(os.Args) <= 1 {
		fmt.Println("~~NTLMHarvest v2.0.0~~")
		fmt.Println("Supply either the identify, userenum, or examples command for further assistance.\n")
		fmt.Println("View examples:")
		fmt.Println("	./msmailprobe examples")
		fmt.Println("	./msmailprobe identify")
		return
	}

	switch os.Args[1] {
		
		case "identify":
			identifyCommand.Parse(os.Args[2:])
		case "examples":
			examplesCommand.Parse(os.Args[2:])
		default:
			fmt.Printf("%q is not valid command.\n",os.Args[1])
			os.Exit(2)
	}

	if identifyCommand.Parsed() {
		if *identifyHost != "" {
			harvestInternalDomain(*identifyHost, true)
			urlEnum(*identifyHost)
		} else {
			fmt.Println("~~Identify Command~~\n")
			fmt.Println("Flag to use:")
				fmt.Println("	-t to specify target host\n")
				fmt.Println("Example:")
				fmt.Println("	./msmailprobe identify -t mail.target.com\n")
		}
	}

	if examplesCommand.Parsed() {
		fmt.Println("./msmailprobe identify -h mail.target.com")
	}
}

func harvestInternalDomain(host string, outputDomain bool) string {
	if outputDomain == true {
		fmt.Println("\nAttempting to harvest internal domain:")
	}
	url1 := "https://"+host+"/ews"
	url2 := "https://"+host+"/autodiscover/autodiscover.xml"
	url3 := "https://"+host+"/rpc"
	url4 := "https://"+host+"/mapi"
	url5 := "https://"+host+"/oab"
	url6 := "https://autodiscover."+host+"/autodiscover/autodiscover.xml"
	var urlToHarvest string
	if webRequestCodeResponse(url1) == 401 {
		urlToHarvest = url1
	} else if webRequestCodeResponse(url2) == 401 {
		urlToHarvest = url2
	} else if webRequestCodeResponse(url3) == 401 {
		urlToHarvest = url3
	} else if webRequestCodeResponse(url4) == 401 {
		urlToHarvest = url4
	} else if webRequestCodeResponse(url5) == 401 {
		urlToHarvest = url5
	} else if webRequestCodeResponse(url6) == 401 {
		urlToHarvest = url6
	} else {
		fmt.Printf(BrightYellow,"[-] ")
		fmt.Print("Unable to resolve host provided to harvest internal domain name.\n")
	}

	tr := &http.Transport {
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := time.Duration(3 * time.Second)

	client := &http.Client {
	        Timeout: timeout,
		Transport: tr,

	}
	req, err := http.NewRequest("GET", urlToHarvest, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36")
	req.Header.Set("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")
	resp, err := client.Do(req)


	if err != nil {
		return ""
	}
	ntlmResponse := resp.Header.Get("WWW-Authenticate")
	data := strings.Split(ntlmResponse, " ")
	
	base64DecodedResp, err := b64.StdEncoding.DecodeString(data[1])
	if err != nil {
		fmt.Println("Unable to parse NTLM response for internal domain name")
	}

	
	var continueAppending bool
	var internalDomainDecimal []byte
	var endcount int
	for count, decimalValue := range base64DecodedResp {
		if decimalValue == 0 {
			continue
		}
		if decimalValue == 2 {
			continueAppending = false
			endcount = count
		}
		if continueAppending == true {
			internalDomainDecimal = append(internalDomainDecimal, decimalValue)
		}
		if decimalValue == 15 {
			continueAppending = true
			continue
		}
	}

	var record bool
	var hostnameDecimal []byte

	for i := endcount+2; i <= len(base64DecodedResp)-1; i++ {
		if record == false {
			if (base64DecodedResp[i-2] == 1 && base64DecodedResp[i-1] == 0 ) {
				record = true
			}
		}
		if record == true {
			if (base64DecodedResp[i] == 0){
				continue
			}
			if (base64DecodedResp[i] == 4){
				endcount = i
				break
			}
			hostnameDecimal = append(hostnameDecimal, base64DecodedResp[i])
		}
	}

	var domainfqdndecimal []byte

	for i := endcount+2; i <= len(base64DecodedResp)-1; i++ {
		if record == true {
			if (base64DecodedResp[i] == 0){
				continue
			}
			if (base64DecodedResp[i] == 3){
				endcount = i
				break
			}
			domainfqdndecimal = append(domainfqdndecimal, base64DecodedResp[i])
		}
	}

	var hostnamefqdndecimal []byte

	for i := endcount+2; i <= len(base64DecodedResp)-1; i++ {
		if record == true {
			if (base64DecodedResp[i] == 0){
				continue
			}
			if (base64DecodedResp[i] == 5){
				endcount = i
				break
			}
			hostnamefqdndecimal = append(hostnamefqdndecimal, base64DecodedResp[i])
		}
	}

	var treefqdndecimal []byte

	for i := endcount+2; i <= len(base64DecodedResp)-1; i++ {
		if record == true {
			if (base64DecodedResp[i] == 0){
				continue
			}
			if (base64DecodedResp[i] == 7){
				endcount = i
				break
			}
			treefqdndecimal = append(treefqdndecimal, base64DecodedResp[i])
		}
	}


	if outputDomain == true {
		fmt.Printf(BrightGreen, "[+] ")
		fmt.Print("Internal Domain: ")
		fmt.Printf(BrightGreen, string(internalDomainDecimal)+ "\n")
		fmt.Printf(BrightGreen, "[+] ")
		fmt.Print("Hostname: ")
		fmt.Printf(BrightGreen, string(hostnameDecimal)+ "\n")
		fmt.Printf(BrightGreen, "[+] ")
		fmt.Print("FQDN Domain: ")
		fmt.Printf(BrightGreen, string(domainfqdndecimal)+ "\n")
		fmt.Printf(BrightGreen, "[+] ")
		fmt.Print("Forest FQDN: ")
		fmt.Printf(BrightGreen, string(treefqdndecimal)+ "\n")
	}
	return string(internalDomainDecimal)
}

func webRequestBasicAuth(URI string, user string, pass string, tr *http.Transport) int {
	timeout := time.Duration(45 * time.Second)
	client := &http.Client {
		Timeout: timeout,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", URI, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1")
	req.SetBasicAuth(user, pass)
	resp, errr := client.Do(req)
	if errr != nil {
		fmt.Printf("[i] Potential Timeout - %s \n", user)
		fmt.Printf("[i] One of your requests has taken longer than 45 seconds to respond.")
		fmt.Printf("[i] Consider lowering amount of threads used for enumeration.")
		log.Fatal(err)
	}
	return resp.StatusCode
}

func urlEnum(hostInput string) {
	//var logger = log.New(os.Stdout, "", 0)
	//Beginning of o365 enumeration
	//target-com.mail.protection.outlook.com
	hostSlice := strings.Split(hostInput, ".")
	//rootDomain := hostSlice[len(hostSlice)-2] + "." + hostSlice[len(hostSlice)-1]
	o365Domain := hostSlice[len(hostSlice)-2] + "-" + hostSlice[len(hostSlice)-1] + ".mail.protection.outlook.com"
	addr,err := net.LookupIP(o365Domain)
	if err != nil {
		fmt.Printf(BrightYellow,"[-] ")
		fmt.Println("Domain is not using o365 resources.")
	} else if addr == nil {
		fmt.Println("error")
	} else {
		fmt.Printf(BrightGreen,"[+] ")
		fmt.Println("Domain is using o365 resources.")
	}
	asURI := "https://" + hostInput + "/Microsoft-Server-ActiveSync"
	adURI := "https://" + hostInput + "/autodiscover/autodiscover.xml"
	ad2URI := "https://autodiscover." + hostInput + "/autodiscover/autodiscover.xml"
	owaURI := "https://" + hostInput + "/owa"
	timeEndpointsIdentified := false
	fmt.Println("")
	fmt.Println("\nIdentifying endpoints vulnerable to time-based enumeration:")
	timeEndpoints := []string{asURI,adURI,ad2URI,owaURI}
	for _, uri := range timeEndpoints {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 401 {
			fmt.Printf(BrightGreen,"[+] ")
			fmt.Println(uri)
			timeEndpointsIdentified = true
		}
		if responseCode == 200 {
			fmt.Printf(BrightGreen,"[+] ")
			fmt.Println(uri)
			timeEndpointsIdentified = true
		}
	}
	if timeEndpointsIdentified == false {
		fmt.Printf(BrightYellow, "[-] ")
		fmt.Println("No Exchange endpoints vulnerable to time-based enumeration discovered.")
	}
	fmt.Println("\n\nIdentifying exposed Exchange endpoints for potential spraying:")
	passEndpointIdentified := false
	rpcURI := "https://" + hostInput + "/rpc"
	oabURI := "https://" + hostInput + "/oab"
	ewsURI := "https://" + hostInput + "/ews"
	mapiURI := "https://" + hostInput + "/mapi"

	passEndpoints401 := []string{oabURI, ewsURI, mapiURI, asURI, adURI,ad2URI,rpcURI}
	for _, uri := range passEndpoints401 {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 401 {
			fmt.Printf(BrightGreen,"[+] ")
			fmt.Println(uri)
			passEndpointIdentified = true
		}
	}
	ecpURI := "https://" + hostInput + "/ecp"
	endpoints200 := []string{ecpURI, owaURI}
	for _, uri := range endpoints200 {
		responseCode := webRequestCodeResponse(uri)
		if responseCode == 200 {
			fmt.Printf(BrightGreen,"[+] ")
			fmt.Println(uri)
			passEndpointIdentified = true
		}
	}
	if passEndpointIdentified == false {
		fmt.Printf(BrightYellow, "[-] ")
		fmt.Println("No onprem Exchange services identified.")
	}
}

func webRequestCodeResponse(URI string) int {
	tr := &http.Transport {
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	timeout := time.Duration(3 * time.Second)
	client := &http.Client {
		Timeout: timeout,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", URI, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1")
	resp, err := client.Do(req)
	if err != nil {
		return 0
		//log.Fatal(err)
	}
	return resp.StatusCode
}

func writeFile(filename string, values []string) {
	if len(values) == 0 {
		return
	}
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	for _, value := range values {
		fmt.Fprintln(f, value)
	}
}
