#!/bin/bash	

# To run this script -> sudo ./script.sh google.com  after first making it executable using => chmod +x <script name>

url=$1     # in => assetfinder legomake.com. assetfinder is index 0 while legomake.com is index 1
RED="\033[1;31m"
RESET="\033[0m"

info_path=$url/info

if [ ! -d "$url" ];then    # This means if not directory of url, then make directory 
	mkdir $url
fi

if [ ! -d "$info_path" ];then
    mkdir $info_path
fi

if [ ! -d "$url/recon" ];then
	mkdir $url/recon
fi

if [ ! -d '$url/recon/gowitness_Screenshot' ];then
    mkdir $url/recon/gowitness_Screenshot
fi

if [ ! -d "$url/recon/scans" ];then
	mkdir $url/recon/scans
fi

if [ ! -d "$url/recon/httprobe" ];then
	mkdir $url/recon/httprobe
fi

if [ ! -d "$url/recon/potential_takeovers" ];then
	mkdir $url/recon/potential_takeovers
fi

if [ ! -d "$url/recon/wayback" ];then
	mkdir $url/recon/wayback
fi

if [ ! -d "$url/recon/wayback/params" ];then
	mkdir $url/recon/wayback/params
fi

if [ ! -d "$url/recon/wayback/extensions" ];then
	mkdir $url/recon/wayback/extensions
fi

if [ ! -f "$url/recon/httprobe/alive.txt" ];then    # This means if not file of alive.txt, then make that file
	touch $url/recon/httprobe/alive.txt
fi

if [ ! -f "$url/recon/final.txt" ];then
	touch $url/recon/final.txt
fi

echo -e "${RED} [+] Checkin' who it is...${RESET}"
whois $1 > $info_path/whois.txt

echo -e "${RED} [+] Harvesting subdomains with assetfinder...${RESET}"
assetfinder $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
rm $url/recon/assets.txt

#echo -e "${RED} [+] Double checking for subdomains with Running Amass. This could take a while...${RESET}"
#amass enum -d $url >> $url/recon/f.txt
#sort -u $url/recon/f.txt >> $url/recon/final.txt
#rm $url/recon/f.txt

echo -e "${RED} [+] Probing for alive domains...${RESET}"
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/httprobe/a.txt    #sort -u sorts unique and removes the duplicate
sort -u $url/recon/httprobe/a.txt > $url/recon/httprobe/alive.txt    #In alive.txt, you can grep for test, stag and admin
rm $url/recon/httprobe/a.txt

echo -e "${RED} [+] Checking for possible subdomain takeover...${RESET}"
if [ ! -f "$url/recon/potential_takeovers/potential_takeovers.txt" ];then
	touch $url/recon/potential_takeovers/potential_takeovers.txt
fi
subjack -w $url/recon/final.txt -t 100 -timeout 30 -ssl -c /home/kali/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $url/recon/potential_takeovers/potential_takeovers.txt

echo -e "${RED} [+] Scanning for open ports with Nmap. Sit tight, take a cup of coffee and relax. This will take some time...${RESET}"
nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned.txt

echo -e "${RED} [+] Scraping wayback data...${RESET}"
cat $url/recon/final.txt | waybackurls >> $url/recon/wayback/wayback_output.txt
sort -u $url/recon/wayback/wayback_output.txt

echo -e "${RED} [+] Pulling and compiling all possible params found in wayback data...${RESET}"
cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done

echo -e "${RED} [+] Pulling and compiling js/php/aspx/jsp/json files from wayback output...${RESET}"
for line in $(cat $url/recon/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "js" ]]; then
		echo $line >> $url/recon/wayback/extensions/js1.txt
		sort -u $url/recon/wayback/extensions/js1.txt >> $url/recon/wayback/extensions/js.txt
	fi
	if [[ "$ext" == "html" ]];then
		echo $line >> $url/recon/wayback/extensions/jsp1.txt
		sort -u $url/recon/wayback/extensions/jsp1.txt >> $url/recon/wayback/extensions/jsp.txt
	fi
	if [[ "$ext" == "json" ]];then
		echo $line >> $url/recon/wayback/extensions/json1.txt
		sort -u $url/recon/wayback/extensions/json1.txt >> $url/recon/wayback/extensions/json.txt
	fi
	if [[ "$ext" == "php" ]];then
		echo $line >> $url/recon/wayback/extensions/php1.txt
		sort -u $url/recon/wayback/extensions/php1.txt >> $url/recon/wayback/extensions/php.txt
	fi
	if [[ "$ext" == "aspx" ]];then
		echo $line >> $url/recon/wayback/extensions/aspx1.txt
		sort -u $url/recon/wayback/extensions/aspx1.txt >> $url/recon/wayback/extensions/aspx.txt
	fi
done

rm $url/recon/wayback/extensions/js1.txt
rm $url/recon/wayback/extensions/jsp1.txt
rm $url/recon/wayback/extensions/json1.txt
rm $url/recon/wayback/extensions/php1.txt
rm $url/recon/wayback/extensions/aspx1.txt

echo -e "${RED} [+] Taking screenshots with gowitness against all compiled subdomains...${RESET}"
gowitness file -f $url/recon/httprobe/alive.txt -P $url/recon/gowitness_Screenshot/

echo -e "${RED} [+] Everything is done. Happy Pentesting...${RESET}"
