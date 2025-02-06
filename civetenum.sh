#!/bin/bash

#Colors
greenColor="\e[0;32m\033[1m"
endColor="\033[0m\e[0m"
redColor="\e[0;31m\033[1m"
blueColor="\e[0;34m\033[1m"
yellowColor="\e[0;33m\033[1m"
purpleColor="\e[0;35m\033[1m"
turquoiseColor="\e[0;36m\033[1m"
grayColor="\e[0;37m\033[1m"

COLS=$(tput cols)
ENDPOINT_NAME=""
CVE_FLAG=false

trap ctrl_c INT 
function ctrl_c() {
  echo -e "\n${redColor}[-] Interrupt signal received${endColor}"
  tput cnorm; exit 1
}

function helpPanel() {
  echo -e "${yellowColor}[+] Usage: civetenum [-h] [-v] [-n <name>] -p <ip>${endColor}\n"
  exit 0
}

#principal
function main() {
  manageRequirements

  tput civis; clear; echo -e "${purpleColor}"
  figlet -f "./bulbhead.flf" CivetEnum -w ${COLS}; echo -e "${endColor}"
  echo -e "${blueColor}                -==========================-"
  echo -e "                |  author | C1Ph3r@Hacker  |"
  echo -e "                -==========================-${endColor}"
  echo -e "                    CLI TOOL: CivetEnum"
  echo -e "                    Version: $(git rev-parse --short HEAD)"
  echo ""

  generateBinSpace "$1"
  scanNetwork "$1"

  echo "$1" > target.in
  echo $(/usr/bin/nmap -O $1) > "./nmap/system.in"

  if [[ -f ./nmap/Targeted && "$CVE_FLAG" -eq true ]]; then
#     searchVulnerability
     echo -e "The searched CVEs will be found on content folder"   
  fi

  tput cnorm; exit 0
}

#see for registered CVE and CVSS
function searchVulnerability() {
   echo -e "${turquoiseColor}[*] Searching for service registers... ${endColor}"
   progra=($(awk '/open/ {print $7 }' ./nmap/Targeted | grep -o -E '[[:alnum:]]+' | paste -sd ' '))
	
   for prog in "${progra[@]}"; do
      f=$(curl -s -m 100 https://vulnerability.circl.lu/api/browse/${prog} | jq -r '.[]')

      for i in "$f[@]"; do
	 # aqui debe validar si el producto tiene relación con lo hayado
      	 req=$(curl -s https://vulnerability.circl.lu/api/search/$prog/${i} | jq -r '.variot[0][1].affected_products.sources[4].id')
 	 echo -e "${greenColor}[+] Vuln $req Found! ${endColor}"
 	 curl -s https://vulnerability.circl.lu/api/cve/$req -o "./content/$req.json"
       done
   done
}

#see for required programs
function manageRequirements() {
  dependencies=(nmap figlet curl jq)

  echo -e "${yellowColor}[+] Testing dependencies...${endColor}"

  for program in "${dependencies[@]}"; do
    echo -ne "${turquoiseColor}[*] Testing ${program}...${endColor}"

    if test -f /usr/bin/$program; then
      echo -e "${greenColor}(V)${endColor}"

    else
      echo -e "${redColor}(X)${endColor}"
      echo -e "${redColor}[-] cancelling...${endColor}"
      tput cnorm; exit 0

    fi; sleep 1
  done
}

#create necesary directories to audit an endpoint
function generateBinSpace() {
  directories=("nmap" "content" "exploits" "screenshots")

  rootname=""
  if [ -z $ENDPOINT_NAME ]; then
    rootname=$1
  else 
    rootname="${ENDPOINT_NAME}-${1}"
  fi

  mkdir -p "$rootname"
  chmod 755 "$rootname"
  chown $SUDO_USER:$SUDO_USER $rootname
  cd "$rootname"
  
  for d in "${directories[@]}"; do
    mkdir -p $d
    chmod 755 $d
    chown $SUDO_USER:$SUDO_USER $d
  done
}

#search on the ip from open ports and generate trace
function scanNetwork() {
  /usr/bin/nmap -p- --open -sS --min-rate=5000 -vvv -n -Pn $1 -oG "./nmap/AllPorts"
  ports="$(cat ./nmap/AllPorts | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' | tr -d '\n')"

  if [ -z "${ports}" ]; then
    mv "./nmap/AllPorts" "./nmap/AllPortsOpened" 2> /dev/null 
    /usr/bin/nmap -p- -sS --min-rate=5000 -vvv -n -Pn $1 -oG "./nmap/AllPorts"
    ports="$(cat ./nmap/AllPorts | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' | tr -d '\n')"
  fi

  hosts_up=$(grep -oP '\(\K\d+(?= (hosts?|host) up\))' "./nmap/AllPorts")

  if [ "${hosts_up}" -ne "0" ]; then
    ports="$(cat ./nmap/AllPorts | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' | tr -d '\n')"
    /usr/bin/nmap -p"${ports}" -vvv -sVC $1 -oN nmap/Targeted -oX nmap/Targeted.xml
    echo -e "\n${greenColor}[v] Exploration finished!${endColor}"

  else
    echo -e "\n${redColor}[x] Host not found. ${endColor}"
  fi
}

# execution
ipv=""
declare -i parameter_counter=0; while getopts ":p:n:h:v" arg; do
  case $arg in
    h) helpPanel;;
    p) ipv=$OPTARG; parameter_counter+=1;;
    n) ENDPOINT_NAME=$OPTARG;;
    v) CVE_FLAG=true;;
    :) echo -e "\n${redColor}[-] Option -${OPTARG} requires an argument.${endColor}"; exit 1;;
    ?) echo -e "\n${redColor} [-] Invalid option: -${OPTARG}${endColor}"; exit 1;;
  esac
done

if [[ "$(id -u)" == "0" ]]; then # know is its running a sudo
   if [[ parameter_counter -lt 1 ]]; then
      helpPanel
   else
      main "${ipv}"
   fi
else
   echo -e "${redColor}[-] Root Permissions required.${endColor}\n"
   exit 1
fi

