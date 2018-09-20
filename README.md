# CVEscanner

Nmap script used to discover potentially vulnerabilities of discovered services in detected open ports.

To launch this script is necessary to locate the "databases" folder in the folder you are launching the nmap command. This folder contains the databases used for the NSE script. The file database.csv have to exist inside this folder to a proper execution.

If you have not downloaded this file, the first time you will use this tool you will have to follow this steps:

1) Create one or more databases of a selected year by using the command (without quotes): 
  "nmap -sV localhost --script=example.nse --script-args='database=1999' -sn"

2) This will generate a file, i.e. database1999.csv, with the vulnerabilities of the given year. You can create databases of each year from 1999 to the current year.

3) Merge the previous databases to a single file, database.csv, which will be the database used by the script. To do so, you just have to use the command (without quotes): 
  "nmap -sV localhost --script=example.nse --script-args='merge-database=1' -sn"

4) Launch a search of vulnerabilities (without quotes): 
  "nmap -sV <target_ip> --script=cvescanner.nse"

Otherwise, assuming that you have the databases correctly created, you just have to execute the 4) command to discover the vulnerabilities of the target host.
