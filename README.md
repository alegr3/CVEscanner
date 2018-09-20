# CVEscanner

## Nmap script used to discover potentially vulnerabilities of discovered services in detected open ports.

This tools uses the NSE Engine from Nmap to execute itself. In a Linux distribution, the NSE scripts are located in the following directory:

         /usr/local/share/nmap/scripts/      or      /usr/share/nmap/scripts 
         
Meanwhile in Windows systems this folders usually corresponds to:     
         
         c:\Program Files\Nmap\Scripts       or       <HOME>\AppData\Roaming\nmap
         
 First of all, copy the file **cvescanner.nse** to the previous location.

To launch this script is necessary to locate the */databases/* folder in the folder you are launching the Nmap command. This folder contains the databases used for the NSE script. The file **database.csv** have to exist inside this folder to a proper execution.

If you have not downloaded this file, the first time you will use this tool you will have to follow this steps:

1) Create one or more databases of a selected year by using the command: 
 
          nmap -sV localhost --script=cvescanner.nse --script-args='database=1999' -sn

2) This will generate a file, i.e. database1999.csv, with the vulnerabilities of the given year. You can create databases of each year from 1999 to the current year.

3) Merge the previous databases to a single file, database.csv, which will be the database used by the script. To do so, you just have to use the command: 
 
          nmap -sV localhost --script=cvescanner.nse --script-args='merge-database=1' -sn

4) Launch the script to search for vulnerabilities of a given host: 
 
          nmap -sV <target_ip> --script=cvescanner.nse

Otherwise, assuming that you have the databases correctly created, you just have to execute the 4) command to discover the vulnerabilities of the target host.
