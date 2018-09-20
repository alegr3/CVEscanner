This folder contains the databases used for the NSE script. This folder has to be placed in the same directory where the script is executed.

To a proper execution, which gives positive results, the file "database.csv" has to exist in this folder. 

The steps to execute the script are the following:

1) Create one or more databases of a selected year by using the command:
	nmap -sV localhost --script=example.nse --script-args='database=1999' -sn

2) This will generate a file, i.e. database1999.csv, with the vulnerabilities of the given year. You can create databases of each year from 1999 to the current year.

3) Merge the previous databases to a single file, database.csv, which will be the database used by the script. To do so, you just have to use the command:
	nmap -sV localhost --script=example.nse --script-args='merge-database=1' -sn

4) Launch a search of vulnerabilities:
	nmap -sV <target_ip> --script=cvescanner.nse