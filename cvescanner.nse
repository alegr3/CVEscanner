local http = require("http")
local lfs = require ( "lfs" )
http.max_cache_size = 1500000
local nmap = require "nmap"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local vulns = require "vulns"

description = [[
This script search for possible vulnerabilities of a given host by analyzing its open ports. To do so it employs a database created from CVEdetails.com.
]]
-- @usage
-- nmap -sV <target_ip> --script=example.nse
--
-- @output
-- PORT      STATE SERVICE       VERSION
-- 22/tcp    open  SSH           1.2.27
-- | cvescanner: 
-- |   product: SSH
-- |   version: 1.2.27
-- |   from: database.csv
-- |   vulnerabilities: 35
-- |   vulns: 
-- |     CVE ID          SCORE
-- |     CVE-1999-0248   10.0
-- |     CVE-1999-0398   4.6
-- |     CVE-1999-0787   2.1
-- |     CVE-1999-1010   2.1
-- |     ...

-- Another functionality
-- 		nmap -sV localhost --script=example.nse --script-args='database=1999' -sn
-- @args database: it is possible to create a database of a year ("1999") or a range of years ("1999-2018")
-- 		nmap -sV localhost --script=example.nse --script-args='merge-database=1' -sn
-- @args merge-database: by setting it to "1" value, it unifies the available databases to create the vulnerability database for this script.

authors = "Fernando Alegre"

-- the action function will be executed previously to the nmap scan if creating a database or merging the existing ones.
prerule = function()

	return true 

end

-- function for ports that checks when the action fuction will be executed. In this case, for every open port
portrule = function(host, port)

	if port.service ~= "tcpwrapped" and port.service ~= "unknown" and port.version.product ~= nil and port.version.version ~= nil then
		return true
	else
		stdnse.print_debug(1, "There are not open ports with product/version available.")
	end

end

local function remove_blank( cond , T , F )

    if cond then return T else return F end
    
end

-- scraps and returns the pages in a search
local function scrapPages(response)

	-- pattern to match the links of the pages in the current cvedetails.com page
	local pages_html = string.match(response.body, '<div%sclass=\"paging\"%sid=\"pagingb\">(.-)</div>')
	local pages = {}
	
	for page in pages_html:gmatch('href=\"(.-)\"') do
    		pages[#pages+1] = page
	end
	
	return pages
	
end

-- scraps and returns the rows of the searching table that corresponds to CVEs
local function scrapCVES(current_year, pages, cve_db)

	local num_vuln=0
	
	for k, v in pairs(pages) do

		selected_page = http.get("www.cvedetails.com", 443, v)
		-- pattern to match the links of CVEs in the table of the current page
		local cves = string.match(selected_page.body, '<table class=\"searchresults sortable\" id=\"vulnslisttable\">(.-)</table>')

	  	for row in cves:gmatch('<tr class=\"srrowns\">(.-)</tr>') do
	  		local cvss = string.match(row, '<div class=\"cvssbox\" (.-)/div>')
	  		cvss = string.match(cvss, '>(.-)<')
	  		num_vuln = num_vuln+1
	  		key = string.match(row, '/cve/(.-)/')
	  		local  db_row = {year=current_year, number=num_vuln, link=key, cvss=cvss, vendor="", product="", version="" }
	  		cve_db[key] = db_row
		end

	end
	
end

-- scraps and return the details (vendor, product and version) of each CVE
local function scrapCVEdetails(columns)

	local details = {product_type="", vendor="", product="", version=""}
	
	for index, value in pairs(columns) do
		local details_row = {}

		for column in value:gmatch('<td>(.-)</td>') do
			if string.match(column, '>(.-)</a>') ~= "Version Details" then
				if string.match(column, '>(.-)</a>') ~= nil then
					details_row[#details_row + 1] = string.match(column, '>(.-)</a>')
				elseif column ~= "" and column ~= nil then
					-- Removes blank spaces before and after words
					column = string.gsub(column, "^%s", "")
					column = string.gsub(column, "%s$", "")
					details_row[#details_row + 1] = column
				end
			end
		end

		details[#details + 1] = {product_type=details_row[1], vendor=details_row[2], product=details_row[3], version=details_row[4]}
	end

	-- removes the first row of the table because of the initialization it is empty
	table.remove(details, 1)

	local fields = {product_type="", vendor="", product="", version="", metasploit=""}
	
	-- if a field is empty, replace it with "--"
	for i=1,#details do
		if i==1 then
			fields.product_type = remove_blank(details[1].product_type == "", "--", details[1].product_type) or "--"
			fields.vendor = remove_blank(details[1].vendor == "", "--", details[1].vendor) or "--"
			fields.product = remove_blank(details[1].product == "", "--", details[1].product) or "--"
			fields.version = remove_blank(details[1].version == "", "--", details[1].version) or "--"
		else
			fields.product_type = fields.product_type..","..(remove_blank(details[i].product_type == "", "--", details[i].product_type) or "--")
			fields.vendor = fields.vendor..","..(remove_blank(details[i].vendor == "", "--", details[i].vendor) or "--")
			fields.product = fields.product..","..(remove_blank(details[i].product == "", "--", details[i].product) or "--")
			fields.version = fields.version..","..(remove_blank(details[i].version == "", "--", details[i].version) or "--")
		end
	end

	return fields
	
end

-- functions that creates the database
local function create_csv_database(from, to)

	local path
	local cve_db = {}

	local filePath = ""
	if to == nil then 
		to = from 
		filePath = "./databases/database" ..  from .. ".csv"
	else
		filePath = "./databases/database" .. from ..  "-" .. to .. ".csv"
	end
	
	local file = assert(io.open(filePath, "w"))

	for year = from, to do
		path = "/vulnerability-list.php?year=" .. year .. "&order=2"
		response = http.get("www.cvedetails.com", 443, path) 
		pages = {}
		pages = scrapPages(response)
		scrapCVES(math.floor(year), pages, cve_db)
	end

	local ordered_CVE_DB = {}

	for k in pairs(cve_db) do
	    table.insert(ordered_CVE_DB, k)
	end
	
	table.sort(ordered_CVE_DB)
	
	-- orders the database (from the oldest year to the newest one)
	for i = 1, #ordered_CVE_DB do
	    local k, v = ordered_CVE_DB[i], cve_db[ ordered_CVE_DB[i] ]
	    cve_page = http.get("www.cvedetails.com", 443, "/cve/"..ordered_CVE_DB[i].."/")
		details_table = string.match(cve_page.body, '<table class="listtable" id="vulnprodstable">(.-)</table>')
		local columns={}
		for detail in details_table:gmatch('<tr>(.-)</tr>') do
			columns[#columns+1] = detail:gsub("%s+", " ")
		end
		
		local module_link = ""
		
		-- adds the metasploit module if available
		local metasploit = string.match(cve_page.body, '<table class=\"metasploit\">(.-)</table>')
		if metasploit ~= nil then
			for metasploit_module in metasploit:gmatch('href=\"(.-)\"') do
					if module_link == "" then
						module_link = metasploit_module
					else
						module_link = module_link .. "," .. metasploit_module
					end
			end
		else
			module_link = "--"
		end

		local CVE_fields = {product_type="", vendor="", product="", version="", metasploit=""}

		CVE_fields = scrapCVEdetails(columns)
		CVE_fields.metasploit = module_link

		-- writes the info to the database file
		file:write(k .. ';' .. v.year .. ';' .. v.number .. ';' .. v.cvss .. ';' .. CVE_fields.product_type .. ';' .. CVE_fields.vendor .. ';' .. CVE_fields.product .. ';' .. CVE_fields.version .. ';' .. CVE_fields.metasploit)
    		file:write('\n')
		
		if (i % 50 == 0) then 
			print ("Creating database... " .. tostring(math.ceil(((i * 100) / #ordered_CVE_DB)*100)*0.01) ..  "% (" .. i .. "/" .. #ordered_CVE_DB .." vulnerabilities)") 
		end

	end

	print ("Database completed. " .. "100% (" .. #ordered_CVE_DB .. "/" .. #ordered_CVE_DB .." vulnerabilities)") 
	file:close()
	
end

function file_exists(name)

   	local f=io.open(name,"r")

   	if f~=nil then 
   		io.close(f) 
   		return true 
   	else 
   		return false 
   	end
   	
end

local function load_csv(name)

	local db = {}
	
	if file_exists(name) then 
		for line in io.lines(name) do
     		local cve, year, number, cvss, product_type, vendor, product, version, metasploit = line:match("(.-);%s*(.-);%s*(.-);%s*(.-);%s*(.-);%s*(.-);%s*(.-);%s*(.-);([^,]+)")
     		if product ~= "--" and version ~= "--" then
     			db[#db + 1] = { cve = cve, year = year, number = number, cvss = cvss, product_type = product_type, vendor = vendor, product = product, version = version, metasploit = metasploit }
			end
		end
		return db
	else 
		stdnse.print_debug(1, "Dabatase not found.")
		return nil
	end

end

local function parse_database()

	local csv_database = {}
	
	csv_database = load_csv("./databases/database.csv")

	if csv_database ~= nil then
		stdnse.print_debug(1, "Database loaded.")
		stdnse.print_debug(1, "Database found, searching any possible match...")
		return csv_database
	else
		return nil
	end
	
end

local function search_vulnerabilities_by_port(port, db)

	local db_name = "database.csv"
	local detected_vulns = {}
	local vulns = {}
	vulns.vulnerabilities = {}
	
	local product = port.version.product
	vulns.product = port.version.product
	vulns.version = port.version.version
	local num_vuln = 0

	if #db > 0  then

		if file_exists(string.format("./databases/%s_%s.csv", port.version.product, port.version.version)) then
			db = load_csv(string.format("./databases/%s_%s.csv", port.version.product, port.version.version))
			db_name = string.format("%s_%s.csv", port.version.product, port.version.version)
		end

		local vulnFile = io.open(string.format("./databases/%s_%s.csv", port.version.product, port.version.version), "a")
		for row in ipairs(db) do 

			local products = {}
			local versions = {}
			local ind_prod = 0
			local ind_vers = 0

			if db[row].product ~= nil then

				for cve_product in string.gmatch(db[row].product, "[^,]+") do
					ind_prod = ind_prod + 1
					products[ind_prod] = cve_product
		 		end 
		 		for cve_version in string.gmatch(db[row].version, "[^,]+") do
	   				ind_vers = ind_vers + 1
					versions[ind_vers] = cve_version	
	   			end 

	   			for j=1, #products do		
					if string.find(string.lower(products[j]), "%f[%a]" .. string.lower(port.version.product) .. "%f[%A]") and (port.version.version == versions[j]) then
						num_vuln = num_vuln + 1
						if num_vuln == 1 then
							vulns.from = db_name
							vulns.vulnerabilities[#vulns.vulnerabilities + 1] = "CVE ID          SCORE"
						end
   					
	   					local row = { cve = db[row].cve, year = db[row].year, number = db[row].number, cvss = db[row].cvss, product_type = db[row].product_type, vendor = db[row].vendor, product = db[row].product, version = db[row].version, metasploit = db[row].metasploit }
			     		if (products[j] ~= "--" and versions[j] ~= "--") and not detected_vulns[row] then
			     			table.insert(detected_vulns, row)
						end
						break
					end
				end

			end 
		end 

		if #detected_vulns > 0 then
			local orderedDatabases = {}

			for index in pairs(detected_vulns) do
			    table.insert(orderedDatabases, index)
			end

			table.sort(orderedDatabases)

			for i = 1, #orderedDatabases do
			    local k, value = orderedDatabases[i], detected_vulns[ orderedDatabases[i] ]
				if string.len(value.cve) == 14 then
					vulns.vulnerabilities[#vulns.vulnerabilities + 1] = value.cve .. "  " .. value.cvss
				elseif string.len(value.cve) == 13 then
					vulns.vulnerabilities[#vulns.vulnerabilities + 1] = value.cve .. "   " .. value.cvss
				else
					vulns.vulnerabilities[#vulns.vulnerabilities + 1] = value.cve .. "   " .. value.cvss
				end
				if vulns.from == "database.csv" then
					vulnFile:write(value.cve .. ';' .. value.year .. ';' .. value.number .. ';' .. value.cvss .. ';' .. value.product_type .. ';' .. value.vendor .. ';' .. value.product .. ';' .. value.version .. ';' .. value.metasploit)
		    		vulnFile:write('\n')
		    	end
			end
		end	

		if num_vuln == 0 then
			stdnse.print_debug(1, "Not vulnerabilities discovered in the database. Going to CVE Details to get further information...")
			
			-- Replace whitespace with "+" in multi-word products to prepare the link (e.g. "Linux Kernel" to "Linux+Kernel")
			port.version.product = string.gsub(port.version.product, "%s+", "+")
		
			--local cves_online = http.get("www.cvedetails.com", 443, "/version-search.php?vendor=&product=" .. port.version.product .."&version=" .. port.version.version)
			local cves_online = http.get_url("http://www.cvedetails.com:80/version-search.php?vendor=&product=" .. port.version.product .."&version=" .. port.version.version, 
											{redirect_ok =  function(host,port)
    															local c = 5
    															return function(url)
      																if ( c==0 ) then return false end
      																	c = c - 1
      																	return true
    																end
  															end})

			-- No matches are found
			if string.find(cves_online.body, "No matches") then
				vulns.from = "cvedetails.com"
				vulns.vulnerabilities[#vulns.vulnerabilities + 1] = "Not any match found."
			
			-- Cloudflare blocked the conection
			elseif string.find(cves_online.body, "<center>The plain HTTP request was sent to HTTPS port</center>") then
				vulns.vulnerabilities[#vulns.vulnerabilities + 1] = "Cloudflare blocked the conection. \n    Try executing the scan again to gather information about this service."
			
			-- Found matches
			elseif string.find(cves_online.body, "<div id=\"searchresults\">") then
				vulns.from = "cvedetails.com"
				local pages = scrapPages(cves_online)
				vulns.vulnerabilities[#vulns.vulnerabilities + 1] = "CVE ID          SCORE"
				for k, page in pairs(pages) do
					selected_page = http.get("www.cvedetails.com", 443, page)
					-- pattern to match the links of CVEs in the table of the current page
					local cves = string.match(selected_page.body, '<table class=\"searchresults sortable\" id=\"vulnslisttable\">(.-)</table>')
					 
	  				for row in cves:gmatch('<tr class=\"srrowns\">(.-)</tr>') do
	  					cve = string.match(row, "/cve/(.-)/")
	  					local cvss = string.match(row, '<div class=\"cvssbox\" (.-)/div>')
	  					cvss = string.match(cvss, '>(.-)<')
	  					if string.len(cve) == 14 then
			   				vulns.vulnerabilities[#vulns.vulnerabilities + 1] = cve .. "  " .. cvss
			   			elseif string.len(cve) == 13 then
							vulns.vulnerabilities[#vulns.vulnerabilities + 1] = cve .. "   " .. cvss
	   					else
	   						vulns.vulnerabilities[#vulns.vulnerabilities + 1] = cve .. "   " .. cvss
			   			end
			   			vulnFile:write(cve .. ';' .. "--" .. ";" .. "--" .. ";".. cvss .. ';' .. "--" .. ";" .. product .. ";" .. port.version.version .. ';' .. "--" .."\n")
					end
				end		
	
			-- Found partial matches
			elseif string.find(cves_online.body, "<table class=\"searchresults\">") then
				local t = {row_number="", vendor="", product="", version="", language="", update="", edition="", num_vuln="", link=""}
				vulns.from = "cvedetails.com"
				local search_table = string.match(cves_online.body, "<table class=\"searchresults\">(.-)</table>")
				-- Scrape the table to find the link with the correct CVEs 
				for row in search_table:gmatch('<tr>(.-)</tr>') do
					row = string.gsub(row, ' class=\"num\"', '')
					local columns = {}
					for column in row:gmatch('<td>(.-)</td>') do
						column = string.gsub(column, "%s+", " ")
						column = string.gsub(column, "^%s+", "")
						if string.find(column, ">Vulnerabilities</a>") then
							column = string.match(column, '&nbsp;<a href=\"(.-)\"')
						elseif string.find(column, "</a>") then
							column = string.match(column, '>(.-)</a>')
						end
						columns[#columns+1] = column
					end
	
					-- t is the logical representation of the versions' table found on the webpage 
					t[#t+1] = {row_number=columns[1], vendor=columns[2], product=columns[3], version=columns[4], language=columns[5], update=columns[6], edition=columns[7], num_vuln=columns[8], link=columns[9]}
					
				end
	
				-- Remove the first row that is all values "nil" because of the initialization
				table.remove(t, 1)
	
				-- Only matters the row with the highest number of vulnerabilities because this one includes some of the other ones
				local highest = 0
				for i=1,#t do
					 if i == 1 then
						highest = 1
					 else
					 	if tonumber(t[i].num_vuln) > tonumber(t[highest].num_vuln) then
					 		highest = i
					 	end
					 end
				end
				
				cves_online = http.get("www.cvedetails.com", 443, t[highest].link)
	
				local pages = scrapPages(cves_online)
				vulns.vulnerabilities[#vulns.vulnerabilities + 1] = "CVE ID          SCORE"

				for k, page in pairs(pages) do
					selected_page = http.get("www.cvedetails.com", 443, page)
					-- pattern to match the links of CVEs in the table of the current page
					local cves = string.match(selected_page.body, '<table class=\"searchresults sortable\" id=\"vulnslisttable\">(.-)</table>')
					
					for row in cves:gmatch('<tr class=\"srrowns\">(.-)</tr>') do
	  					cve = string.match(row, "/cve/(.-)/")
	  					local cvss = string.match(row, '<div class=\"cvssbox\" (.-)/div>')
	  					cvss = string.match(cvss, '>(.-)<')
						if string.len(cve) == 14 then
			   				vulns.vulnerabilities[#vulns.vulnerabilities + 1] = cve .. "  " .. cvss
			   			elseif string.len(cve) == 13 then
							vulns.vulnerabilities[#vulns.vulnerabilities + 1] = cve .. "   " .. cvss
	   					else
	   						vulns.vulnerabilities[#vulns.vulnerabilities + 1] = cve .. "   " .. cvss
			   			end
				   			vulnFile:write(cve .. ';' .. "--" .. ";" .. "--" .. ";".. cvss .. ';' .. "--" .. ";" .. product .. ";" .. port.version.version .. ';' .. "--" .."\n")
					end
				end	

			end

		end -- not nil

		if vulnFile:seek("end") == 0 then
			os.remove(string.format("./databases/%s_%s.csv", product, port.version.version))
		end

	else
		print("Before running a scan you must generate the file \"database.csv\".")	

	end	

	return vulns
	
end

local function findCSVFiles(path)

	local csvFiles = {}
	for file in lfs.dir ( path ) do
	    if string.find( file, "database(.-).csv" ) then
	        table.insert( csvFiles, file )
	    end
	end
	
	return csvFiles
	
end

local function mergeFiles(files)

	local databases = {}
	
	print("Merging databases...")

	if #files > 0 then

		for _,file in ipairs(files) do

			print("Loading file " .. file .. "...")
			for line in io.lines( "./databases/" .. file ) do
	     		local cve, year, number, cvss, product_type, vendor, product, version, metasploit = line:match("(.-);%s*(.-);%s*(.-);%s*(.-);%s*(.-);%s*(.-);%s*(.-);%s*(.-);([^,]+)")
	     		local row = { cve = cve, year = year, number = number, cvss = cvss, product_type = product_type, vendor = vendor, product = product, version = version, metasploit = metasploit }
	     		if (product ~= "--" and version ~= "--") and not databases[row] then
	     			databases[cve] = row
				end
			end

		end

		local orderedDatabases = {}

		for index in pairs(databases) do
		    table.insert(orderedDatabases, index)
		end

		table.sort(orderedDatabases)

		local file = assert(io.open("./databases/database.csv", "w"))

		for i = 1, #orderedDatabases do
		    local k, value = orderedDatabases[i], databases[ orderedDatabases[i] ]
			file:write(value.cve .. ';' .. value.year .. ';' .. value.number .. ';' .. value.cvss .. ';' .. value.product_type .. ';' .. value.vendor .. ';' .. value.product .. ';' .. value.version .. ';' .. value.metasploit)
	    	file:write('\n')
		end

		print("File \"database.csv\" sucessfully created.")

	else
		print("There are not valid CSV files to merge. It is necessary at least one valid database to create database.csv.")
	end
	
end

action = function(host, port)

	local last_year = 2019
	local log = assert(io.open("./cvescanner.log", "a"))

	-- This function is launched before the scan for the database manipulation
	if SCRIPT_TYPE == "prerule" then

		local years = stdnse.get_script_args("database") or nil

		if years ~= nil then
			local from, to = string.match(years, "(%d+)-(%d+)")

			if from == nil and to == nil then
				from = string.match(years, "(%d+)") 
				date = from
			else
				date = string.format("%s-%s", from, to)	
			end
	
			if from ~= nil and type(tonumber(from)) == "number" then
				if (tonumber(from) >= 1999 and tonumber(from) <= last_year) and (to == nil or (tonumber(to) >= 1999 and tonumber(to) <= last_year)) then
					stdnse.print_debug(1, "Years in allowed range.")
					create_csv_database(from, to)
					log:write(string.format("[%s] INFO: File database%s.csv created.\n", os.date("%Y-%m-%d %H:%M:%S"), date))
					log:close()
					stdnse.print_debug(1, "Database sucessfully created.")
				else
					print(string.format("One of the year(s) is not in the allowed range [1999-%s]"), last_year)
					log:write(string.format("[%s] INFO: One of the year(s) is not in the allowed range [1999-%s].\n", os.date("%Y-%m-%d %H:%M:%S"), last_year))
					log:close()
				end
			end
		end

		if stdnse.get_script_args("merge-database") == "1" and file_exists("./databases/database.csv") then
			print("The file database.csv already exists.")
			log:write(string.format("[%s] INFO: File database.csv already exists.\n", os.date("%Y-%m-%d %H:%M:%S")))
			log:close()
			return
		elseif stdnse.get_script_args("merge-database") == "1" then
			local files = findCSVFiles("./databases/")
			mergeFiles(files)
			log:write(string.format("[%s] INFO: File database.csv created after merging database files.\n", os.date("%Y-%m-%d %H:%M:%S")))
			log:close()
			return
		end

		if stdnse.get_script_args("merge-database") == nil and stdnse.get_script_args("database") == nil then
			log:write(string.format("[%s] INFO: Starting CVE scanning...\n", os.date("%Y-%m-%d %H:%M:%S")))
			log:close()
		end

	-- This function is launched for every open port with available information
	elseif SCRIPT_TYPE == "portrule" then

		if stdnse.get_script_args("merge-database") ~= '1' then
			local output = stdnse.output_table()
			local database = parse_database()
			if database == nil then print("Database not found.") end
		
			-- then search for vulnerabilities in the database
			-- if no result matched, make a request to the following URL to search into online vulnerabilities
			-- ==> https://www.cvedetails.com/version-search.php?vendor=&product=elasticsearch&version=
			-- fill the CSV if any online information is discovered
			local vulns = {}
			vulns = search_vulnerabilities_by_port(port, database)

			if #vulns.vulnerabilities > 0 then
				output.product = vulns.product
				output.version = vulns.version
				output.from = vulns.from
				output.vulnerabilities = #vulns.vulnerabilities - 1
				output.vulns = vulns.vulnerabilities
				if output.vulnerabilities > 0 then
					log:write(string.format("[%s] INFO: Scan completed. Found %d vulnerabilities for %s %s in %s.", os.date("%Y-%m-%d %H:%M:%S"), output.vulnerabilities, vulns.product, vulns.version, vulns.from), "\n")
				else
					log:write(string.format("[%s] INFO: Scan completed. No results found for %s %s in http://www.cvedetails.com", os.date("%Y-%m-%d %H:%M:%S"), vulns.product, vulns.version), "\n")
				end
				log:close()
				return output
			else
				output.vulnerabilities = "No results found."
				
			end
		end 

	end

end
