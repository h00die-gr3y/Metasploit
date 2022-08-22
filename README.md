# Metasploit Private Module Development
This repository contains private developed Metasploit modules that can be reused freely.

## Modules Installation
1. Copy the files with the rb extension to your local Metasploit module directory -> ~/.msf4/modules/...
2. Restart Metasploit to see the module or reload the modules with command reload_all
3. See also https://docs.metasploit.com/docs/using-metasploit/intermediate/running-private-modules.html

## Module listing
* auxiliary/admin/http/hikvision_unauth_pwd_reset.rb
* exploits/linux/http/apache_spark_exec.rb

## Module details

### auxiliary/admin/http/hikvision_unauth_pwd_reset.rb
Unauthenticated password change for any user configured at a vulnerable Hikvision IP Camera.

Many Hikvision IP cameras contain a backdoor that allows unauthenticated impersonation of any configured user account. The vulnerability has been present in Hikvision products since 2014. In addition to Hikvision-branded devices, it affects many white-labeled camera products sold under a variety of brand names. Hundreds of thousands of vulnerable devices are still exposed to the Internet at the time of publishing (shodan search: App-webs 200 OK product:"Hikvision IP Camera" port:"80"). 

This module allows the attacker to perform an unauthenticated password change of any vulnerable Hikvision IP Camera to gaining full administrative access. The vulnerability can be exploited for all configured users.

**Installation:**
```
# cp hikvision_unauth_pwd_reset.rb ~/.msf4/modules/auxiliary/admin/http
# msfconsole
msf6> reload_all
```

### exploits/linux/http/apache_spark_exec.rb
This module exploits an unauthenticated command injection vulnerability in Apache Spark. Successful exploitation results in remote code execution under the context of the Spark application user. The command injection occurs because Spark checks the group membership of the user passed in the ?doAs parameter by using a raw Linux command. It is triggered by a non-default setting called `spark.acls.enable`. This configuration setting `spark.acls.enable` should be set **true** in the Spark configuration to make the application vulnerable for this attack. 

Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1 are affected by this vulnerability.

**Installation:**
```
# cp apache_spark_exec.rb ~/.msf4/modules/exploits/linux/http
# msfconsole
msf6> reload_all
```
