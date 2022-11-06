# Metasploit Private Module Development
This repository contains private developed Metasploit modules that can be reused freely.

## Modules Installation
1. Copy the files with the rb extension to your local Metasploit module directory -> ~/.msf4/modules/...
2. Restart Metasploit to see the module or reload the modules with command reload_all
3. See also https://docs.metasploit.com/docs/using-metasploit/intermediate/running-private-modules.html

## Module listing
* auxiliary/admin/http/hikvision_unauth_pwd_reset.rb
* exploit/linux/http/apache_spark_exec.rb
* exploit/unix/http/pfsense_pfblockerng_rce_cve_2022_31814.rb
* exploit/linux/http/flir_ax8_unauth_rce_cve_2022_37061.rb
* exploit/linux/http/vmware_nsxmgr_xstream_rce_cve_2021_39144.rb

## Module details

### auxiliary/admin/http/hikvision_unauth_pwd_reset.rb
Unauthenticated password change for any user configured at a vulnerable Hikvision IP Camera.

Many Hikvision IP cameras contain a backdoor that allows unauthenticated impersonation of any configured user account. The vulnerability has been present in Hikvision products since 2014. In addition to Hikvision-branded devices, it affects many white-labeled camera products sold under a variety of brand names. Hundreds of thousands of vulnerable devices are still exposed to the Internet at the time of publishing (shodan search: `App-webs 200 OK product:"Hikvision IP Camera" port:"80"`). 

This module allows the attacker to perform an unauthenticated password change of any vulnerable Hikvision IP Camera to gaining full administrative access. The vulnerability can be exploited for all configured users.

**Installation:**
```
# cp hikvision_unauth_pwd_reset.rb ~/.msf4/modules/auxiliary/admin/http
# msfconsole
msf6> reload_all
```
**UPDATE September 30, 2022:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:
`auxiliary/admin/http/hikvision_unauth_pwd_reset_cve_2017_7921`

https://www.rapid7.com/blog/post/2022/09/30/metasploit-weekly-wrap-up-178/

### exploits/linux/http/apache_spark_exec.rb
This module exploits an unauthenticated command injection vulnerability in Apache Spark. Successful exploitation results in remote code execution under the context of the Spark application user. The command injection occurs because Spark checks the group membership of the user passed in the ?doAs parameter by using a raw Linux command. It is triggered by a non-default setting called `spark.acls.enable`. This configuration setting `spark.acls.enable` should be set **true** in the Spark configuration to make the application vulnerable for this attack. 

Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1 are affected by this vulnerability.

**Installation:**
```
# cp apache_spark_exec.rb ~/.msf4/modules/exploits/linux/http
# msfconsole
msf6> reload_all
```
**UPDATE September 13, 2022:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/linux/http/apache_spark_rce_cve_2022_33891`

https://www.rapid7.com/blog/post/2022/09/09/metasploit-weekly-wrap-up-175/

### exploit/unix/http/pfsense_pfblockerng_rce_cve_2022_31814.rb
unauthenticated Remote Command Execution as root in the pfSense pfBlockerNG plugin.

This module exploits an unauthenticated Remote Command Execution as root in the pfSense pfBlockerNG plugin (CVE-2022-31814). The vulnerability affects versions of pfBlockerNG <= 2.1.4_26 and can be exploited by an un authenticated user gaining root access.
pfBlockerNG is a pfSense plugin that is NOT installed by default and it’s generally used to block inbound connections from wholecountries or IP ranges. This module uses the vulnerability to upload and execute payloads gaining root privileges.

**Installation:**
```
# cp pfsense_pfblockerng_rce_cve_2022_31814.rb ~/.msf4/modules/exploits/unix/http/
# msfconsole
msf6> reload_all
```
**UPDATE October 14, 2022:**<br />
Similar module is now available at the main stream of Metasploit.<br />
`exploit/unix/http/pfsense_pfblockerng_webshell`

https://www.rapid7.com/blog/post/2022/10/14/metasploit-wrap-up-155/

### exploit/linux/http/flir_ax8_unauth_rce_cve_2022_37061.rb
FLIR AX8 is affected by an unauthenticated remote command injection vulnerability.

FLIR AX8 is a thermal sensor with imaging capabilities, combining thermal and visual cameras that provides continuous temperature monitoring and alarming for critical electrical and mechanical equipment.

All FLIR AX8 thermal sensor cameras versions up to and including `1.46.16` are vulnerable to Remote Command Injection.<br />
This can be exploited to inject and execute arbitrary shell commands as the root user through the id HTTP POST parameter in the `res.php` endpoint.
This module uses the vulnerability to upload and execute payloads gaining root privileges.

**Installation:**
```
# cp flir_ax8_unauth_rce_cve_2022_37061.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```

### exploit/linux/http/vmware_nsxmgr_xstream_rce_cve_2021_39144.rb
VMware Cloud Foundation (NSX-V) contains a remote code execution vulnerability via XStream open source library.<br />
Due to an unauthenticated endpoint that leverages XStream for input serialization in VMware Cloud Foundation (NSX-V), a malicious actor can get remote code execution in the context of `root` on the appliance.<br />
VMware Cloud Foundation `3.x` and more specific NSX Manager Data Center for vSphere up to and including version `6.4.13` are vulnerable to Remote Command Injection.<br /><br />
This module exploits the vulnerability to upload and execute payloads gaining root privileges.

**Installation:**
```
# cp vmware_nsxmgr_xstream_rce_cve_2021_39144.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
