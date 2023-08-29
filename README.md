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
* exploit/linux/http/linear_emerge_unauth_rce_cve_2019_7256.rb
* exploit/linux/http/ivanti_csa_unauth_rce_cve_2021_44529.rb
* exploit/linux/http/control_web_panel_unauth_rce_cve_2022_44877.rb
* exploit/linux/http/sugarcrm_webshell_cve_2023_22952.rb
* exploit/linux/http/optergy_bms_backdoor_rce_cve_2019_7276.rb
* exploit/multi/http/bash_env_cgi_rce.rb
* exploit/linux/http/terramaster_unauth_rce_cve_2020_35665.rb
* exploit/linux/http/terramaster_unauth_rce_cve_2021_45837.rb
* exploit/linux/http/terramaster_unauth_rce_cve_2022_24990.rb
* exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315.rb
* exploit/multi/http/wp_plugin_fma_shortcode_unauth_rce.rb
* exploit/linux/http/chamilo_unauth_rce_cve_2023_34960.rb

## Module details

### auxiliary/admin/http/hikvision_unauth_pwd_reset.rb
Unauthenticated password change for any user configured at a vulnerable Hikvision IP Camera.

Many Hikvision IP cameras contain a backdoor that allows unauthenticated impersonation of any configured user account. The vulnerability has been present in Hikvision products since 2014. In addition to Hikvision-branded devices, it affects many white-labeled camera products sold under a variety of brand names. Hundreds of thousands of vulnerable devices are still exposed to the Internet at the time of publishing (shodan search: `App-webs 200 OK product:"Hikvision IP Camera" port:"80"`). 

This module allows the attacker to perform an unauthenticated password change of any vulnerable Hikvision IP Camera to gaining full administrative access. The vulnerability can be exploited for all configured users.

**Installation:**
```console
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
```console
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
```console
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
```console
# cp flir_ax8_unauth_rce_cve_2022_37061.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE November 4, 2022:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/linux/http/flir_ax8_unauth_rce_cve_2022_37061`

https://www.rapid7.com/blog/post/2022/11/04/metasploit-weekly-wrap-up-182/

### exploit/linux/http/vmware_nsxmgr_xstream_rce_cve_2021_39144.rb
VMware Cloud Foundation (NSX-V) contains a remote code execution vulnerability via XStream open source library.<br />
Due to an unauthenticated endpoint that leverages XStream for input serialization in VMware Cloud Foundation (NSX-V), a malicious actor can get remote code execution in the context of `root` on the appliance.<br />
VMware Cloud Foundation `3.x` and more specific NSX Manager Data Center for vSphere up to and including version `6.4.13` are vulnerable to Remote Command Injection.<br /><br />
This module exploits the vulnerability to upload and execute payloads gaining root privileges.

**Installation:**
```console
# cp vmware_nsxmgr_xstream_rce_cve_2021_39144.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE November 18, 2022:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/linux/http/vmware_nsxmgr_xstream_rce_cve_2021_39144`

https://www.rapid7.com/blog/post/2022/11/18/metasploit-weekly-wrap-up-184/

### exploit/linux/http/linear_emerge_unauth_rce_cve_2019_7256.rb
Nortek Security & Control, LLC (NSC) is a leader in wireless security, home automation and personal safety systems and devices. The eMerge E3-Series is part of Linear’s access control platform, that delivers entry-level access control to buildings.<br />
It is a web based application where the HTTP web interface is typically exposed to the public internet.<br />

The Linear eMerge E3-Series with firmware versions `1.00-06` and below are vulnerable to an unauthenticated command injection remote root exploit that leverages card_scan_decoder.php.<br />
This can be exploited to inject and execute arbitrary shell commands as the root user through the No and door HTTP GET parameter.<br />
A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system with the root privileges.<br />

Building automation and access control systems are at the heart of many critical infrastructures, and their security is vital.<br />
Executing attacks on these systems may enable unauthenticated attackers to access and manipulate doors, elevators, air-conditioning systems, cameras, boilers, lights, safety alarm systems within a building.<br />

This issue affects all Linear eMerge E3 versions up to and including `1.00-06`.<br />

**Installation:**
```console
# cp linear_emerge_unauth_rce_cve_2019_7256.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE January 06, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/linux/http/linear_emerge_unauth_rce_cve_2019_7256`

https://www.rapid7.com/blog/post/2023/01/06/metasploit-weekly-wrap-up-4/

### exploit/linux/http/ivanti_csa_unauth_rce_cve_2021_44529.rb
This module exploits a command injection vulnerability in the Ivanti Cloud Services Appliance (CSA)for Ivanti Endpoint Manager.<br />
A cookie based code injection vulnerability in the Cloud Services Appliance before `4.6.0-512` allows an unauthenticated user
to execute arbitrary code with limited permissions.<br />
Successful exploitation results in command execution as the `nobody` user.<br />

**Installation:**
```console
# cp ivanti_csa_unauth_rce_cve_2021_44529.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE January 20, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/linux/http/ivanti_csa_unauth_rce_cve_2021_44529.rb`

https://www.rapid7.com/blog/post/2023/01/20/metasploit-weekly-wrap-up-189/

### exploit/linux/http/control_web_panel_unauth_rce_cve_2022_44877.rb
This module exploits a remote command execution vulnerability in the Control Web Panel (CWP) application.<br />
The vulnerability allows an unauthenticated user to execute arbitrary code by using a special POST login request
that creates a failed login entry in the `/var/log/cwp.log` using double quotes.<br />
The vulnerable endpoint is the admin login `/login/index.php?login=` which typically runs on port `2030` or `2086` for `http` and
port `2031` and port `2087` for `https`. Successful exploitation results in command execution as the `root` user.<br />
CWP versions `0.9.8.1146` and below are vulnerable.

**Installation:**
```console
# cp control_web_panel_unauth_rce_cve_2022_44877.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
### exploit/linux/http/sugarcrm_webshell_cve_2023_22952.rb
This module exploits a Remote Code Execution vulnerability that has been identified in the SugarCRM application.<br />
Using a specially crafted request, custom PHP code can be uploaded and injected through the EmailTemplates because of missing input validation.
Any user privileges can exploit this vulnerability and it results in access to the underlying operating system with the same privileges
under which the web services run (typically user www-data).
SugarCRM 11.0 Professional, Enterprise, Ultimate, Sell and Serve versions `11.0.4` and below are affected. Fixed in release `11.0.5`.<br />
SugarCRM 12.0 Enterprise, Sell and Serve versions `12.0.1` and below are affected. Fixed in release `12.0.2`.<br />

**Installation:**
```console
# cp sugarcrm_webshell_cve_2023_22952.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE March 10, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/multi/http/sugarcrm_webshell_cve_2023_22952.rb`

https://www.rapid7.com/blog/post/2023/03/10/metasploit-weekly-wrap-up-196/

### exploit/linux/http/optergy_bms_backdoor_rce_cve_2019_7276.rb
This module exploits an undocumented backdoor vulnerability in the Optergy Proton and Enterprise Building Management System (BMS) applications. Versions `2.0.3a` and below are vulnerable.
Attackers can exploit this issue by directly navigating to an undocumented backdoor script called `Console.jsp` in the tools directory and gain full system access.
Successful exploitation results in `root` command execution using `sudo` as user `optergy`.

**Installation:**
```console
# cp optergy_bms_backdoor_rce_cve_2019_7276.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE March 31, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/linux/http/optergy_bms_backdoor_rce_cve_2019_7276.rb`

https://www.rapid7.com/blog/post/2023/03/31/metasploit-weekly-wrap-up-198/

### exploit/multi/http/bash_env_cgi_rce.rb
This module exploits the Shellshock vulnerability, a flaw in how the Bash shell handles external environment variables. This module targets CGI scripts in web servers by setting the `HTTP_USER_AGENT` environment variable to a malicious function definition.

**Installation:**
```console
# cp bash_env_cgi_rce.rb ~/.msf4/modules/exploits/multi/http/
# msfconsole
msf6> reload_all
```
### exploit/linux/http/terramaster_unauth_rce_cve_2020_35665.rb a.k.a. TerrorMaster 1
This module is exploiting a vulnerability described in [CVE-2020-35665](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35665) or [CVE-2020-28188](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28188) that allows an unauthenticated attacker to upload a webshell via shell metacharacters in the `Event` parameter using the vulnerable endpoint `include/makecvs.php` during the `CSV` creation process.
See this [AttackerKB Article](https://attackerkb.com/topics/lXY4yjOvwx/cve-2020-35665) for more details.

Because of this, any remote attacker, regardless of authentication, can exploit this vulnerability to gain access to the underlying operating system as the user that the web services are running as (typically `root` in case of TerraMaster).

**Installation:**
```console
# cp terramaster_unauth_rce_cve_2020_35665.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
### exploit/linux/http/terramaster_unauth_rce_cve_2021_45837.rb a.k.a. TerrorMaster 2
This module provides a Terramaster chained exploit that performs session crafting to achieve escalated privileges that allows an attacker to access vulnerable code execution flaws. TOS versions `4.2.15` and below  are affected. 

[CVE-2021-45839](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45839) is exploited to obtain the first administrator's hash set up on the system as well as other information such as MAC address, by performing a `POST` request to the `/module/api.php?mobile/webNasIPS` endpoint.
This information is used to craft an unauthenticated admin session using [CVE-2021-45841](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45841) where an attacker can self-sign session cookies by knowing the target MAC address and the user password hash.
Guest users (disabled by default) can be abused using a null/empty hash and allow an unauthenticated attacker to login as guest which is used to download the `/etc/group` info to obtain the list of admin users, used to establish an unauthenticated admin session thru session crafting.

Finally, [CVE-2021-45837](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45837) is exploited to execute arbitrary commands as root by sending a specifically crafted input to vulnerable endpoint `/tos/index.php?app/del`.
See this [AttackerKB Article](https://attackerkb.com/topics/8rNXrrjQNy/cve-2021-45837) for more details.

**Installation:**
```console
# cp terramaster_unauth_rce_cve_2021_45837.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
### exploit/linux/http/terramaster_unauth_rce_cve_2022_24990.rb a.k.a. TerrorMaster 3
This module exploits an unauthenticated remote code execution vulnerability in TerraMaster TOS `4.2.29` and lower by chaining two existing vulnerabilities, [CVE-2022-24990: Leaking sensitive information](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24990) and [CVE-2022-24989: Authenticated remote code execution](https://www.redpacketsecurity.com/terramaster-tos-command-execution-cve-2022-24989/).
Exploiting vulnerable endpoint `api.php?mobile/webNasIPS` leaking sensitive information such as admin password hash and mac address, the attacker can achieve unauthenticated access and use another vulnerable endpoint `api.php?mobile/createRaid` with POST parameters `raidtype` and `diskstring` to upload a webshell and execute remote code as root on TerraMaster NAS devices.

See this [AttackerKB Article](https://attackerkb.com/topics/h8YKVKx21t/cve-2022-24990) for more details.

**Installation:**
```console
# cp terramaster_unauth_rce_cve_2022_24990.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE Jue 16, 2023:**<br />
All TerraMaster modules have been added to the main stream of Metasploit and are now available under same the module names<br />

https://www.rapid7.com/blog/post/2023/06/16/metasploit-weekly-wrap-up-15/

### exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315.rb
`Openfire's` administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment using the path `http://localhost:9090/setup/setup-s/%u002e%u002e/%u002e%u002e/`. Endpoints such as `log.jsp`, `user-groups.jsp` and `user-create.jsp` can be used to gain unauthorized admin access.
It allows an unauthenticated user to use the unauthenticated `Openfire` Setup Environment in an already configured `Openfire` environment to access restricted pages in the `Openfire Admin Console` reserved for administrative users.

This module will use the vulnerability to create a new admin user that will be used to upload a `Openfire` management plugin weaponized with a `Java` native payload that triggers an RCE. The vulnerability affects all versions of `Openfire` that have been released since April 2015, starting with version `3.10.0`.
The problem has been patched in `Openfire` release `4.7.5` and `4.6.8`, and further improvements will be included in the first version on the `4.8` branch, which is version `4.8.0`.

See this [AttackerKB Article](https://attackerkb.com/topics/7Tf5YGY3oT/cve-2023-32315) for more details.

**Installation:**
```console
# cp openfire_auth_bypass_rce_cve_2023_32315.rb ~/.msf4/modules/exploits/multi/http/
# msfconsole
msf6> reload_all
```
**UPDATE July 21, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315`

https://www.rapid7.com/blog/post/2023/07/21/metasploit-weekly-wrap-up-20/

### exploit/multi/http/wp_plugin_fma_shortcode_unauth_rce.rb
The Wordpress plugin does not adequately prevent uploading files with disallowed MIME types when using the shortcode.
This leads to RCE in cases where the allowed MIME type list does not include PHP files.
In the worst case, this is available to unauthenticated users, but is also works in an authenticated configuration.
File Manager Advanced Shortcode plugin version `2.3.2` and lower are vulnerable.
To install the Shortcode plugin File Manager Advanced version `5.0.5` or lower is required to keep the configuration vulnerable. 
Any user privileges can exploit this vulnerability which results in access to the underlying operating system with the same privileges under which the Wordpress web services run.

See this [AttackerKB Article](https://attackerkb.com/topics/JncRCWZ5xm/cve-2023-2068) for more details.

**Installation:**
```console
# cp wp_plugin_fma_shortcode_unauth_rce.rb ~/.msf4/modules/exploits/multi/http/
# msfconsole
msf6> reload_all
```
**UPDATE July 28, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/multi/http/wp_plugin_fma_shortcode_unauth_rce`

https://www.rapid7.com/blog/post/2023/07/28/metasploit-weekly-wrap-up-21/

### exploit/linux/http/chamilo_unauth_rce_cve_2023_34960.rb
`Chamilo` is an e-learning platform, also called Learning Management Systems (LMS).
This module exploits an unauthenticated remote command execution vulnerability that affects `Chamilo` versions `1.11.18` and below. See also [CVE-2023-34960](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34960). 
Due to a functionality called `Chamilo Rapid` to easily convert PowerPoint slides to courses on `Chamilo`, it is possible for an unauthenticated remote attacker to execute arbitrary commands at OS level using a malicious SOAP request at the vulnerable endpoint `/main/webservices/additional_webservices.php`.

Read this [article](https://attackerkb.com/topics/VVJpMeSpUP/cve-2023-34960) on attackerkb.com for more details.

**Installation:**
```console
# cp chamilo_unauth_rce_cve_2023_34960.rb ~/.msf4/modules/exploits/linux/http/
# msfconsole
msf6> reload_all
```
**UPDATE August 25, 2023:**<br />
This module has been added to the main stream of Metasploit and is now available under the module name:<br />
`exploit/linux/http/chamilo_unauth_rce_cve_2023_34960`

https://www.rapid7.com/blog/post/2023/08/25/metasploit-weekly-wrap-up-24/
