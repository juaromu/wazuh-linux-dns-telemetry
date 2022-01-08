
**DNS TELEMETRY IN LINUX WITH PACKETBEAT**

## 


## Intro

Capturing DNS telemetry in Linux using Elastic’s Packetbeat and output collected events to Wazuh manager.


## Install Packetbeat.


```
curl -L -O https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-7.16.2-amd64.deb
sudo dpkg -i packetbeat-7.16.2-amd64.deb
```


Create Packetbeat Yaml config file, “/etc/packetbeat/packetbeat.yml”


```
#################### Packetbeat Configuration Example #########################

# This file is an example configuration file highlighting only the most common
# options. The packetbeat.reference.yml file from the same directory contains all the
# supported options with more comments. You can use it as a reference.
#
# You can find the full configuration reference here:
# https://www.elastic.co/guide/en/beats/packetbeat/index.html

# =============================== Network device ===============================

# Select the network interface to sniff the data. On Linux, you can use the
# "any" keyword to sniff on all connected interfaces.
packetbeat.interfaces.device: any

# The network CIDR blocks that are considered "internal" networks for
# the purpose of network perimeter boundary classification. The valid
# values for internal_networks are the same as those that can be used
# with processor network conditions.
#
# For a list of available values see:
# https://www.elastic.co/guide/en/beats/packetbeat/current/defining-processors.html#condition-network
packetbeat.interfaces.internal_networks:
  - private

# =================================== Flows ====================================

# Set `enabled: false` or comment out all options to disable flows reporting.
packetbeat.flows:
  # Set network flow timeout. Flow is killed if no packet is received before being
  # timed out.
  timeout: 30s
  enabled: false
  # Configure reporting period. If set to -1, only killed flows will be reported
  period: 10s

# =========================== Transaction protocols ============================

packetbeat.protocols:
- type: icmp
  # Enable ICMPv4 and ICMPv6 monitoring. The default is true.
  enabled: false

- type: amqp
  # Configure the ports where to listen for AMQP traffic. You can disable
  # the AMQP protocol by commenting out the list of ports.
#  ports: [5672]

- type: cassandra
  # Configure the ports where to listen for Cassandra traffic. You can disable
  # the Cassandra protocol by commenting out the list of ports.
#  ports: [9042]

- type: dhcpv4
  # Configure the DHCP for IPv4 ports.
#  ports: [67, 68]

- type: dns
  # Configure the ports where to listen for DNS traffic. You can disable
  # the DNS protocol by commenting out the list of ports.
  ports: [53]

- type: http
  # Configure the ports where to listen for HTTP traffic. You can disable
  # the HTTP protocol by commenting out the list of ports.
#  ports: [80, 8080, 8000, 5000, 8002]

- type: memcache
  # Configure the ports where to listen for memcache traffic. You can disable
  # the Memcache protocol by commenting out the list of ports.
#  ports: [11211]

- type: mysql
  # Configure the ports where to listen for MySQL traffic. You can disable
  # the MySQL protocol by commenting out the list of ports.
#  ports: [3306,3307]

- type: pgsql
  # Configure the ports where to listen for Pgsql traffic. You can disable
  # the Pgsql protocol by commenting out the list of ports.
#  ports: [5432]

- type: redis
  # Configure the ports where to listen for Redis traffic. You can disable
  # the Redis protocol by commenting out the list of ports.
#  ports: [6379]

- type: thrift
  # Configure the ports where to listen for Thrift-RPC traffic. You can disable
  # the Thrift-RPC protocol by commenting out the list of ports.
#  ports: [9090]

- type: mongodb
  # Configure the ports where to listen for MongoDB traffic. You can disable
  # the MongoDB protocol by commenting out the list of ports.
#  ports: [27017]

- type: nfs
  # Configure the ports where to listen for NFS traffic. You can disable
  # the NFS protocol by commenting out the list of ports.
#  ports: [2049]

- type: tls
  # Configure the ports where to listen for TLS traffic. You can disable
  # the TLS protocol by commenting out the list of ports.
#  ports:
#    - 443   # HTTPS
#    - 993   # IMAPS
#    - 995   # POP3S
#    - 5223  # XMPP over SSL
#    - 8443
#    - 8883  # Secure MQTT
#    - 9243  # Elasticsearch

- type: sip
  # Configure the ports where to listen for SIP traffic. You can disable
  # the SIP protocol by commenting out the list of ports.
#  ports: [5060]

# ======================= Elasticsearch template setting =======================

setup.template.settings:
  index.number_of_shards: 1
  #index.codec: best_compression
  #_source.enabled: false

# ================================== General ===================================

# The name of the shipper that publishes the network data. It can be used to group
# all the transactions sent by a single shipper in the web interface.
#name:

# A list of tags to include in every event. In the default configuration file
# the forwarded tag causes Packetbeat to not add any host fields. If you are
# monitoring a network tap or mirror port then add the forwarded tag.
#tags: [forwarded]

# Optional fields that you can specify to add additional information to the
# output.
#fields:
#  env: staging

# ================================= Dashboards =================================
# These settings control loading the sample dashboards to the Kibana index. Loading
# the dashboards is disabled by default and can be enabled either by setting the
# options here or by using the `setup` command.
#setup.dashboards.enabled: false

# The URL from where to download the dashboards archive. By default this URL
# has a value which is computed based on the Beat name and version. For released
# versions, this URL points to the dashboard archive on the artifacts.elastic.co
# website.
#setup.dashboards.url:

# =================================== Kibana ===================================

# Starting with Beats version 6.0.0, the dashboards are loaded via the Kibana API.
# This requires a Kibana endpoint configuration.
setup.kibana:

  # Kibana Host
  # Scheme and port can be left out and will be set to the default (http and 5601)
  # In case you specify and additional path, the scheme is required: http://localhost:5601/path
  # IPv6 addresses should always be defined as: https://[2001:db8::1]:5601
  #host: "localhost:5601"

  # Kibana Space ID
  # ID of the Kibana Space into which the dashboards should be loaded. By default,
  # the Default Space will be used.
  #space.id:

# =============================== Elastic Cloud ================================

# These settings simplify using Packetbeat with the Elastic Cloud (https://cloud.elastic.co/).

# The cloud.id setting overwrites the `output.elasticsearch.hosts` and
# `setup.kibana.host` options.
# You can find the `cloud.id` in the Elastic Cloud web UI.
#cloud.id:

# The cloud.auth setting overwrites the `output.elasticsearch.username` and
# `output.elasticsearch.password` settings. The format is `<user>:<pass>`.
#cloud.auth:

# ================================== Outputs ===================================

# Configure what output to use when sending the data collected by the beat.

# ---------------------------- Elasticsearch Output ----------------------------
#output.elasticsearch:
  # Array of hosts to connect to.
#  hosts: ["localhost:9200"]

  # Protocol - either `http` (default) or `https`.
  #protocol: "https"

  # Authentication credentials - either API key or username/password.
  #api_key: "id:api_key"
  #username: "elastic"
  #password: "changeme"

# ------------------------------ Logstash Output -------------------------------
#output.logstash:
  # The Logstash hosts
  #hosts: ["localhost:5044"]

  # Optional SSL. By default is off.
  # List of root certificates for HTTPS server verifications
  #ssl.certificate_authorities: ["/etc/pki/root/ca.pem"]

  # Certificate for SSL client authentication
  #ssl.certificate: "/etc/pki/client/cert.pem"

  # Client Certificate Key
  #ssl.key: "/etc/pki/client/cert.key"

# ================================= Processors =================================
# -------------------------------- File Output ---------------------------------
output.file:
  # Boolean flag to enable or disable the output module.
  enabled: true

  # Configure JSON encoding
  codec.json:
    # Pretty-print JSON event
    #pretty: false

    # Configure escaping HTML symbols in strings.
    #escape_html: false

  # Path to the directory where to save the generated files. The option is
  # mandatory.
  path: "/var/log/"

  # Name of the generated files. The default is `packetbeat` and it generates
  # files: `packetbeat`, `packetbeat.1`, `packetbeat.2`, etc.
  #filename: packetbeat

  # Maximum size in kilobytes of each file. When this size is reached, and on
  # every Packetbeat restart, the files are rotated. The default value is 10240
  # kB.
  #rotate_every_kb: 10000

  # Maximum number of files under path. When this number of files is reached,
  # the oldest file is deleted and the rest are shifted from last to first. The
  # default is 7 files.
  #number_of_files: 7

  # Permissions to use for file creation. The default is 0600.
  #permissions: 0600
# ================================= Processors =================================

processors:
  - # Add forwarded to tags when processing data from a network tap or mirror.
    if.contains.tags: forwarded
    then:
      - drop_fields:
          fields: [host]
    else:
      - add_host_metadata: ~
  - add_cloud_metadata: ~
  - add_docker_metadata: ~
  - detect_mime_type:
      field: http.request.body.content
      target: http.request.mime_type
  - detect_mime_type:
      field: http.response.body.content
      target: http.response.mime_type

# ================================== Logging ===================================

# Sets log level. The default log level is info.
# Available log levels are: error, warning, info, debug
#logging.level: debug

# At debug level, you can selectively enable logging only for some components.
# To enable all selectors use ["*"]. Examples of other selectors are "beat",
# "publisher", "service".
#logging.selectors: ["*"]

# ============================= X-Pack Monitoring ==============================
# Packetbeat can export internal metrics to a central Elasticsearch monitoring
# cluster.  This requires xpack monitoring to be enabled in Elasticsearch.  The
# reporting is disabled by default.

# Set to true to enable the monitoring reporter.
#monitoring.enabled: false

# Sets the UUID of the Elasticsearch cluster under which monitoring data for this
# Packetbeat instance will appear in the Stack Monitoring UI. If output.elasticsearch
# is enabled, the UUID is derived from the Elasticsearch cluster referenced by output.elasticsearch.
#monitoring.cluster_uuid:

# Uncomment to send the metrics to Elasticsearch. Most settings from the
# Elasticsearch output are accepted here as well.
# Note that the settings should point to your Elasticsearch *monitoring* cluster.
# Any setting that is not set is automatically inherited from the Elasticsearch
# output configuration, so if you have the Elasticsearch output configured such
# that it is pointing to your Elasticsearch monitoring cluster, you can simply
# uncomment the following line.
#monitoring.elasticsearch:

# ============================== Instrumentation ===============================

# Instrumentation support for the packetbeat.
#instrumentation:
    # Set to true to enable instrumentation of packetbeat.
    #enabled: false

    # Environment in which packetbeat is running on (eg: staging, production, etc.)
    #environment: ""

    # APM Server hosts to report instrumentation results to.
    #hosts:
    #  - http://localhost:8200

    # API Key for the APM Server(s).
    # If api_key is set then secret_token will be ignored.
    #api_key:

    # Secret token for the APM Server(s).
    #secret_token:


# ================================= Migration ==================================

# This allows to enable 6.7 migration aliases
#migration.6_to_7.enabled: true
```


With the config above we disable capturing telemetry for all protocols except DNS.

In the output section we tell packetbeat to log to a local file (“/var/log/packetbeat”).


## Wazuh Agent configuration (can be done centralised on the Wazuh manager):


```
    <localfile>
      <log_format>json</log_format>
      <location>/var/log/packetbeat</location>
    </localfile>
```



## Rules in Wazuh Manager.


```
<group name="linux,packetbeat,dns">
    <rule id="200300" level="3">
        <decoded_as>json</decoded_as>
        <field name="method">QUERY</field>
        <mitre>
          <id>T1071</id>
        </mitre>
        <description>Linux: DNS Query</description>
        <options>no_full_log</options>
    </rule>
</group>
```


Alert (example): 


```
{
   "timestamp":"2022-01-08T10:27:41.666+0000",
   "rule":{
      "level":3,
      "description":"Linux: DNS Query",
      "id":"200300",
      "mitre":{
         "id":[
            "T1071"
         ],
         "tactic":[
            "Command and Control"
         ],
         "technique":[
            "Standard Application Layer Protocol"
         ]
      },
      "firedtimes":641,
      "mail":false,
      "groups":[
         "linux",
         "packetbeat",
         "dns"
      ]
   },
   "agent":{
      "id":"017",
      "name":"ubunutu2004vm",
      "ip":"192.168.252.191",
      "labels":{
         "customer":"d827"
      }
   },
   "manager":{
      "name":"ASHWZH01"
   },
   "id":"1641637661.257780241",
   "decoder":{
      "name":"json"
   },
   "data":{
      "status":"OK",
      "@timestamp":"2022-01-08T10:27:37.987Z",
      "@metadata":{
         "beat":"packetbeat",
         "type":"_doc",
         "version":"7.16.2"
      },
      "type":"dns",
      "destination":{
         "ip":"127.0.0.53",
         "port":"53",
         "bytes":"76"
      },
      "server":{
         "ip":"127.0.0.53",
         "port":"53",
         "bytes":"76"
      },
      "event":{
         "end":"2022-01-08T10:27:38.005Z",
         "category":[
            "network_traffic",
            "network"
         ],
         "type":[
            "connection",
            "protocol"
         ],
         "kind":"event",
         "dataset":"dns",
         "duration":"17926000",
         "start":"2022-01-08T10:27:37.987Z"
      },
      "ecs":{
         "version":"1.12.0"
      },
      "dns":{
         "header_flags":[
            "RD",
            "RA"
         ],
         "authorities_count":"0",
         "answers_count":"1",
         "additionals_count":"0",
         "flags":{
            "recursion_available":"true",
            "authentic_data":"false",
            "checking_disabled":"false",
            "authoritative":"false",
            "truncated_response":"false",
            "recursion_desired":"true"
         },
         "answers":[
            {
               "class":"IN",
               "ttl":"0",
               "data":"firewall-us.socfortress.co",
               "name":"nms-us.socfortress.co",
               "type":"CNAME"
            }
         ],
         "type":"answer",
         "op_code":"QUERY",
         "question":{
            "top_level_domain":"co",
            "subdomain":"nms-us",
            "name":"nms-us.socfortress.co",
            "type":"AAAA",
            "class":"IN",
            "etld_plus_one":"socfortress.co",
            "registered_domain":"socfortress.co"
         },
         "opt":{
            "ext_rcode":"NOERROR",
            "do":"false",
            "version":"0",
            "udp_size":"65494"
         },
         "id":"42269",
         "response_code":"NOERROR"
      },
      "source":{
         "ip":"127.0.0.1",
         "port":"35471",
         "bytes":"50"
      },
      "method":"QUERY",
      "resource":"nms-us.socfortress.co",
      "related":{
         "ip":[
            "127.0.0.1",
            "127.0.0.53"
         ]
      },
      "client":{
         "ip":"127.0.0.1",
         "port":"35471",
         "bytes":"50"
      },
      "host":{
         "hostname":"ubunutu2004vm",
         "architecture":"x86_64",
         "os":{
            "type":"linux",
            "platform":"ubuntu",
            "version":"20.04.3 LTS (Focal Fossa)",
            "family":"debian",
            "name":"Ubuntu",
            "kernel":"5.4.0-91-generic",
            "codename":"focal"
         },
         "id":"277d2fec48db4052a889faabd6ca7e97",
         "name":"ubunutu2004vm",
         "containerized":"false",
         "ip":[
            "192.168.252.191",
            "fe80::cc54:41ff:fe01:cfbb"
         ],
         "mac":[
            "ce:54:41:01:cf:bb"
         ]
      },
      "network":{
         "type":"ipv4",
         "transport":"udp",
         "protocol":"dns",
         "direction":"ingress",
         "community_id":"1:0FIJBsstSM1Qd3htb0QpjQGPRa0=",
         "bytes":"126"
      },
      "query":"class IN, type AAAA, nms-us.socfortress.co",
      "agent":{
         "type":"packetbeat",
         "version":"7.16.2",
         "hostname":"ubunutu2004vm",
         "ephemeral_id":"f228dc79-78c9-4bb9-903d-544e9ad08587",
         "id":"b77bc49c-abb8-44f3-a4ff-95ca558ec080",
         "name":"ubunutu2004vm"
      }
   },
   "location":"/var/log/packetbeat"
}
```

