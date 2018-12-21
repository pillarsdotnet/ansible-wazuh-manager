wazuh-manager
=============

This role will install and configure the Wazuh manager service.

OS Requirements
---------------

This role will work on:
 * Red Hat
 * CentOS
 * Fedora
 * Debian
 * Ubuntu

Role Requirements
-----------------

* [ansible-xml](https://github.com/GSA/ansible-xml)

Role Variables
--------------

* `nodejs_repo_add`: (boolean) Add nodejs repo to apt or rpm sources before installing
* `nodejs_repo_remove`: (boolean) Remove nodejs repo from sources after installation is complete
* `wazuh_agentless_hosts`: (dict) Usernames and passwords for [agentless](https://documentation.wazuh.com/current/user-manual/capabilities/agentless-monitoring/how-it-works.html#connection) monitoring
* `wazuh_api_install`: (boolean) Install [wazuh-api](https://documentation.wazuh.com/current/user-manual/api/index.html) app
* `wazuh_api_users`: (dict) Usernames and passwords for [API authentication](https://documentation.wazuh.com/current/user-manual/api/configuration.html#basic-authentication)
* `wazuh_async_timeout`: (int) Default timeout between checks for completion of async operations such as [apt](https://docs.ansible.com/ansible/latest/modules/apt_module.html#apt-module) and [yum](https://docs.ansible.com/ansible/latest/modules/yum_module.html#yum-module)
* `wazuh_async_tries`: (int) Max number of times to check for async completion before declaring failure
* `wazuh_authd_pass`: Password for [agent registration](https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#use-a-password-to-authorize-agents)
* `wazuh_cdb_lists_custom`: Custom [CDB lists](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)
* `wazuh_manager`: Wazuh manager [local configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html)
  * `wazuh_manager_activeresponse`: Settings for [active-response](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html) section
  * `wazuh_manager_alerts`: Settings for [alerts](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/alerts.html) section
  * `wazuh_manager_auth`: Settings for [auth](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html) section
  * `wazuh_manager_cluster`: Settings for [cluster](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/cluster.html) section
  * `wazuh_manager_command`: Settings for [command](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/commands.html) section
  * `wazuh_manager_databaseoutput`: Settings for [database_output](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/database-output.html) section
  * `wazuh_manager_emailalerts`: Settings for [email_alerts](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/email_alerts.html) section
  * `wazuh_manager_global`: Settings for [global](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html) section
  * `wazuh_manager_integration`: Settings for [integration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html) section
  * `wazuh_manager_labels`: Settings for [labels](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/labels.html) section
  * `wazuh_manager_localfile`: Settings for [localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html) section
  * `wazuh_manager_logformat`: [Log format](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/logging.html#log-format) setting
  * `wazuh_manager_remote`: [Remote](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html) section
  * `wazuh_manager_reports`: [Reports](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/reports.html) section
  * `wazuh_manager_rootcheck`: Settings for [rootcheck](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/rootcheck.html) section
  * `wazuh_manager_ruleset`: Settings for [ruleset](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/ruleset.html) section
  * `wazuh_manager_socket`: Settings for [socket](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/socket.html) section
  * `wazuh_manager_syscheck`: Settings for [syscheck](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html) section
  * `wazuh_manager_syslogoutput`: Settings for [syslog_output](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syslog-output.html) section
  * `wazuh_manager_wodle`: Settings for [Wazuh modules](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-modulesd.html)
  * `wazuh_manager_wodle_aws`: Settings for the [AWS-s3](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-s3.html) module
  * `wazuh_manager_wodle_ciscat`: Settings for the [cis-cat](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-ciscat.html) module
  * `wazuh_manager_wodle_command`: Settings for the [command](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html) module
  * `wazuh_manager_wodle_openscap`: Settings for the [open-scap](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-openscap.html) module
  * `wazuh_manager_wodle_osquery`: Settings for the [osquery](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-osquery.html) module
  * `wazuh_manager_wodle_syscollector`: Settings for the [syscollector](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-syscollector.html) module
  * `wazuh_manager_wodle_vuldetector`: Settings for the [vulnerability-detector](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-vuln-detector.html) module
* `wazuh_shared`: Settings for [centralized configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
  * `wazuh_shared_linux`: Centralized settings for linux agents
  * `wazuh_shared_windows`: Centralized settings for windows agents

Example Playbook
----------------

```

    - hosts: 'wazuh-manager.example.com'
      roles:
        - 'ansible-wazuh-manager'
      vars:
        wazuh_authd_pass: 'S3CR3T'
		wazuh_manager_auth_disabled: false
	    wazuh_manager_auth_usepassword: true
        
```

License
-------

BSD

### Created by [Robert Vincent](mailto:robert.vincent@gsa.gov) based on [previous work](https://github.com/wazuh/wazuh-ansible) by Wazuh, Inc.
