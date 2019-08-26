# Carbon Black - Joe Sandbox Connector

The Joe Sandbox connector submits binaries collected by Carbon Black to a Joe Sandbox
appliance for binary analysis. The results are collected and placed into an Intelligence
Feed on your Carbon Black server. The feed will then tag any binaries executed on your
endpoints identified as malware by Joe Sandbox. Only binaries submitted by the connector
for analysis will be included in the generated Intelligence Feed.

## Installation Quickstart

First, download the rpm package located in `dist` from Github. As root on your Carbon Black
or other RPM based 64-bit Linux distribution server:

```
rpm -i python-cb-joesandbox-connector-1.2-8.x86_64.rpm
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/joesandbox/connector.conf.example` file to
`/etc/cb/integrations/joesandbox/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Then you must place your credentials for Joe Sandbox into the configuration file: place your API key and API token
respectively into the `joesandbox_api_key` and `joesandbox_api_token` variables in the 
`/etc/cb/integrations/joesandbox/connector.conf` file.

If you are using an on-premise Joe Sandbox appliance, make sure to place the URL for your on-premise Joe Sandbox appliance
in the `joesandbox_url` variable and set `joesandbox_url_sslverify` to `0` if your appliance does not have a valid SSL
certificate.

Any errors will be logged into `/var/log/cb/integrations/joesandbox/joesandbox.log`.

## Troubleshooting

If you suspect a problem, please first look at the Joe Sandbox connector logs found here:
`/var/log/cb/integrations/joesandbox/joesandbox.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-joesandbox-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/joesandbox/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-joesandbox-connector start`

## Contacting Carbon Black Developer Relations Support

Web: https://community.bit9.com/groups/developer-relations
E-mail: dev-support@bit9.com

### Reporting Problems

When you contact Carbon Black Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM)
* For documentation issues, specify the version of the manual you are using.
* Action causing the problem, error message returned, and event log output (as appropriate)
* Problem severity
