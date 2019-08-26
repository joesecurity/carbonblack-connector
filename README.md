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
curl -Lo /tmp/joesandbox.rpm https://github.com/joesecurity/carbonblack-connector/raw/master/dist/python-cb-joesandbox-connector-1.2-8.x86_64.rpm
rpm -i /tmp/joesandbox.rpm
```

### Configuration

Once the software is installed, it is time to configure the integration. Copy the example integration:

```
cd /etc/cb/integrations/joesandbox
cp connector.conf.example connector.conf
```

Edit this file and place your Carbon Black API key into the `carbonblack_server_token` variable
and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Then you must place your credentials for Joe Sandbox into the configuration file: place your API key and API token
respectively into the `joesandbox_apikey` and `joesandbox_apiurl`. Please enable `joesandbox_accept_tac=1`.

If you are using an on-premise Joe Sandbox appliance, make sure to place the URL for your on-premise Joe Sandbox appliance
in the `joesandbox_url` variable and set `joesandbox_url_sslverify` to `0` if your appliance does not have a valid SSL
certificate.

Now restart the integration server:

```
/etc/init.d/cb-joesandbox-connector restart
```

Any errors will be logged into `/var/log/cb/integrations/joesandbox/joesandbox.log`.

### Connecting to Carbon Black

In Cb Response navigate to `Threat Intelligence` and then click `Add New Feed`. If you installed the connector
on the same server as Cb Response, the URL is `http://127.0.0.1:4000/feed.json`.

The connector is now installed configured and should start analyzing binaries.

## Troubleshooting

If you suspect a problem, please first look at the Joe Sandbox connector logs found here:
`/var/log/cb/integrations/joesandbox/joesandbox.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `/etc/init.d/cb-joesandbox-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/joesandbox/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `/etc/init.d/cb-joesandbox-connector start`

