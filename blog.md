# pavel.blog

For CV reference check paveljurca.com
For press photo, check ZAJIC


## Check for Apache SSL certificate expiration

```
#!/bin/bash
IFS=$':' URL=( ${1:-USER@HOST:/opt/USER/apache/conf/ssl.crt} )
SERVER=${URL[0]}
LOCATION=${URL[1]}

IFS=$'\n' files=$(ssh $SERVER find ${LOCATION} -maxdepth 1 -mindepth 1 -type d -print| grep -v "\.git")
for site in $files
do
  echo "$SERVER:$site" >&2
  SITE=$(basename ${site})
  VHOST=$(ssh $SERVER "grep -EoA1 -m1 \"[a-zA-Z0-9]+-[0-9]{1,3}:443$\" ${site}/conf/site.conf" )
  IFS=$'\n' INFO=($(ssh $SERVER "echo|openssl s_client -servername ${SITE} -connect ${VHOST} -prexit" \
|openssl x509 -enddate -serial -noout))
  declare ${INFO[0]} # notAfter/enddate
  declare ${INFO[1]} # serial
  days=$(expr $(expr $(date -ud "$notAfter" '+%s') - $(date -u '+%s')) / 86400 )
  [ $days -le 75 ] && alert='Expiring' || alert=''
  [ $days -lt 0 ] && alert='Expired'

  echo "$SERVER,$site,$notAfter,$days,$alert"
done
```

Or testing for a non-Apache certificate

```
#!/bin/bash
IFS=$':' URL=( ${1:-USER@HOST:/opt/USER/apache/conf/ssl.crt} )
SERVER=${URL[0]}
LOCATION=${URL[1]}

IFS=$'\n' files=$(ssh $SERVER find -L $LOCATION -maxdepth 1 -type f -name *.crt)
for crt in $files
do
  echo "$SERVER:$crt" >&2
  IFS=$'\n' INFO=($(ssh $SERVER openssl x509 -in $crt -enddate -serial -noout))
  declare ${INFO[0]} # notAfter/enddate
  declare ${INFO[1]} # serial
  days=$(expr $(expr $(date -ud "$notAfter" '+%s') - $(date -u '+%s')) / 86400 )
  [ $days -le 75 ] && alert='Expiring' || alert=''
  [ $days -lt 0 ] && alert='Expired'
  echo "$SERVER,$crt,$notAfter,$days,$alert"
done

```

The above service check script is executed by Icinga

```
define service {
 use                    apache-service
 host_name      _Apache_
 service_description    ServerCerts-Expiry-Check
 check_command          check-servercerts-expiry!internal
 notification_period    workhours
 notification_interval  1440    ; 24h
}
```

You can than run it like

```
#!/bin/bash

target='internal'
cat /dev/null > $target.csv

for url in \
  USER@SERVER1:$HOME/apache/sites \
  USER@SERVER2:$HOME/apache/sites/SOME_PATH/cert.CRT
do
  ./enddate-of-server-certs.sh $url >> $target.csv
done
```


## Check for Crontab and Setcap with Icinga

```
#!/bin/bash

. $HOME/.sshagent \
 >/dev/null

#unset http_proxy
#unset https_proxy

SERVER=${1:-HOST}

# SETCAP HTTPD CHECK
setcap=$( ssh $SERVER "getcap /usr/sbin/httpd /opt/rh/httpd24/root/sbin/httpd 2>/dev/null | grep +ep" ) || exit 2

# CRONTAB CHECK
# crontab -u $(id -un) -l &>/dev/null || echo cron not allowed
crontab=$( ssh $SERVER "cat /etc/cron.allow | grep -E '\<YOUR_USER\>'" ) || exit 2

echo OK
exit 0

```

The above service check script is executed by Icinga

```
define service {
 use                    apache-service
 hostgroup_name     apache
 service_description    Crontab-Setcap-Check
 check_command          check-apache-server
 normal_check_interval  30 # mins
}
```

Icinga command definition

```
define command {
 command_name   check-apache-server
 command_line   $USER1$/YOUR_FOLDER/check-apache-server.sh $HOSTNAME$
}
```

## Check if Apache sites are working

In this example we check Virtual Hosts for status directly using cURL:

```
#!/bin/bash

. $HOME/.sshagent \
 >/dev/null

#unset http_proxy
#unset https_proxy

SERVER=${1:-HOST}
IFS=$'\n' sites=$(ssh $SERVER "find ${HOME}/apache/sites/ -maxdepth 1 -mindepth 1 -type d -print| grep -v '\.git'")
for site in $sites
do
    VHOST=$(ssh $SERVER "grep -EoA1 -m1 '[a-zA-Z0-9]+-[0-9]{1,3}:[0-9]{2,4}$' ${site}/conf/site.conf")
    s=$( echo $VHOST | cut -d':' -f1 )
    p=$( echo $VHOST | cut -d':' -f2 )
    res=$(curl --output /dev/null --silent --write-out %{http_code} --connect-timeout 5 --max-time 10 -I "http://${s}.SUBDOMAIN.DOMAIN.COM:${p}")
    [[ $res -lt 500 ]] \
      || { echo $(basename $site) NOT OK; exit 1; }
done

echo OK
exit 0
```

The above service check script is executed by Icinga

```
define service {
 use                    apache-service
 service_description    PROXY-ALL
 hostgroup_name         apache
 check_command          check-apache-all
}

```

## Confluent Control Center (C3) License expiry check

```
#!/bin/bash

host=${1:-HOST}
port=${2:-9021}

JQ="$HOME/bin/jq"
exp=$( https_proxy= curl -sk https://USER:PASSWORD@${host}:${port}/3.0/license | $JQ -r ".expiration" )
sec=$((${exp%???}-$(date '+%s')))
days=$(($sec/3600/24))

echo "Expires $(date -d @${exp%???}) (in $days days)"
# warning if license expires in less than 2 months
[ $days -lt 62 ] && exit 1
# error if license expires in less than a month
[ $days -lt 31 ] && exit 2

exit 0
```

The above service check script is executed by Icinga

```
define service {
 use                    kafka-service-pre,srv-pnp
 host_name              HOST
 service_description    C3-License
 check_command          check-c3-license!9021
}
```

Icinga command definition

```
define command {
 command_name   check-c3-license
 command_line   $USER1$/YOUR_FOLDER/check-c3-license.sh $HOSTADDRESS$ $ARG1$
}

```


## Apache monitoring

### Dynamic health check of workers / nodes

* https://httpd.apache.org/docs/2.4/mod/mod_proxy_hcheck.html
** Requires https://httpd.apache.org/docs/2.4/mod/mod_watchdog.html

```
ProxyHCExpr check_run {hc('body') =~ /RUNNING/}
ProxyHCTemplate at_check hcmethod=GET hcexpr=check_run hcpasses=3 hcinterval=5 hcuri=/status
# Backends - Proxy
<Proxy balancer://7a1657620d200251e63a8765441f771d>
  BalancerMember https://HOST:8443 retry=1 loadfactor=1 route=1 hctemplate=at_check
  BalancerMember https://HOST2:8443 retry=1 loadfactor=1 route=2 hctemplate=at_check
  ProxySet lbmethod=byrequests timeout=10 failontimeout=on stickysession=ROUTEID
</Proxy>
```

Or you may consider adding simple ping param:

```
<Proxy balancer://6fb91a2e50dfddb2b36337e3f2e732ac>
  BalancerMember https://HOST:8443 ping=4 retry=1 loadfactor=1 route=1
  BalancerMember https://HOST2:8443 ping=4 retry=1 loadfactor=1 route=2
  BalancerMember https://HOST3:8443 ping=4 retry=1 loadfactor=1 route=3
  ProxySet lbmethod=byrequests
</Proxy>
ProxySet  balancer://6fb91a2e50dfddb2b36337e3f2e732ac timeout=10 failontimeout=on stickysession=ROUTEID
```

### Total HTTPd process size

```
# total_httpd_processes_size
env PID=$(cat YOUR_SITE/logs/httpd.pid) ps -ylC httpd --sort:rss | grep $PID | awk '{ sum += $9 } END { print sum }'
```

### Total HTTPd processes count

```
# total_http_processes_count
env PID=$(cat YOUR_SITE/logs/httpd.pid) ps -ylC httpd --sort:rss | grep $PID | wc -l
```

### Apache Uptime

```
$ ps -eo comm,etime,user | grep httpd
$ httpd fullstatus
```

You may also query the /server-status?auto&refresh=3 page:

```
def parse_scoreboard(scoreboard):
    """ Parses scoreboard """
    keys = {
        '_': 'WaitingForConnection',
        'S': 'StartingUp',
        'R': 'ReadingRequest',
        'W': 'SendingReply',
        'K': 'KeepaliveRead',
        'D': 'DNSLookup',
        'C': 'ClosingConnection',
        'L': 'Logging',
        'G': 'GracefullyFinishing',
        'I': 'Idle',
        '.': 'OpenSlot'
    }
    scores = {}
    for score in scoreboard:
        if score in keys:
            if score in scores:
                scores[keys[score]] += 1
            else:
                scores[keys[score]] = 1
    return scores

def get_status(domain=None):
    """ Returns an Apache performance stat or list all of them """
    if domain is None:
        domain = 'https://localhost/server-status'
    stats_text = get_url("https://%s/server-status?auto" % domain)
    #print(stats_text)
    status = {}
    for line in stats_text.split("\n"):
        if ':' in line:
            key, value = line.split(':')[:2]
            if key == 'Scoreboard':
                for sk, sv in parse_scoreboard(value.strip()).iteritems():
                    status[sk] = sv
            continue
            if not re.search("[a-zA-Z%]", value.strip()) or  re.search("\d+.\d+e-\d", value.strip()):
                status[key.strip().replace(' ', '_')] = float(value.strip())
    return status

def output_status(status, stat=None, domain=None):
    """ Output function """

    #print(status)

    if status['CPULoad'] > 0.1 or status['WaitingForConnection'] > 5:
       exit_status = 2
    elif status['CPULoad'] > 0.05 or status['WaitingForConnection'] > 2:
       exit_status = 1
    else:
       exit_status = 0

    p = ", ".join(["{0}={1}".format(*x) for x in status.items()])
    uptime = datetime.timedelta(seconds=status['Uptime'])
    print "DOMAIN %s\nUPTIME %s hours| %s" % (domain, uptime, p)
    sys.exit(exit_status)
```

### Check CPU usage

```
top -b
```

* [Using SAR command](https://www.thegeekstuff.com/2011/03/sar-examples/)
* [How to use pstack to identify hanging threads or high CPU usage in Apache HTTPD](https://access.redhat.com/solutions/319673)

### Remote logging

* [GoAccess: Real-time log analysis through a Dashboard in multiple output formats](https://goaccess.io/)
* [Forward logs with rsyslog](http://itechsweb.com/tutorial-apache-remote-logging/)
* ELK Stack, Grafana etc.

### SWAP check

* http://nagios-plugins.org/doc/man/check_swap.html
* http://sysadminsjourney.com/content/2009/06/04/new-and-improved-checkmempl-nagios-plugin/
* https://serverfault.com/questions/186325/how-to-monitor-memory-usage-of-linux-server-using-nagios
* https://blog.christosoft.de/2013/01/nagios-icinga-memory-usage/
* https://monitoring-portal.org/woltlab/index.php?thread/36542-checking-memory-and-setting-threshold/
* https://www.thomas-krenn.com/de/wiki/Memory_Monitoring_unter_Linux_mit_Icinga
* https://exchange.nagios.org/directory/Plugins/System-Metrics/Memory/check_mem-2Esh/details

### Tools

* Apache HTTP server benchmarking tool | https://httpd.apache.org/docs/2.4/programs/ab.html
* Siege is an http load testing and benchmarking utility | https://www.joedog.org/siege-home/

### SEE

* https://en.wikipedia.org/wiki/Load_%28computing%29
* https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.cmds5/sar.htm
* https://www.datadoghq.com/blog/collect-apache-performance-metrics/
* http://devopshub.net/apache-monitoring/?lang=en
* https://serverfault.com/questions/67759/how-to-understand-the-memory-usage-and-load-average-in-linux-server
* https://stackoverflow.com/questions/479953/how-to-find-out-which-processes-are-using-swap-space-in-linux
* https://www.tecmint.com/check-apache-httpd-status-and-uptime-in-linux/
* https://www.tecmint.com/apache-performance-tuning/
* https://www.tecmint.com/check-apache-modules-enabled/
* https://dzone.com/articles/apache-http-server-performance-tuning
* https://serverfault.com/questions/254436/apache-memory-usage-optimization
* http://nagios-plugins.org/doc/man/

You may consider creating custom 503 ErrorDocument also.


## Apache remove sensitive details from server-info page

You would need those 3 modules loaded:

* https://httpd.apache.org/docs/2.4/mod/mod_filter.html
* https://httpd.apache.org/docs/2.4/mod/mod_substitute.html
* https://httpd.apache.org/docs/current/mod/mod_deflate.html

httpd.conf

```
####===================================================####
# Perform search and replace operations on response bodies
LoadModule filter_module modules/mod_filter.so
LoadModule substitute_module modules/mod_substitute.so
####===================================================####
```

site.conf

```
<Location "/server-info">
# Hide Whatever_is_Sensitive_For_You details from info page
AddOutputFilterByType SUBSTITUTE text/html
SetOutputFilter SUBSTITUTE;DEFLATE
Substitute 's|(Whatever_is_Sensitive_For_You[a-zA-Z]+).*|$1 <i>REDACTED</i>|'

# Hide Password and X-AFSECRET from info page
Substitute 's|(X-AFSECRET).*|$1 <strong>REDACTED</strong>|'
Substitute 's|.+Password.*|<strong>REDACTED</strong>|q'
</Location>
```

The q flag causes mod_substitute to be much faster but only if the subsequent substitution does not match the same pattern. In that case it would be eventually slower.

## Apache Server Status page

If you are using IP based Virtual Hosts (CNAMEs) you may want to show the domain name right on your Status page.
You need [this Apache module](https://httpd.apache.org/docs/2.4/mod/mod_substitute.html) to change the content of a page before it gets rendered.

Create Web Location:

```
<Location /server-status-hostname>
AddOutputFilterByType SUBSTITUTE text/html
SetOutputFilter SUBSTITUTE;DEFLATE
Substitute 's|<h1>Apache Server Status for|<h1>{{hostname}} \||'
</Location>
```

Add IfModule section:

```
<IfModule server_status.c>

ExtendedStatus On

<IfModule mod_proxy.c>

# Show Proxy LoadBalancer status in mod_status

ProxyStatus On

</IfModule>
</IfModule>
```

See

* https://gist.github.com/tonejito/6a3c64a1d49844a40a2f4c16dd24f423

* https://github.com/soarpenguin/perl-scripts/blob/master/log_server_status

* https://github.com/Humbedooh/server-status

* https://sourceforge.net/projects/pimpapachestat/
* 
https://httpd.apache.org/docs/2.4/mod/mod_info.html
* 
https://httpd.apache.org/docs/2.4/mod/mod_status.html
* 
https://fourtonfish.com/blog/2015-09-11-apache-server-status-custom-css/
* 
https://serverfault.com/questions/225913/explain-apache-status

* https://www.liquidweb.com/kb/use-httpd-fullstatus-to-monitor-apache-status/
* 
https://www.tecmint.com/check-apache-httpd-status-and-uptime-in-linux/

## Check on RAM resources

Checks like those can help you to prevent JVM perm space issues for example:

```
$ vmstat 1
$ sar -r 1 3
$ ps -eo comm,etime,user | grep java
$ swapon --summary
$ free -m
$ cat /proc/meminfo
```

## Debugging Java on command line

In general you want to check on heap memory, long-running threads, PermGen errors, failing TCP sockets etc.

```
$ jps -v
$ ps -p 14016 -F
$ jstat -gc 14016
$ jstat -gcutil 14016
$ java -XX:+PrintFlagsFinal -version | grep HeapSize
```

Sample bash script

```
#!/bin/bash

export JAVA_HOME=/usr

pluginpath=${1:-$HOME/icinga/current/libexec}
host=${2:-HOST}
port=${3:-52001}
warning=${4:-20}
critical=${5:-10}

cd $pluginpath
freemem=`$JAVA_HOME/bin/java -cp groovy-all-1.8.6.jar groovy.lang.GroovyShell get-jvm-heap-free-space.groovy $host:$port`

echo "free heap memory: ${freemem}%"

if [ "$freemem" -lt "$critical" ]
then
  exit 2
elif [ "$freemem" -lt "$warning" ]
then
  exit 1
else
  exit 0
fi
```

See

* https://blog.gceasy.io/2015/08/14/how-to-capture-heap-dump-jmap/
* https://stackoverflow.com/questions/12797560/command-line-tool-to-find-java-heap-size-and-memory-used-linux

## Check disk usage

```
df -h /opt/* | sort -nr | uniq
```

## List all mount points

```
findmnt -a -R -T /opt
```

## Check for mount points

```
$ for kafka in {kafka01,kafka02}; do echo -en "$kafka |\t"; ssh user@${kafka} 'findmnt -n --fstab /var/log/kafka/ || echo kafkaloglv missing'; done

```

Other example

```
$ ssh kafka01 'find /opt -maxdepth 1 -type d | xargs -L1 mountpoint 2>/dev/null'
```

## Check CPU load average

```
$ cat /proc/loadavg
3.39 3.31 3.36 5/2397 235632
```

We can say the load avarage is ~ 3.3.
For example if you got 36 cores and 72 threads ([CPU supports HT](https://ark.intel.com/content/www/us/en/ark/products/120485/intel-xeon-gold-6140-processor-24-75m-cache-2-30-ghz.html)), the below would mean you got ~ 68 threads idle, i.e. being not occupied and available.

```
$ grep 'model name' /proc/cpuinfo | wc -l
72
```

See

* https://scoutapm.com/blog/understanding-load-averages


## Irix mode in top command

After turning Irix mode off the example load goes from 400% down to 5.6% as top shows by default CPU percentage PER core but "Solaris" mode takes all the processors as a whole and the total usage of cpu is always from 0% to 100%:

```
  PID USER      PR  NI    VIRT    RES    SHR S %CPU %MEM     TIME+ COMMAND
273060 cp-cont+  20   0   41.7g   6.1g  27508 S  5.6  2.4 346492:30 java
```

See

* http://logic.edchen.org/irix-mode-vs-solaris-mode-in-top-command/
