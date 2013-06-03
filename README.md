# Ankuscli

Command line interface for ankus big-data deployment tool. Handles the installation of:

 - hadoop
 - hadoop ecosystem tools: pig, hive, sqoop, oozie, flume
 - hbase
 - cassandra
 - storm
 - kafka
 - solr
 - mongodb
 - lucene
 - elastic search

Ankuscli leverages open source tools such as:

 - puppet for deployment and configuration management
 - ganglia for monitoring
 - nagios fot alerting
 - logstash to manage/aggregate logs

## Installation

Dependencies:
 
 - CentOS:

   ```
    yum -y install git ruby rubygems gcc ruby-devel libxml2 libxml2-devel libxslt libxslt-devel make
   ```
 - Ubuntu:

   ```
    apt-get install -y ruby1.8-dev ruby1.8 ri1.8 rdoc1.8 irb1.8 libreadline-ruby1.8 libruby1.8 libopenssl-ruby libxslt-dev libxml2-dev gcc make
   ```

Download and install:

```
$ cd ~ && git clone https://github.com/ashrithr/ankus-cli.git
$ gem install bundle --no-ri --no-rdoc
#install ruby gem dependencies
$ cd ankus-cli && bundle install
```

## Usage:

Modify the configuration to match your environment (Sample configurations for local|cloud installation are in config dir, copy them and modify)

To check for configuration errors:

```
bundle exec bin/ankuscli parse
```
Finally deploy using:

```
bundle exec bin/ankuscli deploy
```
To enable debugging:

```
bundle exec bin/ankuscli deploy --debug
```

For More Options: `bundle exec bin/ankuscli`

