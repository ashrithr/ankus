# Ankuscli

Command line interface for ankus big-data deployment tool. Handles the installation of:

 - hadoop
 - hadoop ecosystem tools: pig, hive, sqoop, oozie, flume
 - hbase
 - cassandra

Ankuscli leverages open source tools such as:

 - puppet for deployment and configuration management
 - ganglia for monitoring
 - nagios for alerting
 - logstash for log aggregation

## Installation

Dependencies:
 
 - CentOS:

   ```
    yum -y install git ruby rubygems gcc ruby-devel libxml2 libxml2-devel libxslt libxslt-devel make
   ```
 - Ubuntu:

   ```
    apt-get install -y ruby1.8-dev ruby1.8 ri1.8 rdoc1.8 irb1.8 libreadline-ruby1.8 libruby1.8 \
    libopenssl-ruby libxslt-dev libxml2-dev gcc make
   ```
 
 - Mac OSX:
 
 	Requiremetns:
	- XCode Command Line Tools (or) [osx-gcc](https://github.com/kennethreitz/osx-gcc-installer/) 
	- Homebrew
	
	```
	brew install libxml2 libxslt ruby
	brew link libxml2 libxslt
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
To enable debugging while deploying a cluster:

```
bundle exec bin/ankuscli deploy --debug
```
To show the cluster information:

```
bundle exec bin/ankuscli info
```
To SSH into the cloud instance (in cloud deployments):

```
bundle exec bin/ankuscli ssh <role>
ex: bundle exec bin/ankuscli ssh controller
```
To destroy the Cloud instances created by ankus:

```
bundle exec bin/ankuscli destroy
```

To pass configuration file explicitly:

```
bundle exec bin/ankuscli parse --config <path_to_config_file>
```

For More Options: `bundle exec bin/ankuscli`

