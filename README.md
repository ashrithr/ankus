# AnkusCLI

Command line interface for ankus big-data deployment tool. Handles the installation/management of:

 - hadoop (hadoop-2.0.0)
 - hadoop ecosystem tools: pig (0.11.x), hive (0.10.x), sqoop (1.4.x), oozie (3.3.x), flume-ng
 - hbase (hbase-0.94)

 AnkusCLI can handle deployments in local as well as cloud mode.

 1. **Local mode** is where the user specifies the instance roles
 2. **Cloud mode** is where ankus will create/manage vm's and auto assigns roles to them. Currently ankuscli supports AWS (Amazon Web Services) & Rackspace.

**Ankuscli leverages open source tools such as:**

 - puppet & puppetdb for deployment and configuration management
 - passenger for scaling puppet
 - ganglia for monitoring
 - nagios for alerting
 - logstash for log aggregation
<<<<<<< Updated upstream
=======
 
![Alt Text](images/ankus_arch.png)
>>>>>>> Stashed changes

## Installation

###Dependencies

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


###Installing AnkusCLI

**Two ways to install AnkusCLI:**

* Installing AnkusCLI from Source:

	```
	cd ~ && git clone https://github.com/ashrithr/ankus-cli.git
	gem install bundle --no-ri --no-rdoc
	cd ankus-cli && bundle install
	```
* Packaging and installing AnkusCLI as a ruby gem (until the gem is publicly available from rubygems):

	```
	cd ~ && git clone https://github.com/ashrithr/ankus-cli.git
	cd ankus-cli
	gem build ankuscli.gemspec && gem install ankuscli-*.gem
	```

## Usage:

###Deployment in Cloud (AWS or Rackspace):

To quickly deploy big-data clusters like hadoop, hbase or cassandra in the cloud, follow the steps:

1. Modify the configuration in (*conf* directory of where you installed ankuscli), for convenience purposes ankuscli comes with pre-built configurations for aws, rackspace and local install modes.
	* if you are working with aws use `conf/ankus_conf_cloud_aws_example.yaml` as a base line template for configuration

		```
		cp conf/ankus_conf_cloud_aws_example.yaml conf/ankus_conf.yaml
		```
	* if you are working with rackspace cloud platform use `conf/ankus_conf_cloud_rs_example.yaml` as a base line template for configuration

		```
		cp conf/ankus_conf_cloud_rs_example.yaml conf/ankus_conf.yaml
		```
2. Once base line configuration file is in place you can open up the configuration file in your favorite text editor, the configuration it self is fairly explanatory with comments in place for every option in the config file.
3. Once all the values required are filled you can check to see if the config looks ok by running the following command

	```
	bin/ankuscli parse
	```
	which will parse the configuration file (by default *conf/ankus_conf.yaml*) and show if there are any warnings or errors. If you have saved the configuraion file with different name or placed the configuration file in another location you can explicitly pass the config as

	```
	bin/ankuscli parse --config conf/ankus.yaml
	```
4. You can deploy a cluster using the following command

	```
	bin/ankuscli deploy
	```
	which will deploy cluster as specified in the configuration. Deployment includes creating instances in the cloud, creating/mounting volumes and installing/configuring respective roles. This might take around *30 mins* for the deployment to complete.

	Once the deployment is complete, ankuscli will show you the overview of cluster information
5. Once you have a running cluster, if you need more worker nodes to do additional tasks (or) store more data

	```
	bin/ankuscli deploy --add-nodes --count 2
	```
	which will provision 2 vm's in the cloud and configure/install vm's and automatically adds them to the running cluster
6. Similarly, if you want to change any configurations related to hadoop, you can simply edit `conf/ankus_hadoop_conf.yaml` which contains basic hadoop configurations once edited you can run

	```
	bin/ankuscli refresh
	```
	which will automatically refresh the nodes with updated configurations and will restart the respective daemons
7. Ankuscli is clever enough to store the roles of the machines being provisioned and automatically do `ssh` into instances using their roles like this:

	```
	bin/ankuscli ssh --role controller
	```
	which will create a ssh tunnel into controller, similarly for hadoop namenode

	```
	bin/ankuscli ssh --role namenode
	```
8. Ankuscli also provides a way to look at cluster details using

	```
	bin/ankuscli info
	```
9. Also, down the line once you have completed your work with cluster in the cloud, you can tell ankuscli to destroy the cluster using

	```
	bin/ankuscli destroy
	```
	this is only applicable to cloud deployments

###Deployment in Local:

Local deployment mode, is where user provides the instances on which specified roles are managed.

*Note: Passwordless-ssh should be setup between host (from which you are running ankuscli) to all the hosts involved in deployment.*

Similar to that of cloud deployments, local deployment also has template configuration file that could be used as base line

```
cp conf/ankus_conf_local_example.yaml conf/ankus_conf.yaml
```

Change the configuration file as per the requirements and then

1. To deploy a cluster

	```
	bin/ankuscli deploy
	```
2. To add more worker hosts to an existing cluster

	```
	bin/ankuscli deploy --add-nodes --hosts slave003.ops.ankus.com slave004.ops.ankus.com
	```
3. Refresh configuration files

	```
	bin/ankuscli refresh
	```
4. SSH into a instance

	```
	bin/ankuscli ssh --role controller
	```
5. Retrieve information about the cluster
	```
	bin/ankuscli info
	```

##Future Work (WIP)

 More deployment modules are in Development:

 - Cassandra
 - storm
 - kafka
 - solr
 - mongodb

##Author:
[Ashrith](https://github.com/ashrithr)
