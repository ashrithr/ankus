# Ankus

Ankus is a big-data deployment & orchestration tool. Handles the installation & management of:

 - hadoop (hadoop-2.0.0)
 - hadoop ecosystem tools: pig (0.11.x), hive (0.10.x), sqoop2, oozie (3.3.x), flume-ng
 - hbase (hbase-0.94)
 - cassandra (cassandra-1.2)

 Ankus can handle deployments in local (group of local machines) as well as cloud (servers hosted by cloud providers).

 1. **Local mode** is where the user specifies the instance roles, supported operating systems for deployments are `centos` and `ubuntu`
 2. **Cloud mode** is where ankus will create/manage vm's and auto assigns roles to them. Currently ankus supports `AWS(Amazon Web Services)` & `Rackspace`.

**Ankus leverages several open source tools such as:**

 - puppet & puppetdb for deployment and configuration management
 - passenger for scaling the deployments
 - ganglia for monitoring
 - nagios for alerting
 - logstash for log aggregation

**Supported Deployment Types:**

 - Highly Available Hadoop & HBase cluster deployments
 - Secure Hadoop & HBase cluster deployments (using kerberos)

---

![Alt Text](images/ankus_arch.png)

---

## Installation

###Dependencies

Ankus should work fine with ruby 1.8.7 or 1.9.3, so to built from source some of the dependencies are required, to install the dependencies required on supported platforms follow these instructions:

 - CentOS:

   ```shell
    yum -y install git ruby rubygems gcc ruby-devel libxml2 libxml2-devel libxslt libxslt-devel make
   ```

 - Ubuntu:

   ```shell
   apt-get install -y ruby1.9.1 ruby1.9.1-dev rubygems1.9.1 irb1.9.1 ri1.9.1 rdoc1.9.1 \
	  build-essential libopenssl-ruby1.9.1 libssl-dev zlib1g-dev libxslt-dev libxml2-dev \
	  git
   ```

 - Mac OSX:

 	Requirements:

	- Install XCode Command Line Tools from [connect.apple.com](http://connect.apple.com/) (or) from [Github](https://github.com/kennethreitz/osx-gcc-installer/downloads)
	- Install [Homebrew](http://mxcl.github.io/homebrew/)

	```shell
	brew install libxml2 libxslt ruby
	brew link libxml2 libxslt
	```


###Installing Ankus

**Two ways to install Ankus:**

* Installing Ankus from Source:

	```shell
	cd ~ && git clone https://github.com/ashrithr/ankus.git
	gem install bundle --no-ri --no-rdoc
	cd ankus && bundle install
	```
* Packaging and installing Ankus as a ruby gem (until the gem is publicly available from rubygems):

	```shell
	cd ~ && git clone https://github.com/ashrithr/ankus.git
	cd ankus
	gem build ankus.gemspec && gem install ankus-*.gem
	```

## Usage:

###Deployment in Cloud (AWS or Rackspace):

To quickly deploy big-data clusters like hadoop, hbase or cassandra in the cloud, follow these steps:

Ankus is a configuration based deployment platform, so deployments should be specified as files written in YAML. So, for the sake of convience example configurations are provided in `conf` directory for several sample deployment(s) which could be used as baseline templates.

1. Modify the configuration in (*conf* directory of where you installed ankus), for convenience ankus comes with pre-built configurations for aws, rackspace and local install modes.
	* If you are working with aws use `conf/ankus_conf_cloud_aws_example.yaml` as a base line template for configuration

		```shell
		cp conf/exmaple_confs/ankus_conf_cloud_aws_example.yaml conf/ankus_conf.yaml
		```
	* If you are working with rackspace cloud platform use `conf/ankus_conf_cloud_rs_example.yaml` as a base line template for configuration

		```shell
		cp conf/exmaple_confs/ankus_conf_cloud_rs_example.yaml conf/ankus_conf.yaml
		```

2. Once base line configuration file is in place you can open up the configuration file (`conf/ankus_conf.yaml`) in your favorite text editor, the configuration itself is fairly explanatory with comments in place for every option in the config file.

3. Once all the values required are filled you can check to see if the config looks ok by running the following command

	```shell
	bin/ankus parse
	```
	which will parse the configuration file (by default *conf/ankus_conf.yaml*) and show if there are any warnings or errors. If you have saved the configuraion file with different name or placed the configuration file in another location you can explicitly pass the config as

	```shell
	bin/ankus parse --config conf/ankus.yaml
	```
4. Now, you are all set to deploy a cluster using the following command

	```
	bin/ankus deploy
	```
	which will deploy cluster as specified in the configuration. Deployment includes creating instances in the cloud, creating/mounting volumes and installing/configuring respective roles. This might take around *30-45 mins* for the deployment to complete based on the type of deployment.

	Once the deployment is complete, ankuscli will show the overview of cluster
5. Once deployment is complete you can see the cluster information using the following command

	```
	bin/ankus info --extended
	```
	`extended` flag will show you more information related to the deployment such as URL(s) for accessing the important daemons and also all the nodes in the deployment and their roles.
6. Once you have a running cluster, if you need more worker nodes to do additional tasks (or) store more data

	```
	bin/ankus deploy --add-nodes --count 2
	```
	which will provision 2 vm's in the cloud and configure/install vm's and automatically adds them to the running cluster
7. Similarly, if you want to change any configurations related to hadoop, you can simply edit `conf/ankus_hadoop_conf.yaml` which contains basic hadoop configurations (or) `conf/ankus_hbase_conf.yaml` which contains hbase related properties, once edited you can run

	```
	bin/ankus refresh
	```
	which will automatically refresh the nodes with updated configurations and will restart the respective daemons
8. Ankus is clever enough to store the roles of the machines being provisioned and automatically do `ssh` into instances using their roles like this:

	```
	bin/ankus ssh --role controller
	```
	which will create a ssh tunnel into controller, similarly for hadoop namenode

	```
	bin/ankus ssh --role namenode
	```
9. Also, down the line once you have completed your work with cluster in the cloud, you can tell ankuscli to destroy the cluster using

	```
	bin/ankus destroy
	```
	this is only applicable to cloud deployments

###Deployment in Local:

Local deployment mode, is where user provides the instances on which specified roles are managed.

*Note: Passwordless-ssh should be setup between host (from which you are running ankus) to all the hosts involved in deployment.*

Similar to that of cloud deployments, local deployment also has template configuration file that could be used as base line

```
cp conf/exmaple_confs/ankus_conf_local_example.yaml conf/ankus_conf.yaml
```

Change the configuration file as per the requirements and then

1. To deploy a cluster

	```
	bin/ankus deploy
	```
2. To add more worker hosts to an existing cluster

	```
	bin/ankus deploy --add-nodes --hosts slave003.ops.ankus.com slave004.ops.ankus.com
	```
3. Refresh configuration files

	```
	bin/ankus refresh
	```
4. SSH into a instance

	```
	bin/ankus ssh --role controller
	```
5. Retrieve information about the cluster
	```
	bin/ankus info
	```

##Future Work (WIP)

 More deployment modules are in Development:

 - storm
 - kafka
 - solr
 - mongodb

##Author:
[Ashrith](https://github.com/ashrithr)
