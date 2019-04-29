#!/bin/bash

################################
##### Credential Creation ######
################################

# Create passphrases and set them as variables
etherpad_user_passphrase=$(date +%s | sha256sum | base64 | head -c 32)
sleep 1
etherpad_mysql_passphrase=$(date +%s | sha256sum | base64 | head -c 32)
sleep 1
etherpad_admin_passphrase=$(date +%s | sha256sum | base64 | head -c 32)
sleep 1
gitea_mysql_passphrase=$(date +%s | sha256sum | base64 | head -c 32)
sleep 1
mumble_passphrase=$(date +%s | sha256sum | base64 | head -c 32)
sleep 1
root_passphrase=$(date +%s | sha256sum | base64 | head -c 32)

# Set root passphrase
# sudo echo "root:$root_passphrase" | chpasswd

# Write the passphrases to a file for reference. You should store this securely in accordance with your local security policy.
# As much as it pains me to admit it, @dcode helped me with the USER_HOME variable to get the creds written to the unprivileged user's home directory
USER_HOME=$(getent passwd 1000 | cut -d':' -f6)
for i in {etherpad_user_passphrase,etherpad_mysql_passphrase,etherpad_admin_passphrase,gitea_mysql_passphrase,mumble_passphrase, root_passphrase}; do echo "$i = ${!i}"; done > $USER_HOME/capes_credentials.txt

# Set your hostname as a variable. This is for instructions below.
HOSTNAME="$(hostname -f)"

# Set your email address for Let's Enrypt. Hard-coded for now.
EMAIL="ca@tactics.coop"

# Update your Host file
# echo "$IP $HOSTNAME" | sudo tee -a /etc/hosts

# Update the landing page index file
sed -i "s/HOSTNAME/$HOSTNAME/" landing_page/index.html

################################
########### Docker #############
################################
sudo yum install -y docker

# Create non-Root users to manage Docker
# You'll still need to run sudo docker [command] until you log out and back in OR run "newgrp - docker"
# The "newgrp - docker" command starts a subshell that prevents this autobuild script from completing, so we'll just keep using sudo until a reboot.
sudo groupadd docker
sudo usermod -aG docker "$USER"

# Set Docker to start on boot
sudo systemctl enable docker.service

# Start the Docker services
sudo systemctl start docker.service

# Create the CAPES network and data volume
sudo docker network create capes
sudo docker volume create portainer_data

# Update Elasticsearch's folder permissions
sudo mkdir -p /var/lib/docker/volumes/elasticsearch/thehive/_data
sudo mkdir -p /var/lib/docker/volumes/elasticsearch{-1,-2,-3}/capes/_data
sudo chown -R 1000:1000 /var/lib/docker/volumes/elasticsearch{-1,-2,-3}
sudo chown -R 1000:1000 /var/lib/docker/volumes/elasticsearch

# Update permissionso on the Heartbeat and Metricbeat yml file
sudo chown root: heartbeat.yml
sudo chmod 0644 heartbeat.yml
sudo chown root: metricbeat.yml
sudo chmod 0644 metricbeat.yml

# Adjust VM kernel setting for Elasticsearch
sudo sysctl -w vm.max_map_count=262144
sudo bash -c 'cat >> /etc/sysctl.conf <<EOF
vm.max_map_count=262144
EOF'

## CAPES Reverse Proxy ##

# Nginx Reverse Proxy
sudo docker run -d --network capes --restart unless-stopped --name nginx-proxy -p 80:80 -p 443:443 -v /etc/nginx/certs -v /etc/nginx/vhost.d -v /usr/share/nginx/html -v /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy

#Let's encrypt nginx-proxy companion
sudo docker run -d --network capes --restart unless-stopped --name nginx-proxy-letsencrypt --volumes-from nginx-proxy -v /var/run/docker.sock:/var/run/docker.sock:ro jrcs/letsencrypt-nginx-proxy-companion



## CAPES Databases ##

# Etherpad MYSQL Container
sudo docker run -d --network capes --restart unless-stopped --name capes-etherpad-mysql -v /var/lib/docker/volumes/mysql/etherpad/_data:/var/lib/mysql:z -e "MYSQL_DATABASE=etherpad" -e "MYSQL_USER=etherpad" -e MYSQL_PASSWORD=$etherpad_mysql_passphrase -e "MYSQL_RANDOM_ROOT_PASSWORD=yes" mysql:5.7

# Gitea MYSQL Container
sudo docker run -d --network capes --restart unless-stopped --name capes-gitea-mysql -v /var/lib/docker/volumes/mysql/gitea/_data:/var/lib/mysql:z -e "MYSQL_DATABASE=gitea" -e "MYSQL_USER=gitea" -e MYSQL_PASSWORD=$gitea_mysql_passphrase -e "MYSQL_RANDOM_ROOT_PASSWORD=yes" mysql:5.7

# TheHive & Cortex Elasticsearch Container
sudo docker run -d --network capes --restart unless-stopped --name capes-thehive-elasticsearch -v /var/lib/docker/volumes/elasticsearch/thehive/_data:/usr/share/elasticsearch/data:z -e "http.host=0.0.0.0" -e "transport.host=0.0.0.0" -e "xpack.security.enabled=false" -e "cluster.name=hive" -e "script.inline=true" -e "thread_pool.index.queue_size=100000" -e "thread_pool.search.queue_size=100000" -e "thread_pool.bulk.queue_size=100000" docker.elastic.co/elasticsearch/elasticsearch:5.6.13

# Rocketchat MongoDB Container
sudo docker run -d --network capes --restart unless-stopped --name capes-rocketchat-mongo -v /var/lib/docker/volumes/rocketchat/_data:/data/db:z -v /var/lib/docker/volumes/rocketchat/dump/_data:/dump:z mongo:latest mongod --smallfiles




## CAPES Services ##

# Portainer Service
sudo docker run -d --network capes --restart unless-stopped --name capes-portainer -e "LETSENCRYPT_HOST=portainer.$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=9000" -e "VIRTUAL_HOST=portainer.$HOSTNAME" -v /var/lib/docker/volumes/portainer/_data:/data:z -v /var/run/docker.sock:/var/run/docker.sock portainer/portainer:latest

# Nginx Service
sudo docker run -d  --network capes --restart unless-stopped --name capes-landing-page -e "LETSENCRYPT_HOST=$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=80" -e "VIRTUAL_HOST=$HOSTNAME" -v $(pwd)/landing_page:/usr/share/nginx/html:z nginx:latest

# Cyberchef Service
sudo docker run -d --network capes --restart unless-stopped --name capes-cyberchef -e "LETSENCRYPT_HOST=cyberchef.$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=80" -e "VIRTUAL_HOST=cyberchef.$HOSTNAME" remnux/cyberchef:latest

# Gitea Service
sudo docker run -d --network capes --restart unless-stopped --name capes-gitea -e "LETSENCRYPT_HOST=gitea.$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=3000" -e "VIRTUAL_HOST=gitea.$HOSTNAME" -v /var/lib/docker/volumes/gitea/_data:/data:z gitea/gitea:latest

# Etherpad Service
sudo docker run -d --network capes --restart unless-stopped --name capes-etherpad -e "LETSENCRYPT_HOST=etherpad.$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=9001" -e "VIRTUAL_HOST=etherpad.$HOSTNAME"  -e "ETHERPAD_TITLE=CAPES" -e "ETHERPAD_PORT=9001" -e ETHERPAD_ADMIN_PASSWORD=$etherpad_admin_passphrase -e "ETHERPAD_ADMIN_USER=admin" -e "ETHERPAD_DB_TYPE=mysql" -e "ETHERPAD_DB_HOST=capes-etherpad-mysql" -e "ETHERPAD_DB_USER=etherpad" -e ETHERPAD_DB_PASSWORD=$etherpad_mysql_passphrase -e "ETHERPAD_DB_NAME=etherpad" tvelocity/etherpad-lite:latest

# TheHive Service
sudo docker run -d --network capes --restart unless-stopped --name capes-thehive -e "LETSENCRYPT_HOST=thehive.$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=9000" -e "VIRTUAL_HOST=thehive.$HOSTNAME"  -e CORTEX_URL=capes-cortex thehiveproject/thehive:latest --es-hostname capes-thehive-elasticsearch --cortex-hostname capes-cortex

# Cortex Service
# sudo docker run -d --network capes --restart unless-stopped --name capes-cortex -e "LETSENCRYPT_HOST=cortex.$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=9000" -e "VIRTUAL_HOST=cortex.$HOSTNAME"  thehiveproject/cortex:latest --es-hostname capes-thehive-elasticsearch

# Rocketchat Service
sudo docker run -d --network capes --restart unless-stopped --name capes-rocketchat -e "LETSENCRYPT_HOST=rocketchat.$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=3000" -e "VIRTUAL_HOST=rocketchat.$HOSTNAME" -e "MONGO_URL=mongodb://capes-rocketchat-mongo:27017/rocketchat" -e "ROOT_URL=http://rocketchat.$HOSTNAME" --link capes-rocketchat-mongo  rocketchat/rocket.chat:latest

# Mumble Service
sudo docker run -d --network capes --restart unless-stopped --name capes-mumble -p 64738:64738 -p 64738:64738/udp -v /var/lib/docker/volumes/mumble-data/_data:/data:z -e SUPW=$mumble_passphrase extra/mumble:latest

## CAPES Monitoring ##

# CAPES Elasticsearch Nodes
sudo docker run -d --network capes --restart unless-stopped --name capes-elasticsearch-1 -v /var/lib/docker/volumes/elasticsearch-1/capes/_data:/usr/share/elasticsearch/data:z --ulimit memlock=-1:-1 -p 9200:9200 -p 9300:9300 -e "cluster.name=capes" -e "node.name=capes-elasticsearch-1" -e "cluster.initial_master_nodes=capes-elasticsearch-1" -e "bootstrap.memory_lock=true" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" docker.elastic.co/elasticsearch/elasticsearch:7.0.0

sudo docker run -d --network capes --restart unless-stopped --name capes-elasticsearch-2 -v /var/lib/docker/volumes/elasticsearch-2/capes/_data:/usr/share/elasticsearch/data:z --ulimit memlock=-1:-1 -e "cluster.name=capes" -e "node.name=capes-elasticsearch-2" -e "cluster.initial_master_nodes=capes-elasticsearch-1" -e "bootstrap.memory_lock=true" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" -e "discovery.seed_hosts=capes-elasticsearch-1,capes-elasticsearch-3" docker.elastic.co/elasticsearch/elasticsearch:7.0.0

sudo docker run -d --network capes --restart unless-stopped --name capes-elasticsearch-3 -v /var/lib/docker/volumes/elasticsearch-3/capes/_data:/usr/share/elasticsearch/data:z --ulimit memlock=-1:-1 -e "cluster.name=capes" -e "node.name=capes-elasticsearch-3" -e "cluster.initial_master_nodes=capes-elasticsearch-1" -e "bootstrap.memory_lock=true" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" -e "discovery.seed_hosts=capes-elasticsearch-1,capes-elasticsearch-2" docker.elastic.co/elasticsearch/elasticsearch:7.0.0

# CAPES Kibana
sudo docker run -d --network capes --restart unless-stopped --name capes-kibana -e "LETSENCRYPT_HOST=kibana.$HOSTNAME" -e "LETSENCRYPT_EMAIL=$EMAIL" -e "VIRTUAL_PORT=5601" -e "VIRTUAL_HOST=kibana.$HOSTNAME" --network capes --link capes-elasticsearch-1:elasticsearch docker.elastic.co/kibana/kibana:7.0.0

# CAPES Heartbeat
sudo docker run -d --network capes --restart unless-stopped --name capes-heartbeat --network capes --user=heartbeat -v $(pwd)/heartbeat.yml:/usr/share/heartbeat/heartbeat.yml:z docker.elastic.co/beats/heartbeat:7.0.0 -e -E output.elasticsearch.hosts=["capes-elasticsearch-1:9200"]

# CAPES Metricbeat
sudo docker run -d --network capes --restart unless-stopped --name capes-metricbeat --network capes --user=root -v $(pwd)/metricbeat.yml:/usr/share/metricbeat/metricbeat.yml:z -v /var/run/docker.sock:/var/run/docker.sock:z -v /sys/fs/cgroup:/hostfs/sys/fs/cgroup:z -v /proc:/hostfs/proc:z -v /:/hostfs:z docker.elastic.co/beats/metricbeat:7.0.0 -e -E output.elasticsearch.hosts=["capes-elasticsearch-1:9200"]

# Wait for Elasticsearch to become available
echo "Elasticsearch takes a negotiate it's cluster settings and come up. Give it a minute."
while true
do
  STATUS=$(curl -sL -o /dev/null -w '%{http_code}' http://127.0.0.1:9200)
  if [ $STATUS -eq 200 ]; then
    echo "Elasticsearch is up. Proceeding"
    break
  else
    echo "Elasticsearch still loading ($STATUS). Trying again in 10 seconds"
  fi
  sleep 10
done

# Adjust the Elasticsearch bucket size
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
    "persistent" : {
        "search.max_buckets" : "100000000"
    }
}
'

################################
### Firewall Considerations ####
################################
# Make firewall considerations
# Port 80 - Nginx (landing page)
# Port 3000 - Rocketchat
# Port 4000 - Gitea
# Port 5000 - Etherpad
# Port 5601 - Kibana
# Port 64738 - Mumble
# Port 8000 - Cyberchef
# Port 9000 - TheHive
# Port 9001 - Cortex (TheHive Analyzer Plugin)
sudo firewall-cmd --add-port=80/tcp --add-port=443/tcp --add-port 64738/udp --add-port 64738/tcp --permanent
sudo firewall-cmd --reload

################################
######### Success Page #########
################################
clear
echo "Please see the "Build, Operate, Maintain" documentation for the post-installation steps."
echo "The CAPES landing page has been successfully deployed. Browse to http://$HOSTNAME to begin using the services."
