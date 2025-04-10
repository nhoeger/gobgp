# Copy the router_config_files to /tmp
sudo cp -r router_config_files /tmp/router_config_files

# Loop through the configuration files and run Docker containers in the background
for i in {1..3}
do
  sudo docker run --name gobgp-router-$i --rm -d -v /tmp/router_config_files/${i}_router.conf:/root/demo.conf gobgp
done

# Remove the router_config_files after the containers are started
sudo rm -rf /tmp/router_config_files