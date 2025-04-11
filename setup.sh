# Copy the router_config_files to /tmp
cd /home/nils/Dokumente/ASPA+/NIST-BGP-SRx

# Start the RPKI Server 
echo "add 10.0.0.0/8 9 7675" > ./rpkirtr_svr.conf
gnome-terminal -- bash -c "docker run --rm -it --name rpkirtr_server \
    -v $PWD/./rpkirtr_svr.conf:/usr/etc/rpkirtr_svr.conf \
    -p 323:323 \
    nist/bgp-srx \
    rpkirtr_svr -f /usr/etc/rpkirtr_svr.conf"
sleep 1
# Start the SRx-Server 
sed "s/localhost/$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' rpkirtr_server)/g" ./srx-server/src/server/srx_server.conf > /tmp/srx_server.conf
gnome-terminal -- bash -c "docker run --rm -d -it --name srx_server \
    -v /tmp/srx_server.conf:/usr/etc/srx_server.conf \
    -v $PWD/./examples/bgpsec-keys/:/usr/opt/bgp-srx-examples/bgpsec-keys \
    -p 17900:17900 -p 17901:17901 \
    nist/bgp-srx \
    srx_server -f /usr/etc/srx_server.conf"

sleep 1
cd ../gobgp

cp /home/nils/Dokumente/ASPA+/gobgp/router_config_files/1_router.conf /tmp/1_router.conf

#sudo cp -r router_config_files /tmp/router_config_files
# Loop through the configuration files and run Docker containers in the background
for i in {1..2}
do
  gnome-terminal -- bash -c docker run --name gobgp-router-$i --rm -d -v router_config_files/${i}_router.conf:/root/demo.conf gobgp
  sleep 1
done

# Remove the router_config_files after the containers are started
# sudo rm -rf /tmp/router_config_files
