#!/bin/bash
# Test Pprogram for nginx-upstream-configure

# Get the directory where the script is installed
test_dir=$(dirname "$(realpath "$0")")
source $test_dir/utils.sh
# Change to the project root directory
cd $test_dir/..
set -e
cargo build
cd test
rm -rf var
mkdir -p var/conf.d
mkdir -p var/upstreams.d
cp db.example.com var/db.example.com
cp default.conf var/conf.d/default.conf
add_a_record 1
setup_upstream_definition
docker compose up -d
sleep 3
expect_number_of_lines 6 docker compose ps --status running
check_server 1
check_server 2 "not exist"
check_server 3 "not exist"
check_http_response "I am app1"
checkout_log
grep_log "add new IP address: 172\.20\.0\.6"
echo "INFO: test rolling update 1->1+2->2"
add_a_record 2
sleep 5
checkout_log
grep_log "add new IP address: 172\.20\.0\.7"
check_server 1 "not exist"
check_server 2
check_server 3 "not exist"
check_http_response "I am app2"
remove_a_record 1
sleep 5
checkout_log
grep_log "remove IP address: 172\.20\.0\.6"
check_server 1 "not exist"
check_server 2
check_server 3 "not exist"
check_http_response "I am app2"
echo "INFO: test rolling update 2+3->1+2+3->1+3"
add_a_record 3
setup_upstream_definition 2
sleep 3
check_http_response "I am app[23]"
add_a_record 1
sleep 5
checkout_log
grep_log "add new IP address: 172\.20\.0\.6"
check_server 1
check_server 2 "not exist"
check_server 3
check_http_response "I am app[13]"
remove_a_record 2
sleep 5
checkout_log
grep_log "remove IP address: 172\.20\.0\.7"
check_server 1
check_server 2 "not exist"
check_server 3
echo "INFO: round-robin test"
check_http_response "I am app[13]"
check_http_response "I am app[13]"
check_http_response "I am app[13]"
check_http_response "I am app[13]"
check_http_response "I am app[13]"
echo "INFO: disable server temporarily"
stop_upstream 1
check_http_response "I am app3"
check_http_response "I am app3"
checkout_log
upstream='upstream: "http://172\.20\.0\.6:80/index.txt"'
grep_log "upstream server temporarily disabled.*$upstream"
echo "INFO: test detecting server recovery"
start_upstream 1
sleep 15
check_http_response "I am app[13]"
check_http_response "I am app[13]"
check_http_response "I am app[13]"
check_http_response "I am app[13]"
check_http_response "I am app[13]"
echo "INFO: test rolling update 1+3->1->2+3"
remove_a_record 3
sleep 5
checkout_log
grep_log "remove IP address: 172\.20\.0\.8"
check_server 1
check_server 2 "not exist"
check_server 3 "not exist"
check_http_response "I am app[1]"
add_a_record 2
sleep 5
checkout_log
grep_log "add new IP address: 172\.20\.0\.7"
check_server 1
check_server 2
check_server 3 "not exist"
check_http_response "I am app[12]"
echo "INFO: test rolling update 1->empty->2"
remove_a_record 2
setup_upstream_definition 1
check_server 1
check_server 2 "not exist"
check_server 3 "not exist"
remove_a_record 1
sleep 5
check_server 1 "not exist"
check_server 2 "not exist"
check_server 3 "not exist"
check_http_response "No upstream server"
add_a_record 2
sleep 30
checkout_log
grep_log "add new IP address: 172\.20\.0\.7"
check_server 1 "not exist"
check_server 2
check_server 3 "not exist"
check_http_response "I am app[2]"
echo "INFO: test port number"
setup_upstream_definition 1 8080
check_server 1 "not exist"
check_server 2
check_server 3 "not exist"
check_http_response -2 "I am app[2] of 8080"
echo "INFO: test multiple upstreams"
add_a_record -2 1
cp default2.conf var/conf.d/default2.conf
setup_upstream_definition
setup_upstream_definition -2 1 8080
check_server 1 "not exist"
check_server 2
check_server 3 "not exist"
check_server -2 1
check_server -2 2 "not exist"
check_server -2 3 "not exist"
check_http_response "I am app2"
check_http_response -8080 -2 "I am app1 of 8080"
echo "INFO: test upstream is down"
stop_upstream 1
check_http_response -8080 -status "504"
check_http_response "I am app2"
echo "INFO: test upstream recovery"
start_upstream 1
sleep 15
check_http_response "I am app2"
check_http_response -8080 -2 "I am app1 of 8080"

# TODO: test custoization by environment variables