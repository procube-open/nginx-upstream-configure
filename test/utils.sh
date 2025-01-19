# utilities

# Function to restart container if it is running
restart_container() {
  local container_name=$1
  local sleep_time=$2
  local status=$(docker inspect -f '{{.State.Status}}' $container_name 2>/dev/null)

  if [ "$status" == "running" ]; then
    echo "INFO: Restarting $container_name container..."
    docker restart $container_name > /dev/null
    if [[ -n $sleep_time ]]; then
      sleep $sleep_time
    fi
  else
    echo "INFO: $container_name container is not running or does not exist."
  fi
}

start_upstream() {
  local container_id=$1
  docker start "app$container_id" > /dev/null
  echo "INFO: Started app$container_id container"
}

stop_upstream() {
  local container_id=$1
  docker stop "app$container_id" > /dev/null
  echo "INFO: Stopped app$container_id container"
}

# Check if a command prints the expected number of lines
expect_number_of_lines() {
  local expected=$1
  shift
  local command=$@
  local actual=$(eval $command | wc -l)
  if [ $actual -ne $expected ]; then
    echo "TEST NG: Expected $expected lines printed by '$(echo $command)', but got $actual"
    exit 1
  fi
  echo "TEST OK: $expected lines printed by '$(echo $command)'"
}

# Manage DNS records
add_a_record() {
  if [[ "$1" == "-2" ]]; then
    local suffix="2"
    shift
  fi
  local name="app$suffix"
  local ip="172.20.0.$(( $1+5 ))"
  local zone_file=var/db.example.com
  echo "$name IN A $ip" >> $zone_file
  echo "INFO: Added a record $name IN A $ip to the zone"
  restart_container coredns
}

remove_a_record() {
  if [[ "$1" == "-2" ]]; then
    local suffix="2"
    shift
  fi
  local name="app$suffix"
  local ip="172.20.0.$(( $1+5 ))"
  local zone_file=var/db.example.com
  sed -i "/$name IN A $(echo $ip | sed -e 's/\./\\./g')/d" $zone_file
  echo "INFO: Remove the record $name IN A $ip from the zone"
  restart_container coredns
}

# Check the HTTP Response body
check_http_response() {
  if [[ "$1" == "-8080" ]]; then
    local port=":8080"
    shift
  fi
  if [[ "$1" == "-2" ]]; then
    local suffix="2"
    shift
  fi
  if [[ "$1" == "-status" ]]; then
    local status_opts="-o /dev/null -w "%{http_code}""
    shift
  fi
  local pattern=$1
  local app="http://172.20.0.2$port/index${suffix}.txt"
  local actual="$(curl -s $status_opts $app)"
  if [[ ! "$actual" =~ $pattern ]]; then
    echo "TEST NG: Expected HTTP response body match with '$pattern', but got '$actual'"
    exit 1
  fi
  echo "TEST OK: HTTP response body='$actual'"
}

# Check the upstream configuration file
check_server () {
  if [[ "$1" == "-2" ]]; then
    local suffix="2"
    shift
  fi
  local server_id=$1
  local mode=${2:-exist}
  local server_ip="172.20.0.$(( $server_id + 5 ))"
  local file=var/conf.d/app${suffix}.conf
  if egrep "server $(echo $server_ip | sed -e 's/\./\\./g')(:[0-9]+)?;" $file > /dev/null; then
    if [[ $mode == "exist" ]]; then
      echo "TEST OK: Found server $server_id ip='$server_ip' in the configuration file."
    else
      echo "TEST NG: Found server $server_id ip='$server_ip' in the configuration file."
      exit 1
    fi
  else
    if [[ $mode == "exist" ]]; then
      echo "TEST NG: Did not find server $server_id ip='$server_ip' in the configuration file."
      exit 1
    else
      echo "TEST OK: Did not find server $server_id ip='$server_ip' in the configuration file."
    fi
  fi
}

# Check the log file for a pattern
checkout_log() {
  local pattern="$1"
  local since_opts=
  local log_file=var/nginx-upstream-configure.log
  local checked_time_file=var/prev_checked_time.log
  if [[ -r $checked_time_file ]]; then
    since_opts="--since $(date -d @$(cat $checked_time_file) --iso-8601=seconds)"
  fi
  docker logs $since_opts nginx-upstream-configure >& $log_file
  date +%s > $checked_time_file
}

grep_log() {
  local pattern="$1"
  local log_file=var/nginx-upstream-configure.log
  if grep "$pattern" $log_file > /dev/null; then
    echo "TEST OK: Found '$pattern' in the log file."
  else
    echo "TEST NG: Did not find '$pattern' in the log file."
    exit 1
  fi
}

cleanup() {
  echo "Cleaning up Docker containers..."
  docker-compose down
}

# Setup the upstream definition file
setup_upstream_definition() {
  if [[ "$1" == "-2" ]]; then
    local suffix="2"
    shift
  fi
  local maxips=$1
  local port=$2
  cp app${suffix}.yml var/upstreams.d/app${suffix}.yml
  if [[ -n $maxips ]]; then
    echo "maxips: $maxips" >> var/upstreams.d/app${suffix}.yml
  fi
  if [[ -n $port ]]; then
    echo "port: $port" >> var/upstreams.d/app${suffix}.yml
  fi
  restart_container nginx-upstream-configure 3
}

trap cleanup EXIT
