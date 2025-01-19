# nginx-upstream-configure

This program periodically queries DNS for the IP address of the specified FQDN and dynamically updates nginx's upstream settings.

## Upstream definition file

Upstream definition file is a configuraion for upstream directive on nginx.The format is yaml include following element.

|element|description|
|--|--|
|name|The name of upstream to be referenced by proxy_pass directive in location defined in other configuration file.|
|fqdn|The fqdn of upstream web server.|
|port|The port number of upstream web server. This can be omitted. If ommited, the server directive generated with no port number.|
|maxips|The number of server directive for each ip address returned by DNS.If DNS returns more IP addresses than the number specified here, server directives will be generated in order from the newest one, and the remaining ones will be discarded. Default is 1.| 
## Procedure

1. Read all configuration files (in YAML format with a .yml extension) under /etc/nginx/upstreams.d and execute the initialization process described in steps 2 and beyond for each configuration file. If the name element in the configuration file is duplicated across multiple files, an error will occur. Hereafter, the value of the name element in the configuration file will be referred to as the upstream name.
2. Initialize an empty IP address table for each upstream.
3. Generate an upstream configuration file named /etc/nginx/conf.d/upstream_name.conf with the content "upstream upstream_name {server 127.0.0.1:10080}".This cause 502 error when access the application via http.
4. After completing the initialization process for all upstreams, start nginx and remember its process ID. Monitor the started process, and If the process ends within 1 second, the program will end with an error.
5. Execute the following steps 6 and beyond in parallel for each configuration file.
6. Query the FQDN specified in the fqdn element of the configuration file via DNS. If the retuned IP address is not registered in the previous IP address table, register it and set the current time as the registration time. Also, remove any unnecessary entries from the IP address table. If the DNS query fails, clear the IP address table.
7. If there is no change in the IP address table maintained as step 6, skip to step 10. If there is a change, execute steps 8 and 9. At this time, acquire a lock to prevent conflicts with other configuration thread.
8. Output the upstream configuration file named /etc/nginx/conf.d/upstream_name.conf. This configuration file should contain a single upstream directive with the upstream name. Inside the upstream directive, output the number of server directives specified by the maxips element in the configuration file (default is 1). Output the server directives in order of the most recently registered IP addresses from the IP address table, and do not output any excess entries. If the port element is specified in the configuration file, add the port number to the server directive. If the IP address table is empty, output "upstream upstream_name {server 127.0.0.1:10080}".
9. And then send a SIGHUP signal to the nginx process to gracefully reload nginx.
10. Sleep until the DNS TTL expires.
11. Return to step 6 and repeat the loop.
When a shutdown signal is received, stop all configuration threds  and send a SIGQUIT signal to the nginx process to shut down nginx and terminate the program.