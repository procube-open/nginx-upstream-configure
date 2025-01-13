$TTL    30
@       IN      SOA     ns.example.com. root.example.com. (
                              2         ; Serial
                         30         ; Refresh
                          30         ; Retry
                        30         ; Expire
                         30 )       ; Negative Cache TTL
;
        IN      NS      ns.example.com.
app     IN      A       172.20.0.6  ; IP address of app1 container
app     IN      A       172.20.0.7  ; IP address of app2 container
app     IN      A       172.20.0.8  ; IP address of app3 container
