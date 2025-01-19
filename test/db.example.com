$TTL    5
@       IN      SOA     ns.example.com. root.example.com. (
                              3         ; Serial
                             20         ; Refresh
                             20         ; Retry
                            120         ; Expire
                             5 )       ; Negative Cache TTL
        IN      NS      ns.example.com.
