# DNSDog

DNSDog is a small utility for generating metrics for DNS queries and replies and sending them to statsd. It's functionally similar to the [DNS plugin for collectd](https://collectd.org/wiki/index.php/Plugin:DNS) but optimized for datadog.

![](https://s3.amazonaws.com/ejholmes.github.com/lbLcK.png)

## Usage

Start watching for DNS packets on `eth0` and send them to statsd:

```
$ dnsdog -iface eth0
```

## Metrics

DNSDog generates the following metrics and tags:

```
dns.query{op_code}
dns.question{op_code,query,query_type}
dns.reply{response_code}
dns.reply.question{response_code,query,query_type}
dns.answer{response_code,query,query_type}
dns.reply.time{response_code}
```
