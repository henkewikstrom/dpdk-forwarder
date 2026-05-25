# dpdk-forwarder
**Author:** Henrik Wikström

A multi-core packet forwarder using DPDK implementing flow tracking, per flow statistics and idle flow expiry.

## Architecture
```
Rx (main-lcore / dispatcher core)
|
|- Removes expired flows
|- Calculates hash
|- Insert in flow table
|- Enqueues to pinned worker or least loaded
|
|- Worker ring 0 -> worker core 0 -> TX
|- Worker ring n -> worker core n -> TX
```

The dispatcher core handles RX, flow classification as well as managing the flow table.

Each worker dequeues its owned flows, transmits them, update statistics and writes to a CSV file.

## Flow Tracking
Flow ID's are a result of rte_jhash based on the 5 tuple:
- Source IP
- Destination IP
- Source port
- Destination port
- L4 protocol

New flows are assigned to the worker with least active flows.
Active flows are processed by the same worker core.
Flows are being removed from the flow table by the dispatcher after a configurable timeout.

## Flow Statistics
Worker cores update the following metrics in real-time:
- RX bytes
- TX bytes
- RX packets
- TX packets

Statistics of all active flows are written to a CSV file at a configurable interval. One file per worker is written to working directory `flow_stats_core_X.csv`

Statitics are cumulative and will be reset when the flow goes inactive.
```
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,rx_bytes,tx_bytes,rx_pkts,tx_pkts
2026-05-25 21:00:55,10.170.16.120,10.128.80.154,58312,887,TCP,4590,4590,85,85
2026-05-25 21:00:55,10.62.137.82,10.138.104.219,46773,1007,UDP,3276,3276,78,78
2026-05-25 21:00:55,10.138.246.219,10.253.19.52,41324,620,UDP,3612,3612,86,86
```

## Design Notes
- Flow table is written to exclusively by the dispatcher core to avoid concurrent writes.
- Worker rings and statistics buffers are allocated on the NUMA socket of the respective worker core.
- A software dispatcher handles flow distribution, removing the need for RSS and allowing the application to run on any NIC.
- IPv6 is not supported, only IPv4 traffic is handled.

## Requirements
- Linux kernel
- DPDK installed and ldconfig updated
- Hugepages configured
- Two network interfaces
- Python3 if using injector.py to generate traffic

## Allocate hugepages
```bash
echo 512 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

## Create two pcap interfaces
```bash
sudo ip link add dpdk0 type veth peer name dpdk0_peer
sudo ip link add dpdk1 type veth peer name dpdk1_peer

sudo ip link set dpdk0 up
sudo ip link set dpdk0_peer up
sudo ip link set dpdk1 up
sudo ip link set dpdk1_peer up
```

## Build
```bash
make
make debug  # debug build (O0, debug symbols + verbose logging)
```

| Flag | Default | Description |
|------|---------|-------------|
| `LOG_LEVEL` | `RTE_LOG_INFO` | Application log level |
| `LOG_LEVEL_DP` | `RTE_LOG_NOTICE` | Data plane log level (compiled out when below DEBUG) |

## Launch
```bash
sudo ./bin/dpdk_forwarder -l 0-3 \
  --vdev "net_pcap0,rx_iface=dpdk0,tx_pcap=/tmp/out.pcap" \
  --vdev "net_pcap1,rx_iface=dpdk1,tx_pcap=/tmp/out1.pcap" \
  -- -i <stats_interval_sec> -t <flow_timeout_sec>
```
Example:
```bash
sudo ./bin/dpdk_forwarder -l 0-3 \
  --vdev "net_pcap0,rx_iface=dpdk0,tx_pcap=/tmp/out.pcap" \
  --vdev "net_pcap1,rx_iface=dpdk1,tx_pcap=/tmp/out1.pcap" \
  -- -i 5 -t 30
```
- `-i`: Statistics flush interval in seconds (default: 15)
- `-t`: Flow timeout in seconds (default: 60)

## Inject traffic
```bash
sudo python3 injector.py <number_of_flows> <number_of_pkts> <interface>
```
Example:
```bash
sudo python3 injector.py 600 100 dpdk0_peer
```

- `number_of_flows`: Number of unique flows to send.
- `number_of_pkts`: Number of packets of each flow to send
- `interface`: Interface to send packets to

To verify flow affinity:
- Set a long flow timeout, e.g. 60 seconds, so flows remain active throughout the test.
- Use a `num_flows` that is a multiple of the number of worker cores. e.g. worker cores = 3, num_flows = 300.
- After all traffic has been sent and a stats flush has occurred, count the lines in each CSV file at the last timestamp. There should be num_flows / num_workers entries in each file.