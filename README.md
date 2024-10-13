# Distance Vector in VNL Topology

## Algorithm Overview

The Distance Vector (DV) algorithm, based on the Distributed Bellman-Ford Algorithm, maintains a routing table with entries for **destination**, **cost**, and **next hop**. Routers periodically exchange their tables with neighbors and update their own based on received information.

### Routing Table Update

For routers `i` and `j`, and destination `dest`, the table update follows this logic:

```pseudo
function updateCostAndNextHop(i, dest, j) {
  if (NextHop[i][dest] == j) {
    cost[i][dest] = cost[i][j] + cost[j][dest];
  } else if (cost[i][j] + cost[j][dest] < cost[i][dest]) {
    cost[i][dest] = cost[i][j] + cost[j][dest];
    NextHop[i][dest] = j;
  }
}
```

This minimizes the cost to reach `dest`:

```
cost(i, dest) = min(cost(i, j) + cost(j, dest), cost(i, dest))
```

## VNL Topology

In the VNL topology with three routers, the DV algorithm guarantees shortest path convergence as long as only one link fails.

## Implementation

- Routers fill routing tables based on interface entries if no static routing file is present.
- Periodic **hello** and **LSU** (Link-State Update) messages are exchanged to maintain neighbor information and routing tables.
- Upon receiving an LSU, a router updates its routing table if the received cost is lower than the current cost. Otherwise, it retains the existing entry.
- If a neighbor timeout occurs, its entries are removed from the table.

## Evaluation

Using the script `./check_link_failures.sh`, tests were conducted by toggling links and pinging all IP addresses. The routing tables correctly reflected updated shortest paths after each link failure.

Results: All 12 IPs were reachable after each link failure (vhost1-vhost2, vhost1-vhost3, vhost2-vhost3).
