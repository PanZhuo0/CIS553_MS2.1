# CIS553_MS2.1

快速到达目录
> cd my_project1_repo/
> 
> docker-compose build cis553
> 
> sudo  docker-compose run --rm cis553
> 
> cd Sp25-cis553-Project1-Group14/

测试
> ./waf --run "simulator-main --routing=LS --scenario=scratch/scenarios/10-ls.sce --inet-topo=scratch/topologies/10.topo --result-check=scratch/results/10-ls.output"


密码
> mcit


事件
```python
#* LS VERBOSE ALL OFF
#* DV VERBOSE ALL OFF
#* APP VERBOSE ALL OFF
#* LS VERBOSE STATUS OFF
#* LS VERBOSE ERROR OFF
#* DV VERBOSE STATUS OFF
#* DV VERBOSE ERROR OFF
#* APP VERBOSE STATUS OFF
#* APP VERBOSE ERROR OFF
#* LS VERBOSE TRAFFIC OFF
#* APP VERBOSE TRAFFIC OFF
LS VERBOSE ALL ON

# Advance Time pointer by 60 seconds. Allow the routing protocol to stabilize.
TIME 60000

# Bring down Link Number 6.
LINK DOWN 6
TIME 10000

# Bring up Link Number 6.
LINK UP 6
TIME 10000

# Bring down all links of node 1
NODELINKS DOWN 1
TIME 10000

# Bring up all links of node 1
NODELINKS UP 1
TIME 10000

# Bring down link(s) between nodes 1 and 8
LINK DOWN 1 8
TIME 10000

# Bring up link(s) between nodes 1 and 8
LINK UP 1 8
TIME 10000

# Dump Link State Neighbor Table.
1 LS DUMP NEIGHBORS

# Dump Link State Routing Table.
1 LS DUMP ROUTES

# Quit the simulator. Commented for now.
QUIT

```

PDF 中给出的LS 的实现方法
```readme
9.1 Link-state Routing
Link State routing protocols hold at least 2 distinctive tables: a neighbor table, and an actual routing
table. Link state routing operation follows four simple steps; each link state enabled router must perform
the following:
1. Neighbor discovery Your node continuously probes the network at a low rate to discover its
immediate neighbors in the network topology.
There are many design choices / implementations, here we list one of the possible implementations, you are not required to use this implementation. Feel free to use other methods.
Suggested implementation: Write three methods: ”ProcessHelloReq, ProcessHelloRsp and
BroadcastPacket”
(a) ProcessHelloReq
Once received a ”hello” message, neighboring nodes respond with a “hello reply” message
with their IP addresses.
(b) ProcessHelloRsp
Once received a ”hello reply” message, and the destination address is own address, then
process the message:
• If it is a new neighbor, add to ”m neighbors” table.
• If the neighbor exists, update ”m neighbors” table, since the timestamp changed, also
the link cost might be changed as well (for extra credit)
(c) BroadcastPacket
It can be called in ProcessHelloReq, periodic broadcast “hello” message on all outgoing
interfaces to neighboring nodes to inform them of the node’s presence. The TTL of the
broadcast message has to be set to 1, to avoid flooding the message to entire network.
Some basic guidelines:
• You may add additional packet types for “hello” message and ”hello reply” message. The
”hello” and ”hello reply” message should mirror the ping/pong message code.
• Neighbors disappear as well as appear (as specified in the scenario file or via the interactive
command line). For debugging, you may want to print out the current list of neighbors so
you can see who they are, perhaps only printing when there is a change.
• You will need to use timers to implement continuous, low-rate background activity. Be very
careful with automated mechanisms, especially when using flooding and broadcast! They
should operate on the timescale of at least tens of seconds (tens of thousands of milliseconds
in the API calls!).
• Add the following command to your node: ”DUMP NEIGHBORS” to dump a list of all of
the neighbors to which your node believes it is currently connected. Each neighbor entry
should include 〈neighbor node number, neighbor IP address, interface IP address〉. Node
number can be retrieved by calling ”ReverseLookup()” method. Since our focus is on the
routing algorithm, the interface IP address for each LS message is given in the starter code,
you can pass that as an parameter in your code.
13
2. Flooding To tell all nodes about all neighbors.
It is recommended to add another message type for link state packet.
Your flooding protocol should not result in infinite packet loops or unnecessary duplicate packets
(i.e. a node should not forward a link-state packet it has seen previously, or if it has seen a
more recent one). A key design choice is whether to send out a LinkState packet periodically
or immediately after the neighbor list changes. A key design criterion is to distribute link state
information using as few packets as possible, while keeping nodes as up to date as possible.
There are many design choices / implementations, here we list one of the possible implementations, you are not required to use this implementation. Feel free to use other methods.
Suggested implementation: Write three methods: ”LSAdvertisement, ProcessLsp, and Flood”
(a) LSAdvertisement
Generate packet that contains all its neighbors information (include but not limited to ip
address, cost, TTL, etc) and broadcast to all its neighbors.
(b) ProcessLsp
Once received a ”lsa” message,
• If the message is from a new node: add to ”m validLSP” and flood the message.
• If the message is from an existing node in ”m validLSP”, but with a newer time-stamp:
update ”m validLSP” and flood the message.
(c) Flood
It is called in ProcessLsp. It copies the packet and broadcast the packet to every other ports
except the coming port
3. Apply the Dijkstra algorithm to construct the shortest path
See the details in the Peterson textbook for a good suggestion on how to implement Dijkstra’s
algorithm. The result of this algorithm should be a routing table containing the next-hop neighbor
to send to for each destination address as well as the cost of this route.
4. Forwarding To send packets using the next-hops.
You should forward packets using the next-hop neighbors in your calculated routing table.
Note, when your node receives a packet, it may perform one of three actions:
(a) if the packet is destined for the node, it will ”deliver” the packet locally;
(b) if the packet is destined for another node, it will ”route” the packet; (See Section 3)
(c) if the packet is destined for the broadcast address, it will both deliver packet locally, and
continue flooding the packet (while avoiding infinite loops)
Add a command to your node: ”DUMP ROUTES” to dump the contents of the routing table. You
may find this more convenient than logging the entire routing table after every change. Note that this
command is already in the skeleton code, and you need to find the function that corresponds to this
command and modify it accordingly. Each routing table entry should contain 〈destination node number,
destination IP address, next hop node number, next hop IP address, interface IP address, cost〉
Once you have completed all of the above, you should be able to ping any other node (by node
number) in the network, and have a packet travel to that node and back without being unnecessarily
flooded throughout the network. To see that your protocol is working, we have provided an example
test scenario. (Read Section 5 of code documentation for details.) For your own testing purposes, you
might want to set up a small ring network, use ping to test whether you can reach remote nodes, and
then break reachability by stopping a node on the path so that ping no longer receives a response. Your
routing protocol should detect this and repair the situation by finding an alternative path. When it does,
ping will work again. Congratulations! You have a real, working network!
```
