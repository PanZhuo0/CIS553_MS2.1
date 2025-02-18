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
