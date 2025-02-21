/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/internet-module.h"
#include "ns3/ls-routing-protocol.h"
#include "ns3/double.h"
#include "ns3/inet-socket-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-packet-info-tag.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv4.h"
#include "ns3/log.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/test-result.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"
#include <ctime>
#include <queue>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("LSRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED(LSRoutingProtocol);

/********** Miscellaneous constants **********/

/// Maximum allowed sequence number
#define LS_MAX_SEQUENCE_NUMBER 0xFFFF
#define LS_PORT_NUMBER 698


TypeId
LSRoutingProtocol::GetTypeId(void)
{
  static TypeId tid = TypeId("LSRoutingProtocol")
                          .SetParent<PennRoutingProtocol>()
                          .AddConstructor<LSRoutingProtocol>()
                          .AddAttribute("LSPort", "Listening port for LS packets", UintegerValue(5000),
                                        MakeUintegerAccessor(&LSRoutingProtocol::m_lsPort), MakeUintegerChecker<uint16_t>())
                          .AddAttribute("PingTimeout", "Timeout value for PING_REQ in milliseconds", TimeValue(MilliSeconds(2000)),
                                        MakeTimeAccessor(&LSRoutingProtocol::m_pingTimeout), MakeTimeChecker())
                          .AddAttribute("HRTimeout", "Timeout value for Hello_Request in milliseconds", TimeValue(MilliSeconds(5000)), // 5s for neighbor search
                                        MakeTimeAccessor(&LSRoutingProtocol::m_HRTimeout), MakeTimeChecker())
                          .AddAttribute("MaxTTL", "Maximum TTL value for LS packets", UintegerValue(16),
                                        MakeUintegerAccessor(&LSRoutingProtocol::m_maxTTL), MakeUintegerChecker<uint8_t>());
  return tid;
}

//### implement flooding ,Dijkstra and Routetable fresh
//### implement receive LSMESSAGE , IT WILL BE RECALL by the logic of LINE 180 
//void LSRoutingProtol::RecvlLSMessage(Ptr<Socket>socket){ // ### PARAMETER: socket OBJ
//	std::cout << "we need to finish RECVLSMESSAGE LOGIC"
//}

LSRoutingProtocol::LSRoutingProtocol() 
: m_auditPingsTimer(Timer::CANCEL_ON_DESTROY),
m_HRTimer(Timer::CANCEL_ON_DESTROY)
{
  LogComponentEnable("LSRoutingProtocol",LOG_LEVEL_DEBUG);
  m_currentSequenceNumber = 0;
  // Setup static routing
  m_staticRouting = Create<Ipv4StaticRouting>();
}

LSRoutingProtocol::~LSRoutingProtocol() {}

void LSRoutingProtocol::DoDispose()
{
  if (m_recvSocket)
  {
    m_recvSocket->Close();
    m_recvSocket = 0;
  }

  // Close sockets
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin();
       iter != m_socketAddresses.end(); iter++)
  {
    iter->first->Close();
  }
  m_socketAddresses.clear();

  // Clear static routing
  m_staticRouting = 0;

  // Cancel timers
  m_auditPingsTimer.Cancel();
  m_HRTimer.Cancel();

  m_pingTracker.clear();
  PennRoutingProtocol::DoDispose();
}

void LSRoutingProtocol::SetMainInterface(uint32_t mainInterface)
{
  m_mainAddress = m_ipv4->GetAddress(mainInterface, 0).GetLocal();
}

void LSRoutingProtocol::SetNodeAddressMap(std::map<uint32_t, Ipv4Address> nodeAddressMap)
{
  m_nodeAddressMap = nodeAddressMap;
}

void LSRoutingProtocol::SetAddressNodeMap(std::map<Ipv4Address, uint32_t> addressNodeMap)
{
  m_addressNodeMap = addressNodeMap;
}

Ipv4Address
LSRoutingProtocol::ResolveNodeIpAddress(uint32_t nodeNumber)
{
  std::map<uint32_t, Ipv4Address>::iterator iter = m_nodeAddressMap.find(nodeNumber);
  if (iter != m_nodeAddressMap.end())
  {
    return iter->second;
  }
  return Ipv4Address::GetAny();
}

std::string
LSRoutingProtocol::ReverseLookup(Ipv4Address ipAddress)
{
  std::map<Ipv4Address, uint32_t>::iterator iter = m_addressNodeMap.find(ipAddress);
  if (iter != m_addressNodeMap.end())
  {
    std::ostringstream sin;
    uint32_t nodeNumber = iter->second;
    sin << nodeNumber;
    return sin.str();
  }
  return "Unknown";
}

void LSRoutingProtocol::DoInitialize()
{

  if (m_mainAddress == Ipv4Address()){ // if m_mainAddres = 0.0.0.0
    Ipv4Address loopback("127.0.0.1");
    for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); i++)
    {
      // Use primary address, if multiple
      Ipv4Address addr = m_ipv4->GetAddress(i, 0).GetLocal();
      if (addr != loopback)
      {
        m_mainAddress = addr;
        break;
      }
    }

    NS_ASSERT(m_mainAddress != Ipv4Address());
  }

  NS_LOG_DEBUG("Starting LS on node " << m_mainAddress);

  bool canRunLS = false;
  // Create sockets
  for (uint32_t i = 0; i < m_ipv4->GetNInterfaces(); i++)
  {
    Ipv4Address ipAddress = m_ipv4->GetAddress(i, 0).GetLocal();
    if (ipAddress == Ipv4Address::GetLoopback())
      continue;

    // Create a socket to listen on all the interfaces
    if (m_recvSocket == 0)
    {
      m_recvSocket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
      m_recvSocket->SetAllowBroadcast(true);
      InetSocketAddress inetAddr(Ipv4Address::GetAny(), LS_PORT_NUMBER);
      m_recvSocket->SetRecvCallback(MakeCallback(&LSRoutingProtocol::RecvLSMessage, this)); // ### this function will callback RECVLSMESSAGE (define by us== STUDENT)
      if (m_recvSocket->Bind(inetAddr))
      {
        NS_FATAL_ERROR("Failed to bind() LS socket");
      }
      m_recvSocket->SetRecvPktInfo(true);
      m_recvSocket->ShutdownSend();
    }

    // Create socket on this interface
    Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
    socket->SetAllowBroadcast(true);
    InetSocketAddress inetAddr(m_ipv4->GetAddress(i, 0).GetLocal(), m_lsPort);
    socket->SetRecvCallback(MakeCallback(&LSRoutingProtocol::RecvLSMessage, this));
    if (socket->Bind(inetAddr))
    {
      NS_FATAL_ERROR("LSRoutingProtocol::DoInitialize::Failed to bind socket!");
    }
    socket->BindToNetDevice(m_ipv4->GetNetDevice(i));
    m_socketAddresses[socket] = m_ipv4->GetAddress(i, 0);
    canRunLS = true;
  }

  if (canRunLS)
  {
    AuditPings();
    NS_LOG_DEBUG("Starting LS on node " << m_mainAddress);
  }
}

void LSRoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
  // You can ignore this function
}

Ptr<Ipv4Route>
LSRoutingProtocol::RouteOutput(Ptr<Packet> packet, const Ipv4Header &header, Ptr<NetDevice> outInterface,
                               Socket::SocketErrno &sockerr)
{
  Ptr<Ipv4Route> ipv4Route = m_staticRouting->RouteOutput(packet, header, outInterface, sockerr);
  if (ipv4Route)
  {
    DEBUG_LOG("Found route to: " << ipv4Route->GetDestination() << " via next-hop: " << ipv4Route->GetGateway()
                                 << " with source: " << ipv4Route->GetSource() << " and output device "
                                 << ipv4Route->GetOutputDevice());
  }
  else
  {
    DEBUG_LOG("No Route to destination: " << header.GetDestination());
  }
  return ipv4Route;
}

bool LSRoutingProtocol::RouteInput(Ptr<const Packet> packet, const Ipv4Header &header, Ptr<const NetDevice> inputDev,
                                   UnicastForwardCallback ucb, MulticastForwardCallback mcb, LocalDeliverCallback lcb,
                                   ErrorCallback ecb)
{
  Ipv4Address destinationAddress = header.GetDestination();
  Ipv4Address sourceAddress = header.GetSource();

  // Drop if packet was originated by this node
  if (IsOwnAddress(sourceAddress) == true)
  {
    return true;
  }

  // Check for local delivery
  uint32_t interfaceNum = m_ipv4->GetInterfaceForDevice(inputDev);
  if (m_ipv4->IsDestinationAddress(destinationAddress, interfaceNum))
  {
    if (!lcb.IsNull())
    {
      lcb(packet, header, interfaceNum);
      return true;
    }
    else
    {
      return false;
    }
  }

  // Check static routing table
  if (m_staticRouting->RouteInput(packet, header, inputDev, ucb, mcb, lcb, ecb))
  {
    return true;
  }

  DEBUG_LOG("Cannot forward packet. No Route to destination: " << header.GetDestination());
  return false;
}

// pakc
void LSRoutingProtocol::BroadcastPacket(Ptr<Packet> packet)
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i = m_socketAddresses.begin();
       i != m_socketAddresses.end(); i++)
  {
    Ptr<Packet> pkt = packet->Copy();  // Inpute Ptr<Packet> parameter
    Ipv4Address broadcastAddr = i->second.GetLocal().GetSubnetDirectedBroadcast(i->second.GetMask());
    i->first->SendTo(pkt, 0, InetSocketAddress(broadcastAddr, LS_PORT_NUMBER));
  }
}

//process CMD 
//LINK UP 6
//
void LSRoutingProtocol::ProcessCommand(std::vector<std::string> tokens)
{
  std::vector<std::string>::iterator iterator = tokens.begin();
  std::string command = *iterator;

  if (command == "PING")
  {
    if (tokens.size() < 3)
    {
      ERROR_LOG("Insufficient PING params...");
      return;
    }
    iterator++;
    std::istringstream sin(*iterator);
    uint32_t nodeNumber;
    sin >> nodeNumber;
    iterator++;
    std::string pingMessage = *iterator;
    Ipv4Address destAddress = ResolveNodeIpAddress(nodeNumber);
    DEBUG_LOG("Here!");
    if (destAddress != Ipv4Address::GetAny())
    {
      uint32_t sequenceNumber = GetNextSequenceNumber();
      TRAFFIC_LOG("Sending PING_REQ to Node: " << nodeNumber << " IP: " << destAddress << " Message: "
                                               << pingMessage << " SequenceNumber: " << sequenceNumber);
      Ptr<PingRequest> pingRequest = Create<PingRequest>(sequenceNumber, Simulator::Now(), destAddress, pingMessage);
      // Add to ping-tracker
      m_pingTracker.insert(std::make_pair(sequenceNumber, pingRequest));
      Ptr<Packet> packet = Create<Packet>();
      LSMessage lsMessage = LSMessage(LSMessage::PING_REQ, sequenceNumber, m_maxTTL, m_mainAddress);
      lsMessage.SetPingReq(destAddress, pingMessage);
      packet->AddHeader(lsMessage);
      BroadcastPacket(packet);
    }
  }

  else if (command == "DUMP")
  {
NS_LOG_INFO("[INFO]: Dump Command executing!");
    if (tokens.size() < 2)
    {
      ERROR_LOG("Insufficient Parameters!");
      return;
    }
    iterator++;
    std::string table = *iterator;
    if (table == "ROUTES" || table == "ROUTING")
    {
      DumpRoutingTable();
    }
    else if (table == "NEIGHBORS" || table == "neighborS")
    {
      DumpNeighbors();
    }
    else if (table == "LSA")
    {
      DumpLSA();
    }
  }

  else if(command == "LINK")
  {
	  NS_LOG_INFO("LINK using !!");
  }
}

void LSRoutingProtocol::DumpLSA()
{
  STATUS_LOG(std::endl
             << "**************** LSA DUMP ********************" << std::endl
             << "Node\t\tNeighbor(s)");
  PRINT_LOG("");
}

void LSRoutingProtocol::DumpNeighbors()
{
  STATUS_LOG(std::endl
             << "**************** Neighbor List ********************" << std::endl
             << "NeighborNumber\t\tNeighborAddr\t\tInterfaceAddr");

  /* NOTE: For purpose of autograding, you should invoke the following function for each
  neighbor table entry. The output format is indicated by parameter name and type.
  */
  
  PRINT_LOG((m_neighbors.size())); 
  //Detail of neighbors
  std::cout << "dumping neighbor list !!!";
  PRINT_LOG("pesudo DATA");
  Ipv4Address a("192.168.1.1");
  Ipv4Address b("192.168.1.2");
  Ipv4Address c("192.168.1.3");
  Neighbor n; 
  n.node = 12;
  n.address = a;
  n.interfaceAddress=b;
  m_neighbors[a]=n;
  for (auto& entry : m_neighbors){
  // m_neighbors Map<IP,Neighbor>
  // Neighbor: ==> [IP,interface Addres ID,TIme lastHello]
  //each neighbor talbe entry should invoke this function ==> checkNeighborTableEntry();
  //<< "NeighborNumber\t\tNeighborAddr\t\tInterfaceAddr");
	std::cout<<"123";
	std::cout<< entry.first;
	//std::cout<< n;
  	//checkNeighborTableEntry(entry);
  } 
}

void LSRoutingProtocol::DumpRoutingTable() {

	std::cout << "dumping route table" << "\t";

	//############ 	we  edit
	 STATUS_LOG("\n**************** Route Table ********************");
	 for (auto& entry : m_routingTable) {
		 uint32_t destNode = entry.first;
		 RouteEntry route = entry.second;

		 Ipv4Address destAddr = ResolveNodeIpAddress(destNode);

		 Ipv4Address interfaceAddr = m_neighbors[route.nextHopAddr].interfaceAddress;

		 std::cout << destNode << "\t" << destAddr << "\t"
		 << route.nextHopNode << "\t" << route.nextHopAddr << "\t"
		 << interfaceAddr << "\t" << route.cost << std::endl;

		 checkRouteTableEntry(destNode, destAddr, route.nextHopNode, route.nextHopAddr,interfaceAddr, route.cost);
	 }
	 //###########



//origin start
//  STATUS_LOG(std::endl
//<< "**************** Route Table ********************" << std::endl
//<< "DestNumber\t\tDestAddr\t\tNextHopNumber\t\tNextHopAddr\t\tInterfaceAddr\t\tCost");
//PRINT_LOG("");
/* NOTE: For purpose of autograding, you should invoke the following function for each
routing table entry. The output format is indicated by parameter name and type.
*/
//  checkNeighborTableEntry();
//origin end
}


// Receive LSMessage and process
void LSRoutingProtocol::RecvLSMessage(Ptr<Socket> socket)
{
  Address sourceAddr; 

  Ptr<Packet> packet = socket->RecvFrom(sourceAddr); // sourceAddr will be assign value by Callback function

  LSMessage lsMessage;

  Ipv4PacketInfoTag interfaceInfo;

  if (!packet->RemovePacketTag(interfaceInfo)) 
  {
    NS_ABORT_MSG("No incoming interface on OLSR message, aborting.");
  }
  uint32_t incomingIf = interfaceInfo.GetRecvIf(); // Income Interface 

  if (!packet->RemoveHeader(lsMessage)) // Remove packet header and analyze
  {
    NS_ABORT_MSG("No incoming interface on LS message, aborting.");
  }

  
  Ipv4Address interface; // the IP of receive interface on device
  Ipv4Address sourceIpv4Addr= lsMessage.GetSource(); // lsMsg is a Header ==> Header::GetSource();

  uint32_t idx = 1;
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin();
       iter != m_socketAddresses.end(); iter++)
  {
    if (idx == incomingIf)
    {
      interface = iter->second.GetLocal(); // find the incoming interface
      break;
    }
    idx++;
  }

  switch (lsMessage.GetMessageType())
  {
  case LSMessage::PING_REQ:
    ProcessPingReq(lsMessage);
    break;

  case LSMessage::PING_RSP:
    ProcessPingRsp(lsMessage);
    break;

  case LSMessage::HR:
    ProcessHR(lsMessage,sourceIpv4Addr,interface); // Params: LSMsg , originAddress,interfaceAddress
    break;

    //code add
  case LSMessage::LSA:
    ProcessLSA(lsMessage); 
    break; 

  default:
    ERROR_LOG("Unknown Message Type!");
    break;
  }
}

//Edit: ProcessHR, receive 
void LSRoutingProtocol::ProcessHR(const LSMessage& lsaMsg,Ipv4Address originAddress,Ipv4Address interfaceAddress){
	//1. get HR info
	LSMessage::HRInfo hr = lsaMsg.GetHR();

	// new a Neighbor object and assign val
	Neighbor neighbor;
	neighbor.node = hr.originNode;
	neighbor.address= originAddress;
	neighbor.interfaceAddress = interfaceAddress; // how to get the into IP of LS
	// add neighbor to m_neighbors Map
	m_neighbors[originAddress]=neighbor; // Map<IP,Neighbor> IP:originAddress  Neighbor:this neighbor obj
}

// ### LETS SET PROCESSLSA  function HERE 
void LSRoutingProtocol::ProcessLSA(const LSMessage & lsaMessage){
	//### use lsaMessage 's GetLSA method
	LSMessage::LSAInfo lsa =  lsaMessage.GetLSA();
	uint32_t originNode = lsa.originNode;
	// ### check whether this LSA have been process 
	// ### 1. not in LSA database or 2. Seq > lsa.orignalNode
	if(m_lsDatabase.find(lsa.originNode) == m_lsDatabase.end() || lsa.sequenceNumber > m_lsDatabase[lsa.originNode].sequenceNumber){
		// ### what should we do here?
		m_lsDatabase[originNode]=lsa;  // add to LSA database
		FloodLSA(lsaMessage); // FLOOD new NODE info
		RunDijkstra(); // re calculate route
		printf("not in LSADB")	;
	}
}

// ### FLOODLSA
void LSRoutingProtocol::FloodLSA(const LSMessage& lsaMessage){
	LSMessage newLsa = lsaMessage;
	newLsa.SetTTL(newLsa.GetTTL() - 1);  //TTL -=1

	//if TTL is valid
	if(newLsa.GetTTL()> 0){
		//### create a new packet and send 
		Ptr<Packet> packet = Create<Packet>();
		//### broadcast this packet
		BroadcastPacket(packet);
	}

}

// ### Dijkstrat
void LSRoutingProtocol::RunDijkstra(){
	std::map<uint32_t,uint32_t> dist;
	std::map<uint32_t,uint32_t> prev;
	uint32_t currentNode = m_addressNodeMap[m_mainAddress];

	//### init distance
	for (auto& entry:m_lsDatabase){
		// if self = 0 , if other nodes = inf
		dist[entry.first]=(entry.first == currentNode) ? 0 : UINT32_MAX;
	}

	// ### prior queue 
	// ?????????????
	auto cmp = [&dist](uint32_t a, uint32_t b) { return dist[a] > dist[b]; };
	std::priority_queue<uint32_t,std::vector<uint32_t>, decltype(cmp)>queue(cmp);
	queue.push(currentNode);
	// ?????????????


	 //if queue != nil not empty
	 while(!queue.empty()){
		 uint32_t u = queue.top();
		 queue.pop();


		 //not exist
		 if(m_lsDatabase.find(u) == m_lsDatabase.end()) 
			 continue;
		 //exist , update cost
		 for (auto& neighbor: m_lsDatabase[u].neighbors){
			uint32_t v = neighbor.first;
			uint32_t cost = neighbor.second;

			// ### if go through this new node better than previous solution ,update it 
			if(dist[v]  > dist[u]  + cost){
				// update dist[v]
				dist[v] = dist[u] + cost;
				// change prev note
				prev[v] = u;
				//????? what 's prior queue?
				queue.push(v);
			}
		 }
	 }

	 //update route table
	 // 更新路由表
	 m_routingTable.clear(); // clear old routing table !!! ?
	 for (auto& entry : dist) { 
		 //if node = self  || cost = inf 
		 if (entry.first == currentNode || entry.second == UINT32_MAX) 
			 continue;

		 // new a route(RouteEntry Obj)
		 RouteEntry route;

		 //set value of this OBJ
		 route.nextHopNode = prev[entry.first];
		 route.cost = entry.second;
		 route.nextHopAddr = ResolveNodeIpAddress(route.nextHopNode);
		 //add to table [NODE, RouteEntry]
		 m_routingTable[entry.first] = route;
	 }
}


void LSRoutingProtocol::ProcessPingReq(LSMessage lsMessage)
{
  // Check destination address
  std::cout << lsMessage;
  if (IsOwnAddress(lsMessage.GetPingReq().destinationAddress))
  {
	  std::cout << "here";
    // Use reverse lookup for ease of debug
    std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
    TRAFFIC_LOG("Received PING_REQ, From Node: " << fromNode
                                                 << ", Message: " << lsMessage.GetPingReq().pingMessage);
    // Send Ping Response
    LSMessage lsResp = LSMessage(LSMessage::PING_RSP, lsMessage.GetSequenceNumber(), m_maxTTL, m_mainAddress);
    lsResp.SetPingRsp(lsMessage.GetOriginatorAddress(), lsMessage.GetPingReq().pingMessage);
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(lsResp);
    BroadcastPacket(packet);
  }
}

void LSRoutingProtocol::ProcessPingRsp(LSMessage lsMessage)
{
  // Check destination address
  if (IsOwnAddress(lsMessage.GetPingRsp().destinationAddress))
  {
    // Remove from pingTracker
    std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
    iter = m_pingTracker.find(lsMessage.GetSequenceNumber());
    if (iter != m_pingTracker.end())
    {
      std::string fromNode = ReverseLookup(lsMessage.GetOriginatorAddress());
      TRAFFIC_LOG("Received PING_RSP, From Node: " << fromNode
                                                   << ", Message: " << lsMessage.GetPingRsp().pingMessage);
      m_pingTracker.erase(iter);
    }
    else
    {
      DEBUG_LOG("Received invalid PING_RSP!");
    }
  }
}

// Chcck whether Input IP is one IP of this Node 
bool LSRoutingProtocol::IsOwnAddress(Ipv4Address originatorAddress)
{
  // Check all interfaces
  for (std::map<  Ptr<Socket>,  Ipv4InterfaceAddress> :: const_iterator i = m_socketAddresses.begin();
       i != m_socketAddresses.end(); i++)
  {
    Ipv4InterfaceAddress interfaceAddr = i->second;
    if (originatorAddress == interfaceAddr.GetLocal())
    {
      return true;
    }
  }
  return false;
}

//hello request function 
void LSRoutingProtocol::HRFunc(){
 //1. broadcast a MSG  with TTL = 1 
 //2. Recevice Response 
  PRINT_LOG("HR timre working!");
  m_HRTimer.Schedule(m_HRTimeout);
}
void LSRoutingProtocol::AuditPings()
{
  std::map<uint32_t, Ptr<PingRequest>>::iterator iter;
  for (iter = m_pingTracker.begin(); iter != m_pingTracker.end();)
  {
    Ptr<PingRequest> pingRequest = iter->second;
    if (pingRequest->GetTimestamp().GetMilliSeconds() + m_pingTimeout.GetMilliSeconds() <= Simulator::Now().GetMilliSeconds())
    {
      DEBUG_LOG("Ping expired. Message: " << pingRequest->GetPingMessage()
                                          << " Timestamp: " << pingRequest->GetTimestamp().GetMilliSeconds()
                                          << " CurrentTime: " << Simulator::Now().GetMilliSeconds());
      // Remove stale entries
      m_pingTracker.erase(iter++);
    }
    else
    {
      ++iter;
    }
  }
  // Rechedule timer
  m_auditPingsTimer.Schedule(m_pingTimeout);
}

uint32_t
LSRoutingProtocol::GetNextSequenceNumber()
{
  m_currentSequenceNumber = (m_currentSequenceNumber + 1) % (LS_MAX_SEQUENCE_NUMBER + 1);
  return m_currentSequenceNumber;
}

void LSRoutingProtocol::NotifyInterfaceUp(uint32_t i)
{
  m_staticRouting->NotifyInterfaceUp(i);
}
void LSRoutingProtocol::NotifyInterfaceDown(uint32_t i)
{
  m_staticRouting->NotifyInterfaceDown(i);
}
void LSRoutingProtocol::NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyAddAddress(interface, address);
}
void LSRoutingProtocol::NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address)
{
  m_staticRouting->NotifyRemoveAddress(interface, address);
}

void LSRoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
  NS_ASSERT(ipv4 != 0);
  NS_ASSERT(m_ipv4 == 0);
  NS_LOG_DEBUG("Created ls::RoutingProtocol");
  // Configure timers
  m_auditPingsTimer.SetFunction(&LSRoutingProtocol::AuditPings, this);
  m_HRTimer.SetFunction(&LSRoutingProtocol::HRFunc, this); // HRTimer 's callback function


  m_ipv4 = ipv4;
  m_staticRouting->SetIpv4(m_ipv4);
}
