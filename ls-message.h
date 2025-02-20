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

#ifndef LS_MESSAGE_H
#define LS_MESSAGE_H

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/object.h"
#include "ns3/packet.h"


using namespace ns3;

#define IPV4_ADDRESS_SIZE 4

class LSMessage : public Header
{
  public:

    LSMessage();

    virtual ~LSMessage();

    // TODO: Define extra message types in enum when needed
    enum MessageType
      {
	      PING_REQ,
	      PING_RSP,
	      LSA   // LSA MSG TYPE used to implement LS algorihm
      };

    LSMessage(LSMessage::MessageType messageType, uint32_t sequenceNumber, uint8_t ttl, Ipv4Address originatorAddress);
    //LSAInfo MSG structure
    struct LSAInfo{
	    uint32_t originNode; //### int32 NODE
	    uint32_t sequenceNumber; // ### int32 Seq
	    //### along with LS node self's neighbors node and cost MAP 
	    std::map<uint32_t,uint32_t> neighbors;


	    //### define serialized method in LSAINFO structure 
	    void Print(std::ostream& os) const; // wait for implement
	    uint32_t GetSerializedSize(void) const; // return SerializedSize wait for implement
	    void Serialize(Buffer::Iterator& start) const; // serilize function wait for implement
	    uint32_t Deserialize(Buffer::Iterator& start); // Deserilize
    };


    /**
     *  \brief Sets message type
     *  \param messageType message type
     */
    void SetMessageType(MessageType messageType);

    /**
     *  \returns message type
     */
    MessageType GetMessageType() const;

    /**
     *  \brief Sets Sequence Number
     *  \param sequenceNumber Sequence Number of the request
     */
    void SetSequenceNumber(uint32_t sequenceNumber);

    /**
     *  \returns Sequence Number
     */
    uint32_t GetSequenceNumber() const;

    /**
     *  \brief Sets Originator IP Address
     *  \param originatorAddress Originator IPV4 address
     */
    void SetOriginatorAddress(Ipv4Address originatorAddress);
    /**
     *  \returns Originator IPV4 address
     */
    Ipv4Address GetOriginatorAddress() const;

    /**
     *  \brief Sets Time To Live of the message
     *  \param ttl TTL of the message
     */
    void SetTTL(uint8_t ttl);

    /**
     *  \returns TTL of the message
     */
    uint8_t GetTTL() const;

  private:
    /**
     *  \cond
     */
    MessageType m_messageType; // lsmsg.m_messageType 
    uint32_t m_sequenceNumber; // lsmsg.m_sequenceNumber
    Ipv4Address m_originatorAddress; // lsmsg.m_originatorAddress 
    uint8_t m_ttl; // lsmsg.m_ttl
    /**
     *  \endcond
     */
  public:
    static TypeId GetTypeId(void);
    virtual TypeId GetInstanceTypeId(void) const;

    void Print(std::ostream& os) const;
    uint32_t GetSerializedSize(void) const;
    void Serialize(Buffer::Iterator start) const;
    uint32_t Deserialize(Buffer::Iterator start);

    struct PingReq // LSMessage::PingReq 
      {
      void Print(std::ostream& os) const;
      uint32_t GetSerializedSize(void) const;
      void Serialize(Buffer::Iterator& start) const;
      uint32_t Deserialize(Buffer::Iterator& start);
      // Payload
      Ipv4Address destinationAddress;
      std::string pingMessage;
     };

    struct PingRsp // LSMessage::PingRes
     {
      void Print(std::ostream& os) const;
      uint32_t GetSerializedSize(void) const;
      void Serialize(Buffer::Iterator& start) const;
      uint32_t Deserialize(Buffer::Iterator& start);
      // Payload
      Ipv4Address destinationAddress;
      std::string pingMessage;
     };

  private:
    struct
     {
      PingReq pingReq;
      PingRsp pingRsp;
      LSAInfo lsa;
     } m_message;


  public:
    //### add LSA operate method
    void SetLSA(uint32_t originNode,uint32_t sequenceNumber, const std::map <uint32_t,uint32_t>& neighbors); // ### wait for implement
    //### ETLSA info 
    LSAInfo GetLSA() const; // ### waif for implement


    /**
     *  \returns PingReq Struct
     */
    PingReq GetPingReq();

    /**
     *  \brief Sets PingReq message params
     *  \param message Payload String
     */

    void SetPingReq(Ipv4Address destinationAddress, std::string message);

    /**
     * \returns PingRsp Struct
     */
    PingRsp GetPingRsp();
    /**
     *  \brief Sets PingRsp message params
     *  \param message Payload String
     */
    void SetPingRsp(Ipv4Address destinationAddress, std::string message);
  }; // class LSMessage

static inline std::ostream&
operator<< (std::ostream& os, const LSMessage& message)
  {
  message.Print(os);
  return os;
  }

#endif
