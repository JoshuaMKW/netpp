// **************************************************************
// * netpp C++ Networking Library (webfetch example)
// * Copyright (C) 2024-2025 Joshua Alston
// *
// * This program is free software; you can redistribute it and/or
// * modify it under the terms of the GNU General Public License
// * as published by the Free Software Foundation; either version 2
// * of the License, or (at your option) any later version.
// **************************************************************

#include <iostream>
#include <string>

#include "client.h"
#include "socket.h"
#include "protocol.h"

#include "dns/record.h"
#include "dtls/security.h"

using namespace netpp;

#define CLIENT_HOST "8.8.8.8"
#define CLIENT_KEY "cert/client_key.pem"
#define CLIENT_USE_DTLS 0

// ------------------------------------
// Pretty Print Helpers
// ------------------------------------
static std::string RRTypeToString(netpp::EDNSQuery_RR_TYPE type)
{
    switch (type) {
    case netpp::EDNSQuery_RR_TYPE::TYPE_A:
        return "A";
    case netpp::EDNSQuery_RR_TYPE::TYPE_AAAA:
        return "AAAA";
    case netpp::EDNSQuery_RR_TYPE::TYPE_NS:
        return "NS";
    case netpp::EDNSQuery_RR_TYPE::TYPE_MD:
        return "MD";
    case netpp::EDNSQuery_RR_TYPE::TYPE_MF:
        return "MF";
    case netpp::EDNSQuery_RR_TYPE::TYPE_CNAME:
        return "CNAME";
    case netpp::EDNSQuery_RR_TYPE::TYPE_SOA:
        return "SOA";
    case netpp::EDNSQuery_RR_TYPE::TYPE_MB:
        return "MB";
    case netpp::EDNSQuery_RR_TYPE::TYPE_MG:
        return "MG";
    case netpp::EDNSQuery_RR_TYPE::TYPE_MR:
        return "MR";
    case netpp::EDNSQuery_RR_TYPE::TYPE_NULL:
        return "NULL";
    case netpp::EDNSQuery_RR_TYPE::TYPE_WKS:
        return "WKS";
    case netpp::EDNSQuery_RR_TYPE::TYPE_PTR:
        return "PTR";
    case netpp::EDNSQuery_RR_TYPE::TYPE_HINFO:
        return "HINFO";
    case netpp::EDNSQuery_RR_TYPE::TYPE_MINFO:
        return "MINFO";
    case netpp::EDNSQuery_RR_TYPE::TYPE_MX:
        return "MX";
    case netpp::EDNSQuery_RR_TYPE::TYPE_TXT:
        return "TXT";
    case netpp::EDNSQuery_RR_TYPE::TYPE_DNSKEY:
        return "DNSKEY";
    default:
        return "UNKNOWN (" + std::to_string((uint16_t)type) + ")";
    }
}

static std::string RRTypeToString(netpp::EDNSQuery_RR_QTYPE type)
{
    switch (type) {
    case netpp::EDNSQuery_RR_QTYPE::TYPE_A:
        return "A";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_AAAA:
        return "AAAA";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_NS:
        return "NS";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_MD:
        return "MD";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_MF:
        return "MF";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_CNAME:
        return "CNAME";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_SOA:
        return "SOA";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_MB:
        return "MB";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_MG:
        return "MG";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_MR:
        return "MR";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_NULL:
        return "NULL";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_WKS:
        return "WKS";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_PTR:
        return "PTR";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_HINFO:
        return "HINFO";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_MINFO:
        return "MINFO";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_MX:
        return "MX";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_TXT:
        return "TXT";
    case netpp::EDNSQuery_RR_QTYPE::TYPE_DNSKEY:
        return "DNSKEY";
    case netpp::EDNSQuery_RR_QTYPE::QTYPE_IXFR:
        return "Q_IXFR";
    case netpp::EDNSQuery_RR_QTYPE::QTYPE_AXFR:
        return "Q_AXFR";
    case netpp::EDNSQuery_RR_QTYPE::QTYPE_MAILA:
        return "Q_MAILA";
    case netpp::EDNSQuery_RR_QTYPE::QTYPE_MAILB:
        return "Q_MAILB";
    case netpp::EDNSQuery_RR_QTYPE::QTYPE_ALL:
        return "Q_ALL";
    default:
        return "UNKNOWN (" + std::to_string((uint16_t)type) + ")";
    }
}

static std::string RRClassToString(netpp::EDNSQuery_RR_CLASS klass)
{
    switch (klass) {
    case netpp::EDNSQuery_RR_CLASS::CLASS_IN:
        return "IN";
    case netpp::EDNSQuery_RR_CLASS::CLASS_CS:
        return "CS";
    case netpp::EDNSQuery_RR_CLASS::CLASS_CH:
        return "CH";
    case netpp::EDNSQuery_RR_CLASS::CLASS_HS:
        return "HS";
    default:
        return "UNKNOWN (" + std::to_string((uint16_t)klass) + ")";
    }
}

static std::string RRClassToString(netpp::EDNSQuery_RR_QCLASS klass)
{
    switch (klass) {
    case netpp::EDNSQuery_RR_QCLASS::CLASS_IN:
        return "IN";
    case netpp::EDNSQuery_RR_QCLASS::CLASS_CS:
        return "CS";
    case netpp::EDNSQuery_RR_QCLASS::CLASS_CH:
        return "CH";
    case netpp::EDNSQuery_RR_QCLASS::CLASS_HS:
        return "HS";
    case netpp::EDNSQuery_RR_QCLASS::QCLASS_ALL:
        return "Q_ALL";
    default:
        return "UNKNOWN (" + std::to_string((uint16_t)klass) + ")";
    }
}

static void printDNSQuestion(const netpp::DNS_Question& question)
{
    std::cout << "--------------------------------------------------\n";
    std::cout << std::left << std::setw(12) << "Domain:" << question.name() << "\n";
    std::cout << std::left << std::setw(12) << "Type:" << RRTypeToString(question.type()) << "\n";
    std::cout << std::left << std::setw(12) << "Class:" << RRClassToString(question.klass()) << "\n";
}

// ------------------------------------
// Pretty Print Implementation
// ------------------------------------
static void printDNSRecord(const netpp::DNS_Record& record)
{
    std::cout << "--------------------------------------------------\n";
    std::cout << std::left << std::setw(12) << "Record:" << record.name() << "\n";
    std::cout << std::left << std::setw(12) << "Type:" << RRTypeToString(record.type()) << "\n";
    std::cout << std::left << std::setw(12) << "Class:" << RRClassToString(record.klass()) << "\n";
    std::cout << std::left << std::setw(12) << "TTL:" << record.ttl() << " seconds\n";
    std::cout << "RData:\n";

    if (!record.rdata()) {
        std::cout << "  (Empty or Null Data)\n";
        return;
    }

    switch (record.type()) {
    case EDNSQuery_RR_TYPE::TYPE_A: {
        auto* rdata = static_cast<const DNS_RData_A*>(record.rdata());
        std::cout << "  Address:    " << rdata->ipv4() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_AAAA: {
        auto* rdata = static_cast<const DNS_RData_AAAA*>(record.rdata());
        std::cout << "  Address:    " << rdata->ipv6() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_CNAME: {
        auto* rdata = static_cast<const DNS_RData_CNAME*>(record.rdata());
        std::cout << "  CNAME:      " << rdata->cname() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_HINFO: {
        auto* rdata = static_cast<const DNS_RData_HINFO*>(record.rdata());
        std::cout << "  CPU:        " << rdata->cpu() << "\n";
        std::cout << "  OS:         " << rdata->os() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_MB: {
        auto* rdata = static_cast<const DNS_RData_MB*>(record.rdata());
        std::cout << "  MADNAME:    " << rdata->madname() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_MD: {
        auto* rdata = static_cast<const DNS_RData_MD*>(record.rdata());
        std::cout << "  MADNAME:    " << rdata->madname() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_MF: {
        auto* rdata = static_cast<const DNS_RData_MF*>(record.rdata());
        std::cout << "  MADNAME:    " << rdata->madname() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_MG: {
        auto* rdata = static_cast<const DNS_RData_MG*>(record.rdata());
        std::cout << "  MGMNAME:    " << rdata->mgmname() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_MINFO: {
        auto* rdata = static_cast<const DNS_RData_MINFO*>(record.rdata());
        std::cout << "  RMAILBX:    " << rdata->rmailbx() << "\n";
        std::cout << "  EMAILBX:    " << rdata->emailbx() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_MR: {
        auto* rdata = static_cast<const DNS_RData_MR*>(record.rdata());
        std::cout << "  NEWNAME:    " << rdata->newname() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_MX: {
        auto* rdata = static_cast<const DNS_RData_MX*>(record.rdata());
        std::cout << "  Preference: " << rdata->preference() << "\n";
        std::cout << "  Exchange:   " << rdata->exchange() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_NS: {
        auto* rdata = static_cast<const DNS_RData_NS*>(record.rdata());
        std::cout << "  NSDNAME:    " << rdata->nsdname() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_PTR: {
        auto* rdata = static_cast<const DNS_RData_PTR*>(record.rdata());
        std::cout << "  PTRDNAME:   " << rdata->ptrdname() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_SOA: {
        auto* rdata = static_cast<const DNS_RData_SOA*>(record.rdata());
        std::cout << "  MNAME:      " << rdata->mname() << "\n";
        std::cout << "  RNAME:      " << rdata->rname() << "\n";
        std::cout << "  Serial:     " << rdata->serial() << "\n";
        std::cout << "  Refresh:    " << rdata->refresh() << "\n";
        std::cout << "  Retry:      " << rdata->retry() << "\n";
        std::cout << "  Expire:     " << rdata->expire() << "\n";
        std::cout << "  Minimum:    " << rdata->minimum() << "\n";
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_TXT: {
        auto* rdata = static_cast<const DNS_RData_TXT*>(record.rdata());
        std::cout << "  TXT Data:\n";
        for (size_t i = 0; i < rdata->txtdata().size(); ++i) {
            std::cout << "    [" << i << "] \"" << rdata->txtdata()[i] << "\"\n";
        }
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_WKS: {
        auto* rdata = static_cast<const DNS_RData_WKS*>(record.rdata());
        std::cout << "  Address:    " << rdata->ipv4() << "\n";
        std::cout << "  Protocol:   " << (int)rdata->protocol() << "\n";

        std::cout << "  Bitmap:     [ ";
        for (uint8_t byte : rdata->bitmap()) {
            // Print as zero-padded hex
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::dec << std::setfill(' ') << "]\n"; // Reset stream state
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_DNSKEY: {
        auto* rdata = static_cast<const DNS_RData_DNSKEY*>(record.rdata());
        std::cout << "  Flags:    " << rdata->flags() << "\n";
        std::cout << "  Protocol:   " << (int)rdata->protocol() << "\n";
        std::cout << "  Algorithm:   " << (int)rdata->algorithm() << "\n";

        std::cout << "  Bitmap:     [ ";
        for (uint8_t byte : rdata->pubkey()) {
            // Print as zero-padded hex
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::dec << std::setfill(' ') << "]\n"; // Reset stream state
        break;
    }
    case EDNSQuery_RR_TYPE::TYPE_NULL: {
        auto* rdata = static_cast<const DNS_RData_NULL*>(record.rdata());
        std::cout << "  Data Length:" << rdata->data().size() << " bytes\n";
        break;
    }
    default:
        std::cout << "  [Unhandled RData Type]\n";
        break;
    }
}

int main(int argc, char** argv) {
  if (!sockets_initialize()) {
    fprintf(stderr, "Failed to initialize sockets interface\n");
    return 1;
  }

#if CLIENT_USE_DTLS
  if (!std::filesystem::exists(CLIENT_KEY)) {
    std::filesystem::create_directories(std::filesystem::path(CLIENT_KEY).parent_path());
    if (!netpp::generate_client_key_rsa_4096(
      CLIENT_KEY,
      "",
      "US",
      "netpp webfetch")) {
      fprintf(stderr, "Failed to generate self-signed certificate\n");
      return 1;
    }
  }

  DTLSSecurityFactory* security
      = new DTLSSecurityFactory(false, CLIENT_KEY, "", "", CLIENT_HOST, "", EDTLSVerifyFlags::VERIFY_PEER);
#else
  DTLSSecurityFactory* security = nullptr;
#endif

  UDP_Client client(security);
  if (!client.start()) {
    fprintf(stderr, "Failed to start the client\n");
    return 1;
  }

  HostIPInfo ip_info = get_ip_address_info(CLIENT_HOST);
  if (!client.connect(ip_info.m_ipv4, "53")) {
    fprintf(stderr, "Failed to connect to the server\n");
    return 1;
  }

  printf("Connected to server (%s:%s)!\n\n", client.hostname().c_str(), client.port().c_str());

  std::mutex send_mutex;
  std::condition_variable send_cv;

  client.on_dns_response([&](const ISocketPipe* source, const DNS_Message* message) -> DNS_Message* {
      std::cout << "DNS MESSAGE (" << message->id() << ")\n";
      
      std::cout << "==== QUESTIONS ====\n";
      for (const DNS_Question& question : message->questions()) {
          printDNSQuestion(question);
      }

      std::cout << "\n==== ANSWERS ====\n";
      for (const DNS_Record& answer : message->answers()) {
          printDNSRecord(answer);
      }

      std::cout << "\n==== AUTHORITATIVES ====\n";
      for (const DNS_Record& authoritative : message->authoritatives()) {
          printDNSRecord(authoritative);
      }

      std::cout << "\n==== ADDITIONALS ====\n";
      for (const DNS_Record& additional : message->additionals()) {
          printDNSRecord(additional);
      }

      std::cout << "\n";

      send_cv.notify_all();
      return nullptr;
  });

  // Get IPV4 addresses associated with google.com
  {
      DNS_Question question = DNS_Question("google.com", EDNSQuery_RR_QTYPE::TYPE_DNSKEY, EDNSQuery_RR_QCLASS::CLASS_IN);
      DNS_Message* message = DNS_Message::create_query(1);
      message->add_question(question);
      message->set_flags(0x0100);

      if (!client.send(message)) {
          fprintf(stderr, "Failed to send message\n");
          return 1;
      }
  }

  // Get the canonical name associated with www.google.com
  {
      DNS_Question question = DNS_Question("www.google.com", EDNSQuery_RR_QTYPE::TYPE_CNAME, EDNSQuery_RR_QCLASS::CLASS_IN);
      DNS_Message* message = DNS_Message::create_query(2);
      message->add_question(question);
      message->set_flags(0x0100);

      if (!client.send(message)) {
          fprintf(stderr, "Failed to send message\n");
          return 1;
      }

      std::unique_lock lock(send_mutex);
      send_cv.wait(lock);
  }

  // Get the Name Server records associated with microsoft.com
  {
      DNS_Question question = DNS_Question("microsoft.com", EDNSQuery_RR_QTYPE::TYPE_NS, EDNSQuery_RR_QCLASS::CLASS_IN);
      DNS_Message* message = DNS_Message::create_query(3);
      message->add_question(question);
      message->set_flags(0x0100);

      if (!client.send(message)) {
          fprintf(stderr, "Failed to send message\n");
          return 1;
      }

      std::unique_lock lock(send_mutex);
      send_cv.wait(lock);
  }

  // Get the long TXT data associated with _dmarc.google.com
  {
      DNS_Question question = DNS_Question("_dmarc.google.com", EDNSQuery_RR_QTYPE::TYPE_TXT, EDNSQuery_RR_QCLASS::CLASS_IN);
      DNS_Message* message = DNS_Message::create_query(4);
      message->add_question(question);
      message->set_flags(0x0100);

      if (!client.send(message)) {
          fprintf(stderr, "Failed to send message\n");
          return 1;
      }

      std::unique_lock lock(send_mutex);
      send_cv.wait(lock);
  }

  // Get the reverse DNS lookup for the ipv4 address
  {
      std::string bruhbruhbruh = get_reverse_lookup_domain_name(ip_info.m_ipv4);

      DNS_Question question = DNS_Question(bruhbruhbruh.c_str(), EDNSQuery_RR_QTYPE::TYPE_PTR, EDNSQuery_RR_QCLASS::CLASS_IN);
      DNS_Message* message = DNS_Message::create_query(5);
      message->add_question(question);
      message->set_flags(0x0100);

      if (!client.send(message)) {
          fprintf(stderr, "Failed to send message\n");
          return 1;
      }

      std::unique_lock lock(send_mutex);
      send_cv.wait(lock);
  }

  client.stop();

  sockets_deinitialize();
  return 0;
}