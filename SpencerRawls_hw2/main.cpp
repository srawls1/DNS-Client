#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "Winsock2.h"
#include "Windows.h"
#include <iostream>
#include <string>

#define BUFFER_SIZE 512

using namespace std;

#pragma pack(push, 1)
struct QueryHeader
{
	USHORT qType;
	USHORT qClass;
};

struct DNSHeader
{
	USHORT txid;
	USHORT flags;
	USHORT questions;
	USHORT answers;
	USHORT authority;
	USHORT additional;
};

struct FixedRR
{
	USHORT qType;
	USHORT qClass;
	UINT ttl;
};

struct DNSAnswerHeader
{
	USHORT ty;
	USHORT cl;
	UINT ttl;
	USHORT len;
};
#pragma pack(pop)

// returns the size of the query
int makeQuery(char* domain, char buffer[], short type, short txid)
{
	string tempDomain = domain;
	if (type == htons(12))
	{
		string temp2Domain = "";
		while (tempDomain.length() > 0)
		{
			int i = tempDomain.find('.') + 1;
			if (i > 0)
			{
				temp2Domain = tempDomain.substr(0, i) + temp2Domain;
				tempDomain = tempDomain.substr(i);
			}
			else
			{
				temp2Domain = tempDomain + '.' + temp2Domain;
				tempDomain = "";
			}
		}
		tempDomain = temp2Domain + "in-addr.arpa";
	}
	const char* query = tempDomain.c_str();

	DNSHeader head;
	head.txid = txid;
	head.flags = htons(256);
	head.questions = htons(1);
	head.answers = 0;
	head.authority = 0;
	head.additional = 0;
	memcpy(buffer, &head, sizeof(DNSHeader));

	int i = sizeof(DNSHeader);
	const char* start = query;
	const char* seperater = strchr(query, '.');
	while (seperater != NULL)
	{
		int len = (long)seperater - (long)start;
		buffer[i++] = len;
		memcpy(buffer + i, start, len);
		i += len;
		start = seperater + 1;
		seperater = strchr(start, '.');
	}
	int len = strlen(start);
	buffer[i++] = len;
	memcpy(buffer + i, start, len);
	i += len;

	buffer[i] = 0;
	++i;

	QueryHeader qh;
	qh.qType = type;
	qh.qClass = htons(1);
	memcpy(buffer + i, &qh, sizeof(QueryHeader));
	i += sizeof(QueryHeader);

	cout << "Query   : " << query << ", type " << ntohs(qh.qType) << ", TXID " << hex << "0x" << txid << endl;
	cout << dec;

	return i;
}

SOCKET getSocket()
{
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == INVALID_SOCKET)
	{
		cout << "socket initialization error: " << WSAGetLastError() << endl;
		exit(2);
	}
	
	return sock;
}

bool notEqualInAddrFuckYouCpp(in_addr addr1, in_addr addr2)
{
	if (addr1.s_addr != addr2.s_addr)
	{
		return true;
	}
	return false;
}

void cwrite(SOCKET sock, sockaddr_in remote, char* query, int len)
{
	if (sendto(sock, query, len, 0, (sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR)
	{
		cout << "sendto error: " << WSAGetLastError() << endl;
		exit(3);
	}
}

int cread(SOCKET sock, sockaddr_in ip, char* buffer)
{
	struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	fd_set fd;
	FD_ZERO(&fd);
	FD_SET(sock, &fd);
	int available = select(0, &fd, NULL, NULL, &timeout);
	int length = 0;
	if (available > 0)
	{
		sockaddr_in response;
		int sizeofSockaddr = sizeof(sockaddr);
		length = recvfrom(sock, (char*)buffer, BUFFER_SIZE, 0, (sockaddr*)&response, &sizeofSockaddr);
		if (length == SOCKET_ERROR)
		{
			cout << "recvfrom error: " << WSAGetLastError() << endl;
			exit(15);
		}
		if (notEqualInAddrFuckYouCpp(response.sin_addr, ip.sin_addr)
		|| response.sin_port != ip.sin_port)
		{
			cout << "response not from the correct server" << endl;
			exit(16);
		}
	}
	return length;
}

// returns initOffset + size of this question
int parseName(char* buffer, int initOffset, int length)
{
	int i;
	int off;
	int numJumps = 0;
	int maxJumps = length / 2;
	char* copyTo = new char[BUFFER_SIZE];
	memset(copyTo, 0, BUFFER_SIZE);
	int copyOffset = 0;
	for (i = initOffset; i < length;)
	{
		unsigned char size = buffer[i];
		if (size == 0)
		{
			if (numJumps > 0)
			{
				i = off + 1;
			}
			++i;
			break;
		}
		else if (size >= 0xC0)
		{
			if (numJumps == 0)
			{
				off = i;
			}
			if (i == length - 1)
			{
				cout << endl << "  ++ invalid record: truncated jump offset" << endl;
				exit(14);
			}
			int jump = ((size << 8) & 0x3F) + (unsigned char)(buffer[i + 1]);
			if (jump >= length)
			{
				cout << endl << "  ++ invalid record: jump beyond packet boundary" << endl;
				exit(7);
			}
			else if (jump < 12)
			{
				cout << endl << "  ++ invalid record: jump into fixed header" << endl;
				exit(8);
			}
			i = jump;
			++numJumps;
			if (numJumps >= maxJumps)
			{
				cout << endl << "  ++ invalid record: jump loop" << endl;
				exit(9);
			}
		}
		else if (i + size > length)
		{
			cout << endl << "  ++ invalid record: truncated name" << endl;
			exit(12);
		}
		else
		{
			memcpy(copyTo + copyOffset, buffer + i + 1, size);
			copyOffset += size;
			copyTo[copyOffset] = '.';
			++copyOffset;
			i += size + 1;
		}
	}

	copyTo[copyOffset - 1] = 0;
	cout << copyTo;
	delete[] copyTo;

	return i;
}

// returns initOffset + size of this question
int parseQuestion(char* buffer, int initOffset, int length)
{
	if (initOffset >= length)
	{
		cout << "  ++ invalid section: not enough records" << endl;
		exit(11);
	}
	cout << "        ";

	int i = parseName(buffer, initOffset, length);

	QueryHeader* qh = (QueryHeader*)(buffer + i);

	cout << " type " << ntohs(qh->qType) << " class " << ntohs(qh->qClass) << endl;

	i += sizeof(QueryHeader);
	return i;
}

// returns initOffset + size of this question
int parseAnswer(char* buffer, int initOffset, int length)
{
	if (initOffset >= length)
	{
		cout << "  ++ invalid section: not enough records" << endl;
		exit(11);
	}
	cout << "        ";

	int i = parseName(buffer, initOffset, length);

	if (i + sizeof(DNSAnswerHeader) > length)
	{
		cout << endl << "  ++ invalid record: truncated fixed RR header" << endl;
		exit(13);
	}
	DNSAnswerHeader* ah = (DNSAnswerHeader*)(buffer + i);
	USHORT ansLen = ntohs(ah->len);
	USHORT ansType = ntohs(ah->ty);
	USHORT ansClass = ntohs(ah->cl);
	UINT ansTtl = ntohl(ah->ttl);

	i += sizeof(DNSAnswerHeader);

	switch (ansType)
	{
	case 1:
		cout << " A ";
		break;
	case 2:
		cout << " NS ";
		break;
	case 5:
		cout << " CNAME ";
		break;
	case 12:
		cout << " PTR ";
		break;
	default:
		cout << ' ' << ansType << ' ';
		return i + ansLen;
	}
	if (ansType == 1)
	{
		if (ansLen == 4)
		{
			int* ip = (int*)(buffer + i);
			struct in_addr ip_addr;
			ip_addr.s_addr = *ip;
			cout << inet_ntoa(ip_addr);
		}
		else if (ansLen == 16)
		{
			cout << "IPv6 address" << endl;
			return i + 16;
		}
	}
	else
	{
		if (i + ansLen > length)
		{
			cout << "  ++ invalid record: value length beyond packet" << endl;
			exit(16);
		}
		parseName(buffer, i, length);
	}

	i += ansLen;
	cout << " TTL = " << ansTtl << endl;

	return i;
}

void parse(char* buffer, short txid, int length)
{
	if (length < 12)
	{
		cout << "  ++ invalid reply: smaller than fixed header" << endl;
		exit(10);
	}
	DNSHeader* header = (DNSHeader*)buffer;
	
	USHORT flags = ntohs(header->flags);
	USHORT questions = ntohs(header->questions);
	USHORT answers = ntohs(header->answers);
	USHORT authority = ntohs(header->authority);
	USHORT additional = ntohs(header->additional);

	cout << hex << "  TXID 0x" << header->txid << " flags 0x" << flags << dec;
	cout << " questions " << questions << " answers " << answers << " authority " << authority << " additional " << additional << endl;
	short rcode = (flags & 0xF);
	if (rcode == 0)
	{
		cout << "  succeeded with Rcode = " << rcode << endl;
	}
	else
	{
		cout << "  failed with Rcode = " << rcode << endl;
		return;
	}
	if (header->txid != txid)
	{
		cout << "  ++ invalid reply: TXID mismatch, sent 0x"
			<< hex << txid << " received 0x" << header->txid << dec << endl;
		return;
	}

	int offset = sizeof(DNSHeader);

	if (questions > 0)
	{
		cout << "  ------------[questions] ----------" << endl;
		for (int i = 0; i < questions; ++i)
		{
			offset = parseQuestion(buffer, offset, length);
		}
	}
	if (answers > 0)
	{
		cout << "  ------------[answers] ------------" << endl;
		for (int i = 0; i < answers; ++i)
		{
			offset = parseAnswer(buffer, offset, length);
		}
	}
	if (authority > 0)
	{
		cout << "  ------------[authority] ----------" << endl;
		for (int i = 0; i < authority; ++i)
		{
			offset = parseAnswer(buffer, offset, length);
		}
	}
	if (additional > 0)
	{
		cout << "  ------------[additional] ---------" << endl;
		for (int i = 0; i < additional; ++i)
		{
			offset = parseAnswer(buffer, offset, length);
		}
	}
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		cout << "Usage: hw2.exe <domain name> <dns server ip>" << endl;
		return 1;
	}

	WSADATA wsadata;
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsadata) != 0)
	{
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return 10;
	}
	srand(GetTickCount64());

	char* domain = argv[1];
	char* dnsipstr = argv[2];
	int targetip = inet_addr(domain);
	int dnsip = inet_addr(dnsipstr);

	cout << "Lookup  : " << domain << endl;

	char query[BUFFER_SIZE];
	int queryLength;

	short txid = rand() & 0xFFFF;
	if (targetip == INADDR_NONE)
	{
		queryLength = makeQuery(domain, query, htons(1), txid);
	}
	else
	{
		queryLength = makeQuery(domain, query, htons(12), txid);
	}

	cout << "Server  : " << dnsipstr << endl;
	cout << "********************************" << endl;

	char buffer[BUFFER_SIZE];
	memset(buffer, 0, BUFFER_SIZE);
	SOCKET sock = getSocket();

	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR)
	{
		cout << "bind error: " << WSAGetLastError() << endl;
		exit(2);
	}

	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = dnsip;
	remote.sin_port = htons(53);

	int tries = 0;
	int responseLength = 0;
	while (responseLength == 0 && tries < 3)
	{
		cwrite(sock, remote, query, queryLength);
		cout << "Attempt " << tries++ << " with " << queryLength << " bytes... ";
		ULONGLONG startTime = GetTickCount64();
		responseLength = cread(sock, remote, buffer);
		ULONGLONG endTime = GetTickCount64();
		if (responseLength > 0)
		{
			cout << "response in " << endTime - startTime << " ms with " << responseLength << " bytes" << endl;
		}
		else
		{
			cout << "timeout in " << endTime - startTime << " ms" << endl;
		}
	}

	if (tries < 3)
	{
		parse(buffer, txid, responseLength);
	}
}