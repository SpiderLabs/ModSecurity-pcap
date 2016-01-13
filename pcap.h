

class Packet
{
    public:
        Packet(pcap_pkthdr *header, const u_char *data, int verbose);
        int parsePacket();
        int setTCPIPdata();
        int extractHTTPuri(std::string type);
        int extractHTTPData();
        int request;
        std::string src;
        std::string dst;
        int srcprt;
        int dstprt;
        int hasData;
        std::string method;
        std::string uri;
        std::string version;
        bool httpDetected = false;
        std::vector<std::string> headerNames;
        std::vector<std::string> headerValues;    
        std::string bodyData = "";
        std::string rVersion;
        std::string status;   
        std::string phrase;
        
    private:
        int _verbose;
        pcap_pkthdr *_header;
        const u_char *_data;
        struct ether_header* _eth;
        struct ip *_ip;
        struct ip6_hdr *_ip6;
        struct tcphdr *_tcp;
        std::string _appData;
        int _hasHTTPData = 0;
        std::vector<std::string> _splitHTTP;
};
