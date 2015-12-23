/////////////////////////// example /////////////////////
///////////////////// header file ////////////////////////////////
#include <modsecurity/modsecurity.h>
#include <pcap.h>
#include <iostream>
#include <fstream>
#include <string>

// Structs for processing
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
// inet_aton
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>




#ifndef ETHERTYPE_IP6
    #define ETHERTYPE_IP6 0x86dd
#endif

class ModSecurityAnalyzer
{
    public:
        ModSecurityAnalyzer(std::string main_rule_uri);
        int AddConnectionInfo(std::string src,int srcprt,std::string dst,int dstprt);
        int AddRequestInfo(std::string uri,std::string method,std::string version);
        int RunPhases();
        int RunCleanup();
    private:
        // ModSecurity engine 
        ModSecurity::ModSecurity *_modsec;
      
       // modsecurity rules
       ModSecurity::Rules *_rules;
 
       // modsecurity transaction object
       ModSecurity::Assay *_pmodsecAssay;
};

ModSecurityAnalyzer::ModSecurityAnalyzer(std::string main_rule_uri){
    const char *error = NULL;
    // Connect to libmodsecurity
    _modsec = ModSecurity::msc_init();
    ModSecurity::msc_set_connector_info(_modsec, "ModSecurity-pcap v0.0.1-alpha");
    // Load the modsecurity rules specified.
    _rules = ModSecurity::msc_create_rules_set();
    if(msc_rules_add_file(_rules, main_rule_uri.c_str(), &error) < 0){
        std::cerr << "Error: Issues loading the rules." << std::endl << error << std::endl;
    }
    ModSecurity::msc_rules_dump(_rules);
}

int ModSecurityAnalyzer::AddConnectionInfo(std::string src,int srcprt,std::string dst,int dstprt){
    _pmodsecAssay = ModSecurity::msc_new_assay(_modsec, _rules, NULL);
    ModSecurity::msc_process_connection(_pmodsecAssay, src.c_str(), srcprt, dst.c_str(), dstprt);
    return 1;       

}

int ModSecurityAnalyzer::AddRequestInfo(std::string uri,std::string method,std::string version){
    // ModSecurity wants the HTTP/ removed from the 1.1
    version = version.substr(5,version.length()-5);
    ModSecurity::msc_process_uri(_pmodsecAssay,uri.c_str(),method.c_str(),version.c_str());
    return 1;
}

int ModSecurityAnalyzer::RunPhases(){
    ModSecurity::msc_process_request_headers(_pmodsecAssay);
    ModSecurity::msc_process_request_body(_pmodsecAssay);
    ModSecurity::msc_process_response_headers(_pmodsecAssay);
    ModSecurity::msc_process_response_body(_pmodsecAssay);
    ModSecurity::msc_process_logging(_pmodsecAssay, 200);
    return 1;
}

int ModSecurityAnalyzer::RunCleanup(){
    ModSecurity::msc_rules_cleanup(_rules);
    ModSecurity::msc_cleanup(_modsec);
}

 

class Packet
{
    public:
        Packet(pcap_pkthdr *header, const u_char *data, int verbose);
        int parsePacket();
        int setTCPIPdata();
        int extractHTTP(std::string type);
        std::string src;
        std::string dst;
        int srcprt;
        int dstprt;
        int hasData;
        std::string method;
        std::string uri;
        std::string version;
        bool httpDetected = false;
        
    private:
        int _verbose;
        pcap_pkthdr *_header;
        const u_char *_data;
        struct ether_header* _eth;
        struct ip *_ip;
        struct ip6_hdr *_ip6;
        struct tcphdr *_tcp;
        std::string _appData;
};

// Our constructor that collects the packet header and data
Packet::Packet(pcap_pkthdr *header, const u_char *data, int verbose)
{
    _header = header;
    _data = data;
    _verbose = verbose;
}

// Returns -1 if there is an error
// Returns 1 if success
int Packet::parsePacket()   
{
    // Assume Ethr and save the header
    _eth = (struct ether_header*)_data;
    if(_verbose){
        std::cout << "[+] Parsed out Ethernet header" << std::endl;
    }
    // Check if we have a TCP header
    // This is an ugly way to check if we have ipv6 or not
    int hasTCP = 0;

    // Check that we have an IP type packet
    if(ntohs(_eth->ether_type) == ETHERTYPE_IP){
        // Save the IP header
        _ip = (struct ip*)(_data+sizeof(struct ether_header));
        if(_ip->ip_p == IPPROTO_TCP){
            hasTCP = 1;
        }
        if(_verbose){
            std::cout << "[+] Parsed out IP header" << std::endl;
        }
    }else if(ntohs(_eth->ether_type) == ETHERTYPE_IP6){
        _ip6 = (struct ip6_hdr *)(_data+sizeof(struct ether_header));
        if(_ip6->ip6_nxt == IPPROTO_TCP){
            hasTCP = 1;
        }
        if(_verbose){
            std::cout << "[+] Parsed out IPv6 header" << std::endl;
        }
        return 1;
    }else{
        return -1;
    }

    // If we have TCP extract the header
    if(hasTCP){
        _tcp = (struct tcphdr*)(_data+sizeof(struct ether_header)+sizeof(struct ip));
        if(_verbose){
            std::cout << "[+] Parsed out TCP header" << std::endl;
        }
        // Overwrite the data we have with the remaining data
        _appData = (char*)(_data + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        // Check if we have any data
        if(_appData.length() != 0){
            //std::cout << "TEST" << std::endl;
            hasData = 1;
            if(_verbose){
                std::cout << "[+] Remaining data is " << _appData.length() << " bytes long" << std::endl;
            }
        }else{
            hasData = 0;
            if(_verbose){
                std::cout << "[+] This packet has no data" << std::endl;
            }
        }
    }else{
        return -1;
    }
}

int Packet::setTCPIPdata()   
{

    // Check for IPv4 header and extract addresses
    if(_ip->ip_v == 4){
        char sourceIP[INET_ADDRSTRLEN];
        char destIP[INET_ADDRSTRLEN];
        const char* ret1 = inet_ntop(AF_INET, &_ip->ip_src, sourceIP, sizeof(sourceIP));
        const char* ret2 =inet_ntop(AF_INET, &_ip->ip_dst, destIP, sizeof(destIP));
        if(ret1 == NULL || ret2 == NULL){
            return -1;
        }
        src = sourceIP;
        dst = destIP;
    }
    // Check for IPv6 header and extract addresses
    if(_ip->ip_v == 6){
        char sourceIP[INET6_ADDRSTRLEN];
        char destIP[INET6_ADDRSTRLEN];
        const char* ret1 = inet_ntop(AF_INET6, &_ip->ip_src, sourceIP, sizeof(sourceIP));
        const char* ret2 = inet_ntop(AF_INET6, &_ip->ip_dst, destIP, sizeof(destIP));
        if(ret1 == NULL || ret2 == NULL){
            return -1;
        }
        src = sourceIP;
        dst = destIP;
    }
    srcprt = ntohs(_tcp->source);
    dstprt = ntohs(_tcp->dest);
    if(_verbose){
        std::cout << "[+] Extracted source IP - " << src << " and source port " << srcprt << std::endl;
        std::cout << "[+] Extracted dest IP - " << dst << " and dest port " << dstprt << std::endl;
    }
}

int Packet::extractHTTP(std::string type)   
{
    std::vector<std::string> seglist;
    int start = 0;
    // Add each line of a potentail request to a vector (split on \r\n)
    for(int i=0; i<_appData.length();i++){
        // We do some limited bounds checking and look for /r/n
        if(_appData.at(i) == '\r' && i != _appData.length()-1){
            if(_appData.at(i+1) == '\n'){
                // Add each line in the HTTP header to a vector
                seglist.push_back(_appData.substr(start,i-start));
                start = i+2;
            }
        }
    }
    if( start != _appData.length()-start){
        seglist.push_back(_appData.substr(start,_appData.length()-start));
    }
    std::string firstLine = seglist.front();
    if(type == "Request"){
        
        int firstSpace = -1;
        int secondSpace = -1;
        // C++ regex takes a long time (way too long)
        // ([A-Z].*?)\\s(.*?)\\s(HTTP/\\d\\.\\d)
        for(int i = 0; i<firstLine.length();i++){
            // Make sure we don't have a third space
            if(isspace(firstLine.at(i)) && secondSpace!=-1){
                httpDetected = false;
                return -1;
            }
            if(isspace(firstLine.at(i))){
                if(firstSpace==-1){
                    firstSpace=i;
                }else{
                    secondSpace=i;
                }
            }
        }
        // Make sure we found two spaces and no more or bail
        if(firstSpace == -1 || secondSpace == -1){
            httpDetected = false;
            return -1;        
        }

        method = firstLine.substr(0,firstSpace);
        uri = firstLine.substr(firstSpace+1,secondSpace-firstSpace+1);   
        version = firstLine.substr(secondSpace+1,firstLine.length()-secondSpace+1);


        // Check to make sure these conform to spec
        // version should say HTTP/[something]
        if(version.substr(0,5) != "HTTP/"){
            httpDetected = false;
            return -1;
        }
        // method should be in caps
        for(int i = 0; i<method.length();i++){
            // CAPITAL LETTERS = 65-90
            if((int)method.at(i) < 65 || (int)method.at(i) > 90){
                httpDetected = false;
                return -1;
            }
        }
        httpDetected = true;
        return 1;
    }
}

             
// Returns -1 on error
// Returns 1 on success
int checkArgs(int argc, char** argv, int* verboseRef, std::string* filenameRef)
{
    std::stringstream usage;
    usage << "Usage: " << argv[0] << " [OPTIONS]... [FILE]";
    
    // Check the number of parameters
    if (argc < 2) {
        std::cerr << usage.str() << std::endl;
        return -1;
    }else{
        *verboseRef = 0;
        if(argc > 2){
            int knownArg = 0;
            // Check if our arguments are valid (except first and last)
            for(int i=1;i<argc-1;i++){
                knownArg = 0;
                // Does everything start with a '-'
                if(argv[i][0] != '-'){
                    std::cerr << usage.str() << std::endl;
                    return -1;
                }
                // ARe they all two chars long?
                if(strnlen(argv[i],5) != 2){
                    std::cerr << usage.str() << std::endl;
                    return -1;
                }
                // Set our verbose argument
                if(argv[i][1] == 'v'){
                    *verboseRef = 1;
                    knownArg = 1;
                }
                // If we get an unknown arg, exit
                if(knownArg == 0){
                    std::cerr << usage.str() << std::endl;
                    return -1;
                }
            }
        }
        // Check if we can find the file
        if(strnlen(argv[argc-1],256) < 255){
            std::string filename = argv[argc-1];
            std::ifstream ifile(filename);
            if (ifile) {
                if(*verboseRef == 1){
                    std::cout << "[+] We were able to succesfully open " << filename << std::endl;
                }
                *filenameRef = filename;
                return 1;
            }else{
                std::cerr << "Error: Could not open/find the file you referenced. Exiting." << std::endl;
                return -1;
            }
        }
        std::cerr << "Error: Unexpected input was identified, exiting." << std::endl;
        std::cerr << "Error: Could not open/find the file you referenced. Exiting." << std::endl;
        return 1;
    }

}


int main(int argc, char* argv[])
{
    int verbose = 0;
    char errbuff[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *data;
    std::string  filename;

    // Check if our arg values are wrong
    if(checkArgs(argc,argv,&verbose,&filename) == -1){
        return -1;    
    }

    // Initalize the ModSecurity Engine 
    ModSecurityAnalyzer *msa = new ModSecurityAnalyzer("basic_rules.conf");

    // Read in our pcap file
    pcap_t * pcap = pcap_open_offline(filename.c_str(),errbuff);
    if( pcap == NULL ){
        std::cerr << "Error: unable to open Pcap File supplied: " << errbuff << std::endl;
        return -1;
    }
    
    // Loop through each packet
    while(pcap_next_ex(pcap, &header, &data) >= 0)
    {  
        Packet * mypacket = new Packet(header,data,verbose);
        // Try parsing each packet
        if(mypacket->parsePacket() == -1){
            if(verbose){
                std::cerr << "Error: There was a problem parsing a packet" << std::endl;
            }
            continue;
        }
        // Check if we have a ports/IPs
        if(mypacket->setTCPIPdata() != -1){
            // Check if it is on a common HTTP port first
            if((mypacket->srcprt == 80 || mypacket->srcprt == 8080) && mypacket->hasData == 1){
                // Extract HTTP information
                mypacket->extractHTTP("Response");
            }
            if((mypacket->dstprt == 80 || mypacket->dstprt== 8080) && mypacket->hasData == 1 ){
                mypacket->extractHTTP("Request");
            }     
        }else{
            if(verbose){
                std::cerr << "Error: There was problem extracting TCPIP data" << std::endl;
                continue;
            }
        }
        if(mypacket->httpDetected == true){
            msa->AddConnectionInfo(mypacket->src, mypacket->srcprt,mypacket->dst,mypacket->dstprt);
            msa->AddRequestInfo(mypacket->uri,mypacket->method,mypacket->version);
            msa->RunPhases();
        }
    }
    msa->RunCleanup();
    
}
