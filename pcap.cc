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

#include "pcap.h"


#ifndef ETHERTYPE_IP6
    #define ETHERTYPE_IP6 0x86dd
#endif



// Our constructor that collects the packet header and data
Packet::Packet(pcap_pkthdr *header, const u_char *data, int verbose)
{
    _header = header;
    _data = data;
    _verbose = verbose;
}

// We will take a raw packet and break it down 
// part by part till we get to the app data
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
    // Extract our src and dest ports
    srcprt = ntohs(_tcp->source);
    dstprt = ntohs(_tcp->dest);

    if(_verbose){
        std::cout << "[+] Extracted source IP - " << src << " and source port " << srcprt << std::endl;
        std::cout << "[+] Extracted dest IP - " << dst << " and dest port " << dstprt << std::endl;
    }
}

// We need to check if it's an HTTP packet and
// if it is extract the URI based on if it's
// a request or a response HTTP
int Packet::extractHTTPuri(std::string type)   
{
    // Store our type for later
    if(type == "Request"){    
        request = 1;
    }else{
        request = 0;
    }
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
    // Make sure to not forget the last element (and bound checking)
    if( start != _appData.length()-start){
        seglist.push_back(_appData.substr(start,_appData.length()-start));
    }
    // Persist our vector (representing line by line HTTP data)
    _splitHTTP = seglist;

    // We'll only need the first line to get started
    std::string firstLine = seglist.front();

    if(request){        
        int firstSpace = -1;
        int secondSpace = -1;
        // C++ regex takes a long time (way too long)
        // ([A-Z].*?)\\s(.*?)\\s(HTTP/\\d\\.\\d)
        // get the locations of the first two spaces
        for(int i = 0; i<firstLine.length();i++){
            // Make sure we don't have a third space (there shouldn't be)
            if(isspace(firstLine.at(i)) && secondSpace!=-1){
                httpDetected = false;
                return -1;
            }
            // Otherwise record spaces
            if(isspace(firstLine.at(i))){
                if(firstSpace==-1){
                    firstSpace=i;
                }else{
                    secondSpace=i;
                }
            }
        }
        // Make sure we found two spaces and no less or bail
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
    // If its not a request its an HTTP response 
    if(!request){
        int firstSpace = -1;
        int secondSpace = -1;
        // C++ regex takes a long time (way too long)
        // (HTTP/\\d\\.\\d)\\s(\\d{3})\\s(.*)
        for(int i = 0; i<firstLine.length();i++){
            // split the first two spaces out
            // the phrase can have spaces 
            if(isspace(firstLine.at(i))){
                if(firstSpace==-1){
                    firstSpace=i;
                }else{
                    secondSpace=i;
                }
            }
        }
        // Make sure we found two spaces and no less or bail
        if(firstSpace == -1 || secondSpace == -1){
            httpDetected = false;
            return -1;        
        }

        rVersion = firstLine.substr(0,firstSpace);
        status = firstLine.substr(firstSpace+1,secondSpace-firstSpace+1);   
        phrase = firstLine.substr(secondSpace+1,firstLine.length()-secondSpace+1);

        // Check to make sure these conform to spec
        // version should say HTTP/[something]
        if(rVersion.substr(0,5) != "HTTP/"){
            httpDetected = false;
            return -1;
        }
        // Status should be of length 3 (eg 200)
        if(status.length() != 3){
            httpDetected = false;
            return -1;
        }
        // Status should also only be numeric
        for(int i = 0; i<status.length();i++){
            // n3mb3rs - ASCII 48-57
            if((int)status.at(i) < 48 || (int)status.at(i) > 57){
                httpDetected = false;
                return -1;
            }
        }
        
    }
}

// We need to get the headers out one by one and
// isolate the data portion of the HTTP element
int Packet::extractHTTPData()   
{
    // We have a request/response URI and something else (maybe headers)
    if(_splitHTTP.size() > 1){
        // First line is request/responseURI - last line may be data
        for(std::vector<std::string>::size_type header = 1; header != _splitHTTP.size()-1; header++) {
            // Ignore blank lines (we'll use the later)
            if(_splitHTTP[header] == ""){
                continue;
            }

            // Search for colon and split our header based on it
            for(int i = 0;i<_splitHTTP[header].length();i++){
                if(_splitHTTP[header].at(i) == ':'){
                    headerNames.push_back(_splitHTTP[header].substr(0,i));
                    headerValues.push_back(_splitHTTP[header].substr(i+1,_splitHTTP[header].length()-(i+1)));
                    break;
                }
            }
        }

        // Check our headers to see if there is content
        // apparently this isn't really a great check
        for(auto headerName: headerNames){
            if(headerName == "Content-Length"){
                _hasHTTPData = 1;
            }
        }
        // Also check for a black CRLF as the penultimate item
        if (_splitHTTP.rbegin()[1] == ""){
            _hasHTTPData = 1;
        }
        // if there is data extract it as data, otherwise its a header
        if(_hasHTTPData){
            bodyData = _splitHTTP.back();
        }else{
            for(int i = 0;i<_splitHTTP.back().length();i++){
                if(_splitHTTP.back().at(i) == ':'){
                    headerNames.push_back(_splitHTTP.back().substr(0,i));
                    headerValues.push_back(_splitHTTP.back().substr(i+1,_splitHTTP.back().length()-(i+1)));
                }
            }
        }
    }
}

         

class ModSecurityAnalyzer
{
    public:
        ModSecurityAnalyzer(std::string main_rule_uri);
        int AddConnectionInfo(std::string src,int srcprt,std::string dst,int dstprt);
        int AddRequestInfo(Packet *mypacket);
        int AddResponseInfo(Packet *mypacket);
        int RunPhases();
        int RunAssayCleanup();
        int RunCleanup();
    private:
        int _testIntervention(modsecurity::ModSecurityIntervention status_it);
        // ModSecurity engine 
        modsecurity::ModSecurity *_modsec;
      
       // modsecurity rules
       modsecurity::Rules *_rules;
 
       // modsecurity transaction object
       modsecurity::Assay *_pmodsecAssay;
};

ModSecurityAnalyzer::ModSecurityAnalyzer(std::string main_rule_uri){
    const char *error = NULL;
    // Connect to libmodsecurity
    _modsec = modsecurity::msc_init();
    _modsec->setConnectorInformation("ModSecurity-pcap v0.0.1-alpha");
    
    // Load the modsecurity rules specified.
    _rules = modsecurity::msc_create_rules_set();
    if(modsecurity::msc_rules_add_file(_rules, main_rule_uri.c_str(), &error) < 0){
        std::cerr << "Error: Issues loading the rules." << std::endl << error << std::endl;
    }
    // C++ form of msc_rules_dump()
    _rules->dump();
}


int ModSecurityAnalyzer::AddConnectionInfo(std::string src,int srcprt,std::string dst,int dstprt){
    _pmodsecAssay = modsecurity::msc_new_assay(_modsec, _rules, NULL);
    // Assign the IP's and ports to the transaction
    _pmodsecAssay->processConnection(src.c_str(), srcprt, dst.c_str(), dstprt);
    return 1;       

}

int ModSecurityAnalyzer::AddRequestInfo(Packet *mypacket){
    std::string uri = mypacket->uri;
    std::string method = mypacket->method;
    std::string version = mypacket->version;
    std::vector<std::string> headerNames = mypacket->headerNames;
    std::vector<std::string> headerValues =mypacket->headerValues;
    std::string bodyData = mypacket->bodyData;

    // ModSecurity wants the HTTP/ removed from the 1.1
    version = version.substr(5,version.length()-5);
    _pmodsecAssay->processURI(uri.c_str(),method.c_str(),version.c_str());

    // Add each header key/value to as a header in modsec
    for(std::vector<std::string>::size_type header = 0; header != headerNames.size(); header++) {
      _pmodsecAssay->addRequestHeader(reinterpret_cast<const unsigned char*>(headerNames[header].c_str()),reinterpret_cast<const unsigned char*>(headerValues[header].c_str()));
    }

    // Add the body data only if it has a body
    if(bodyData != "" ){
        _pmodsecAssay->appendRequestBody(reinterpret_cast<const unsigned char*>(bodyData.c_str()),bodyData.length());
    }
    return 1;
}

int ModSecurityAnalyzer::AddResponseInfo(Packet *mypacket){
    std::string bodyData = mypacket->bodyData;
    std::vector<std::string> headerNames = mypacket->headerNames;
    std::vector<std::string> headerValues =mypacket->headerValues;

    //TODO: RESPONSE STATUS is not implmented yet

    // Add each response header as a header in modsec
    for(std::vector<std::string>::size_type header = 0; header != headerNames.size(); header++) {
      _pmodsecAssay->addResponseHeader(reinterpret_cast<const unsigned char*>(headerNames[header].c_str()),reinterpret_cast<const unsigned char*>(headerValues[header].c_str()));
    }
    
    // Add the body if there is one
    if(bodyData != "" ){
        _pmodsecAssay->appendRequestBody(reinterpret_cast<const unsigned char*>(bodyData.c_str()),bodyData.length());
    }

}

// Testing for interventions is needed but we can't deny anyway, we're out of line
// If needed a TCP reset packet could be sent here to try and emulate inline-ness
int ModSecurityAnalyzer::_testIntervention(modsecurity::ModSecurityIntervention status_it){
    _pmodsecAssay->intervention(&status_it);
    if( status_it.disruptive == 1)
    {
        std::cout << "There was a disruptive action but we are out of line" << std::endl;
        if(status_it.log != NULL){
             std::cerr << "processResponseBody intervention: " << status_it.log << std::endl;
        }else{
             std::cerr << "no data received from modsecuritylib in processResponseBody: status_it.log is NULL" << std::endl;

        }
        return 1;
    }
    return 0;
}

// This is where we tell ModSec to actually check
// our packet
int ModSecurityAnalyzer::RunPhases(){
    modsecurity::ModSecurityIntervention status_it;
    _pmodsecAssay->processRequestHeaders();
    _testIntervention(status_it);
    _pmodsecAssay->processRequestBody();
    _testIntervention(status_it);
    _pmodsecAssay->processResponseHeaders();
    _testIntervention(status_it);
    _pmodsecAssay->processResponseBody();
    _testIntervention(status_it);
    _pmodsecAssay->processLogging(200);
    _testIntervention(status_it);
    return 1;
}
int ModSecurityAnalyzer::RunAssayCleanup(){
    delete _pmodsecAssay;
}
int ModSecurityAnalyzer::RunCleanup(){
    delete _rules;
    delete _modsec;
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
                mypacket->extractHTTPuri("Response");
            }
            if((mypacket->dstprt == 80 || mypacket->dstprt== 8080) && mypacket->hasData == 1 ){
                mypacket->extractHTTPuri("Request");
                
            }     
        }else{
            if(verbose){
                std::cerr << "Error: There was problem extracting TCPIP data" << std::endl;
                continue;
            }
        }
        // Only if we found HTTP data we need to do things
        if(mypacket->httpDetected == true){
            // We want to add the IP/port info about the request
            msa->AddConnectionInfo(mypacket->src, mypacket->srcprt,mypacket->dst,mypacket->dstprt);
            // This will pull out headers and body
            mypacket->extractHTTPData();
            // We then add them into modsec
            if(mypacket->request){
                msa->AddRequestInfo(mypacket);
            }
            if(!mypacket->request){
                msa->AddResponseInfo(mypacket);
            }
            // Last we run our transaction through the rules
            msa->RunPhases();
        }
        // We won't need our packet for this tool
        delete mypacket;
        // TODO: cleaning up the assay results in a segfault?
        //msa->RunAssayCleanup();
    }
    // Cleansup our modsec objects
    msa->RunCleanup();
    delete msa;
    
}
