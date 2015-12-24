# ModSecurity-pcap
Currently using the following to compile
g++ -std=c++11 -I../../../headers -L../../../src/.libs/ ../../../src/.libs/libmodsecurity.so -lpcap -Wl,-rpath -Wl,/usr/local/modsecurity/lib pcap.cc
