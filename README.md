# ModSecurity-pcap
Have you ever wanted to run ModSecurity out of line without a webserver? Have you been told it's impossible? ModSecurity v3 makes anything possimpible! This is the ModSecurity v3 connector for a pcap file.

This is also a good example of how to use libmodsecurity's C++ interfaces.

Currently using the following to compile
g++ -std=c++11 -I../../../headers -L../../../src/.libs/ ../../../src/.libs/libmodsecurity.so -lpcap -Wl,-rpath -Wl,/usr/local/modsecurity/lib pcap.cc
