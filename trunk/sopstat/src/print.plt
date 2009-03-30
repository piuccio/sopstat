#prova file gnuplot
#set terminal jpeg
#load  "parameters.gp"

set terminal jpeg large font arial size 800,600 xffffff x000000 x000000 xff0000 xffa500 x66cdaa xcdb5cd xadd8e6 x0000ff xdda0dd x9500d3    # defaults
set macros

set output sprintf("%s/%s/n_peers_dw.jpeg",dir,name)
#set term x11 enhanced font "verdanaz,15" 
set title 'Number of peers (download)' 
set xlabel "Time (seconds) "
set ylabel "Peers"
plot sprintf("%s/time_dwudp.dat",dir) using 1:9 with boxes title "Number of active peers"

set output sprintf("%s/%s/n_peers_up.jpeg",dir,name)
set title 'Number of peers (upload)' 
set xlabel "Time (seconds) "
set ylabel "Peers"
plot sprintf("%s/time_upudp.dat",dir) using 1:9 with boxes title "Number of active peers"

set output sprintf("%s/%s/discovery_rate.jpeg",dir,name)
set title 'Discovery Rate' 
set xlabel "Time (seconds) "
set ylabel "Discovery rate B/s"
plot sprintf("%s/time_upudp.dat",dir) using 1:8 with lines title ""

set output sprintf("%s/%s/video_rate_dw.jpeg",dir,name)
set title 'Video Rate (download)' 
set xlabel "Time (seconds) "
set ylabel "Video Rate kB/s"
plot sprintf("%s/time_dwudp.dat",dir) using 1:5 with lines title ""

set output sprintf("%s/%s/video_rate_up.jpeg",dir,name)
set title 'Video Rate (upload)' 
set xlabel "Time (seconds) "
set ylabel "Video Rate kB/s"
plot sprintf("%s/time_upudp.dat",dir) using 1:5 with lines title ""

set output sprintf("%s/%s/data_sent.jpeg",dir,name)
set title 'Data sent (upload)' 
set xlabel "Time (seconds) "
set ylabel "Data sent kB/s"
plot sprintf("%s/time_upudp.dat",dir) using 1:3 with lines title ""

set output sprintf("%s/%s/data_downloaded.jpeg",dir,name)
set title 'Data received (download)' 
set xlabel "Time (seconds) "
set ylabel "Data received kB/s"
plot sprintf("%s/time_dwudp.dat",dir) using 1:3 with lines title ""


set output sprintf("%s/%s/data_and_video_downloaded.jpeg",dir,name)
set title 'Data and Video received (download)' 
set xlabel "Time (seconds) "
set ylabel "Data received kB/s"
plot sprintf("%s/time_dwudp.dat",dir) using 1:3 with lines title "Total Data", \
sprintf("%s/time_dwudp.dat",dir) using 1:5 with lines title "Video"


set output sprintf("%s/%s/packet_size.jpeg",dir,name)
set title 'UDP Packet Size Distribution' 
set xlabel "Time (seconds) "
set ylabel "Packet Size Byte"
plot sprintf("%s/stream.dat",dir) using 1:5 with dots title ""


set output sprintf("%s/%s/packet_size_up.jpeg",dir,name)
set title 'UDP Packet Size Distribution (upload)' 
set xlabel "Time (seconds) "
set ylabel "Packet Size Byte"
plot sprintf("%s/upudp.dat",dir) using 1:5 with dots title ""


set output sprintf("%s/%s/packet_size_dw.jpeg",dir,name)
set title 'UDP Packet Size Distribution (download)' 
set xlabel "Time (seconds) "
set ylabel "Packet Size Byte"
plot sprintf("%s/dwudp.dat",dir) using 1:5 with dots title ""


#pause -1 "Press enter to quit!"
