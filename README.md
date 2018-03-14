<html>
<head>
<title>User Documentation</title>
</head>
<body bgcolor="#99CCCC">
<div align="center"><h1><b>Sniff v2.2</b></h1></div>
<div align="center"><h2><b>User Documentation</b></h2></div>
<font size="+1">
<div align="right"><b>December 09, 2004</b><br></div>
<hr>

<h2><b>1. Introduction</b></h2>
<p>Sniff v2.2 is a network monitoring tool developed for platforms running POSIX operating systems. It monitors all the packet activity in the network, logs the information extracted from the packets and displays a simple user-friendly online  summary. The summary is displayed at console and webpage interfaces. Also, the packets may be dumped straight, without online analysis and can be analysed (offline) later. Sniff has a complex triple-process architecture (It spawns three processes when you launch the tool!) in order to ensure high performance levels during peak network activity. This document describes the features, user options and intended uses of the tool. For technical details kindly go through the <a href="sniff2.2-sdd.html">Software Design Document</a> and <a href="sniff2.2-srs.html">System Requirements</a>. Also go through the <a href="tutorial.html">Networking Basics Tutorial</a> for a brief survey of some of the concepts of contemporary computer networking.</p>
<br>
<h2><b>2. Why Sniff?</b></h2>
<p>There are many network analysis freeware tools available today. Softwares like Ethereal and TCPDump are used by system administrators, protocol developers and networking professionals. These tools are characterised by very high protocol coverage (Ethereal supports 602 protocols!), detailed protocol analysis, and complex and extensive user options. The extent to which the gory details are extracted from the packets is so extensive that it usually drowns the user with an information flood. It is very hard for the user to get a birds eye view of the network as a whole. This is where the need for a tool like Sniff arises.</p>

<p>Sniff focusses on providing a simple overall summary of the packet activity in the network. It is more of a wholesome network monitor than an extensive protocol analyser. The emphasis on the holistic birds eye view of the whole network and the ease of comprehension of the summarised information, together make Sniff a convenient tool for the diagnosis of the aberrations that might be present in the network. Once the trouble is identified and diagnosed, appropriate remedial measures may be figured out after a more detailed analysis using one of the extensive analysers available. Another advantage that Sniff has is its webpage interface. Other tools can be run only on local machines, whereas the webpage interface that Sniff provides makes it possible to monitor networks anywhere in the world.</p>
<br>
<h2><b>3. Features</b></h2>
<p>Sniff comes with a wide range of features. Some of the salient features are listed below.</p>

<ul>
<li>Packets are captures completely "off the wire" from the network. The high performance triple-process architecture doesn't leave a single packet uncaptured!</li>

<li>Analysis of the packets is extensive at the machine, network and transport layers of the protocol stack to provide a wholesome picture of the network. Analysis of the application layer protocols is done only to the required extent to improve performance and save the users from getting drowned in information.</li>

<li>The analysis generates extensive logs covering every packet analysed. The logs are in a simple easy-to-read format.</li>

<li>A succinct and a complete summary of the analysis going on can be viewed online. The summary gives a machinewise and a protocolwise profile of all the packets analysed so far. The packet density and the packet collision count are also displayed.</li>

<li>The webpage interface provided makes it possible to use Sniff to monitor remote networks.</li>

<li>Packet data can be dumped to a file (preferable on a RAM Disk) and analysed offline later.</li>

<li>Users can specify filters to analyse only those packets which pass through. Filters can be specified w.r.t. machine addresses, IP addresses and port numbers in simple config files, which are easy to write.</li>

<li>The package comes with statically linked binaries that can be executed on any POSIX operating system.</li>

<li>The user interface is simple and console based. It requires the barest minimum of resources and works even on the most primitive consoles.</li>
</ul>
<br>
<h2><b>4. Compiling Source and Installation</b></h2>
<p>The package provides pre-compiled binaries with the source. The source can be compiled by issuing a <b><i>make all</b></i> in the source directory. System administrators may install the tool by issuing a <b><i>make install</b></i> command in the source directory. Kindly go through the <a href="sniff2.2-srs.html#lib">System Requirements</a> for library dependencies.</p>
<br>
<a name="usage"></a>
<h2><b>5. Usage and Options</b></h2>
<p>The software provides three tools viz. <i>sniff</i>, <i>sniff_dump</i> and <i>sniff_open</i>.</p>

<ul>
<li><p><b>iitm_sniff:</b><br>
Sniff is the online network monitor. The static linked executable is sniff_static in the bin directory of the distribution. It should be invoked with root privileges as:<br>
<div align="center"> <font color="brown">
./iitm_sniff &lt;number of packets&gt; [&lt;optional config file&gt;]</div></font><br>
For analysis of infinite number of packets, the number of packets may be specified as -1. To exit out of the execution press <b>CTRL C</b> at any point of time. The log file generated at the end of the execution is called <i>log.txt</i> and its format is described below. The optional config file (which sets the packet filters) must be in the format described subsequently.</p></li>

<li><p><b>iitm_sniff_dump:</b><br>
Sniff_dump is a packet data dumping tool. It should be invoked with root privileges as:<br>
<div align="center"> <font color="brown">
./iitm_sniff_dump &lt;number of packets&gt; &lt;dump_file&gt;</font></div><br>
The packet data is dumped to &lt;dump file&gt; and -1 keeps dumping infinitely.</p></li>

<li><p><b>iitm_sniff_open:</b><br>
Sniff_open is the offline analysis tool for the dumped packets (using sniff_dump). It should be invoked with root privileges as:<br>
<div align="center"> <font color="brown">
./iitm_sniff_open &lt;dumpfile&gt; [&lt;optional config file&gt;]</div></font><br>
It generates a log file like the tool sniff.</p></li>

<li><p><b>Log File Format:</b><br>
The log file is generated by both sniff and sniff_open and is called <i>log.txt</i>. The logs generated for the individual packets are separated by empty lines. The log for a packet begins with the timestamp. The ethernet header is printed in the next line followed by the IP and TCP/UDP headers in the following lines. The application packet protocol (if known) is printed in the next line.</p></li>

<a name=config></a>
<li><p><b>Config File Format:</b><br>
Config files are used to specify the machine addresses, IP addresses and port numbers to be used for filtering. The addresses and numbers need to be specified in individual lines with appropriate tags indication what they are. The tags to be used are <machine> </machine>, <hosts> </hosts> and <ports> </ports> for specifying machine addresses, IP addresses and port number respectively. Note that these tags also need to be specified in individual lines.<br><br>

A sample config file would look like:<br><br>
<div align="left">
<font color="brown">
&lt;machine&gt;<br>
0:2:44:89:2:ec<br>
0:20:ed:f:64:80<br>
0:11:5b:21:50:41<br>
0:8:2:66:b:2d<br>
0:e0:4c:e9:64:c2<br>
&lt;/machine&gt;<br>
&lt;hosts&gt;<br>
10.132.9.12<br>
10.120.1.1<br>
&lt;/hosts&gt;<br>
&lt;ports&gt;<br>
110<br>
80<br>
&lt;/ports&gt; </font></div></p></li>

<li><p><b>iitm_sniff.pl:</b><br>
This CGI script provides the webpage user interface. It must be installed in the <i>cgi-bin</i> directory of the webserver running on the machine. The webserver needs to be configured to support CGI scripting. The latest network activity can be remotely monitored by refreshing the webpage (spawned by the script) periodically.</p></li>
</ul>
<br>
<h2><b>6. User Interface Screenshots</b></h2>
<p>The user interfaces (both console and webpage) consist of the header, the machinewise profile and the protocolwise profile. The header displays time, number of packets analysed, packet density and number of packets dropped. The machinewise profile shows the details of the packet activity of the most active systems in the network. The protocolwise profile gives the protocol distribution of the packets. (See the screenshot given below.) A sample <a href="iitm_sniff.cgi.html">webpage</a> (spawned by the CGI script) is also available.</p>
<a name=screen></a>
<p><i>A 450,000-odd packet analysis session is still going on...</i>
<p><img align="top" src="https://github.com/kameshr/sniff/blob/master/docs/screen1.jpg" width="836" height="536"></p><br>
<hr>
<i>Project developed by Kamesh Raghavendra (<a href="mailto: kameshr@gmail.com">kameshr@gmail.com</a>) under the guidance of Prof. R Kalyana Krishnan, Dept. of CSE, IIT Madras</i>
</font>
</body>
</html>
