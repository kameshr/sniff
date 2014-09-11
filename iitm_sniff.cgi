#!/usr/bin/perl -w
# $$File$$ iitm_sniff.cgi 	$$Date$$ December 10, 2004
# This script is a part of Sniff v2.2 tool
# It provides the web interface to Sniff
use strict;

print("Content-type: text/html\n\n");
print("<html>\n");
print("<head>\n");
print("<title>IIT Sniff Web Interface</title>\n");
print("<meta http-equiv=\"REFRESH\"\nCONTENT=\"12\">\n");
print("</head>\n");
print("<body bgcolor=\"#99CCCC\">\n");
#print("<body>\n");
print("<div align=\"center\"><h1><b>IITM Sniff v2.2</b></h1></div>\n");
print("<div align=\"center\"><h2><b>Network Activity Relay</b></h2></div>\n");
my(@months) = ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December");
(my($sec), my($min), my($hour), my($mday), my($mon), my($year), my($wday), my($ydat), my($isdst)) = localtime();
$year += 1900;
print("<div align=\"right\"><font color=\"brown\" size=\"+1\"><b>$months[$mon] $mday, $year<br>\n");
printf("%02d:%02d:%02d hrs IST</b></font><br>\n", $hour, $min, $sec);
print("<hr>\n");
print("<font size=\"+1\">\n");

my($filename) = "/tmp/sniffweb.txt";
my($first) = 1;
my($last) = 0;

if( -e $filename or errorpage() ) {
	open( my($file), "<".$filename ) or errorpage();
	print("<br><br>\n");
	while(<$file>) {
		if( $_ eq "\n" ) {
			$last = 1;
			$_ = "";
			next;
		}
		chomp($_);
		if( $first == 1 ) {
			my(@nums) = split(/ /,$_);
			print("<table border=\"1\" align=\"center\" cellpadding=\"5\" cellspacing=\"2\" width=\"300\">\n");
			print("<caption><b><font color=\"brown\" size=\"+1\">Network Activity Summary</b></font></caption>\n");
			print("<tr><th align=\"left\">Time (HH:MM:SS)<td colspan=\"2\">$nums[0]\n");
			print("<tr><th align=\"left\">Total Packets<td colspan=\"2\">$nums[1]\n");
			print("<tr><th align=\"left\" rowspan=\"2\">Packet Density<th align=\"left\">Average<td>$nums[2]\n");
			print("<tr><th align=\"left\">Current<td>$nums[3]\n");
			print("<tr><th align=\"left\">Dropped Packets<td colspan=\"2\">$nums[4]\n");
			print("</table>");
			print("<br>\n");
			print("<hr><br>\n");
			$first = 0;

			print("<table border=\"1\" align=\"center\" cellpadding=\"5\" cellspacing=\"2\">\n");
			print("<caption><b><font color=\"brown\" size=\"+1\">Machinewise Analysis of the packets</b></font></caption>\n");
			print("<tr><th>Machine Address<th>IP Address<th>Total<th>ARP<th>RARP<th>IP<th>ICMP<th>TCP<th>UDP<th>OTHER\n");
			$_ = "";
			next;
		}
		if($last == 1) {
			my(@nums) = split(/ /, $_);
			print("</table>\n<br>\n<hr><br>\n");
			print("<table border=\"1\" align=\"center\" cellpadding=\"5\" cellspacing=\"2\">\n");
			print("<caption><b><font color=\"brown\" size=\"+1\">Protocolwise Analysis of the packets</b></font></caption>\n");
			print("<tr><th>Total<th>ARP<th>RARP<th>IP<th>ICMP<th>TCP<th>UDP<th>OTHER\n");
			print("<tr><td>$nums[0]<td>$nums[1]<td>$nums[2]<td>$nums[3]<td>$nums[4]<td>$nums[5]<td>$nums[6]<td>$nums[7]\n");
			print("</table>\n");
			$last = 0;
			$_ = "";
			next;
		}
			
		my(@nums) = split(/ /,$_);
		print("<tr><td>$nums[0]<td>$nums[1]<td>$nums[2]<td>$nums[3]<td>$nums[4]<td>$nums[5]<td>$nums[6]<td>$nums[7]<td>$nums[8]<td>$nums[9]\n");
		$_ = "";
	}
	print("<hr><a href=\"http://www.cs.iitm.ernet.in/~kameshr/csd/csd.html\">Back</a> to Software Home Page\n");
	print("</font>\n</body>\n</html>\n");
	close($file);
}

sub errorpage() {
	print("<br><br><h2><b><div align=\"left\">Error: Sniff is not running on this machine.</div></b></h2>\n");
	print("<hr><a href=\"http://www.cs.iitm.ernet.in/~kameshr/csd/csd.html\">Back</a> to Software Home Page\n");
	print("</font>\n</body></html>\n");
	exit(0);
}
