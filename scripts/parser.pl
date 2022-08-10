#!/usr/bin/perl -w
# http://www.perlmonks.org/index.pl?node_id=17576
# http://en.wikipedia.org/wiki/IPv4#Packet_structure
# http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
# http://www.iana.org/assignments/ip-parameters/ip-parameters.xml
# http://wiki.wireshark.org/Development/LibpcapFileFormat
# http://www.tcpdump.org/linktypes.html
use Fcntl;
use strict;

my %seq = ();
my $frame = 0;
my $debug = 0;
my ($interseptpktsz, $iphdrsz, $tcphdrsz) = (56, 20, 20);

open FD, $ARGV[0] or die $!;

sysopen TSHARK, "tshark.log", O_CREAT | O_TRUNC | O_WRONLY or die $!;

syswrite TSHARK, pack ("LsslL3", ( 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101 ) );

while (!eof(FD)) {
	my $buffer;
	read FD, $buffer, $interseptpktsz or die $!;

	# Structure format
	# (8 bytes) long long -> sec
	# (8 bytes) long long -> nsec
	# (4 bytes) Integer -> source ip addr
	# (4 bytes) Integer -> destination ip addr
	# (4 bytes) Integer -> pid
	# (4 bytes) Integer -> tgid
	# (4 bytes) Integer -> parent->pid
	# (4 bytes) Integer -> parent->tgid
	# (4 bytes) file descriptor
	# (2 bytes) Short -> source port
	# (2 bytes) Short -> destination port
	# (2 bytes) Short -> message size
	# (1 byte)  Character -> message type (r/w)
	# (5 byte)  padding
	# Payload

	my ($sec, $nsec, $src_host, $dst_host, $pid, $tgid, $parentpid, $parenttgid, $filedes,
		$src_port, $dst_port, $pkt_len, $op) = unpack ('QqNNi5nnScx5', $buffer);

	read FD, $buffer, $pkt_len or die $!;

	if ($debug)
	{
		print (sprintf ("%d ", $pkt_len));
		print (sprintf ("%c ", $op));
		print (sprintf ("%u.", $sec));
		print (sprintf ("%06u ", $nsec));
		print (sprintf ("%d.%d.%d.%d ", unpack ('C4', pack ('N', $src_host))));
		print (sprintf ("%d.%d.%d.%d ", unpack ('C4', pack ('N', $dst_host))));
		print (sprintf ("%d ", $src_port));
		print (sprintf ("%d ", $dst_port));
		print (sprintf ("%d ", $pid));
		print (sprintf ("%d ", $tgid));
		print (sprintf ("%d ", $parentpid));
		print (sprintf ("%d ", $parenttgid));
		print (sprintf ("%d ", $filedes));

		print map ( chr($_ > 31 && $_ < 127? $_ : 32 ), unpack ('C*', $buffer));
		print ("\t");
		print map ( sprintf ("%02x", $_), unpack ('C*', $buffer));
		print ("\n");
	}
	else
	{
		syswrite STDOUT, "$frame\r";
	}

	my @pktid = ($src_host, $dst_host, $src_port, $dst_port );
	@pktid = @pktid[1,0,3,2] if ($op eq ord('w'));

	my $ip_ver = 4;
	my $ip_ttl = 254;
	my $ip_hdr_len = 0x05;
	my $ip_proto = 6; # tcp
	my $tcp_hdr_len = 0x05;
	my $tcp_window_size = 8192;

	my $seqn = 0;
	my $hash = pack ('NNnn', @pktid);
	$seqn = $seq{$hash}
		if defined $seq{$hash};

	my $ip_opts = pack ('w*', $pid, $tgid, $parentpid, $parenttgid, $filedes);
	my $ip_opts_sz = length($ip_opts) + 2;
	my $ip_opts_sz_norm = (($ip_opts_sz % 4) == 0) ? int($ip_opts_sz / 4) : int($ip_opts_sz / 4) + 1;

	$ip_opts = unpack ('H*', pack ('CC', 0xFF, $ip_opts_sz) . $ip_opts . pack ('x' x (($ip_opts_sz_norm * 4) - $ip_opts_sz)));
	$ip_hdr_len += $ip_opts_sz_norm;
	$ip_opts_sz = length($ip_opts) / 2;

	my $tcp_opts_sz = ( $tcp_hdr_len - 0x05 ) << 2;
	my $tcp_opts = 'FF' x $tcp_opts_sz;

	my $snaplen =  $iphdrsz + $tcphdrsz + $ip_opts_sz + $tcp_opts_sz + $pkt_len;

	syswrite TSHARK, pack ("L4", $sec, int ($nsec / 1000), $snaplen, $snaplen);

 	syswrite TSHARK, pack ('Cxnx4C2nN2H' . 2 * $ip_opts_sz . 'n2Nx4Cxnx4H' . 2 * $tcp_opts_sz,
		($ip_ver & 0x0f) << 4 | ($ip_hdr_len & 0x0f),
		$iphdrsz + $tcphdrsz +$ip_opts_sz + $tcp_opts_sz + $pkt_len,
		$ip_ttl, $ip_proto, 
		unpack('n*', pack('S*', &in_cksum(pack('Cxnx4C2x2N2H' . 2 * $ip_opts_sz,
			($ip_ver & 0x0f) << 4 | ($ip_hdr_len & 0x0f),
			$iphdrsz + $tcphdrsz +$ip_opts_sz + $tcp_opts_sz + $pkt_len,
			$ip_ttl, $ip_proto, @pktid[0,1], $ip_opts)))),
		@pktid[0,1], $ip_opts, @pktid[2,3], $seqn,
		($tcp_hdr_len & 0x0f) << 4, $tcp_window_size, $tcp_opts);

	syswrite TSHARK, $buffer, $pkt_len;

	$seq{$hash} = $seqn + $pkt_len;
	$frame++;
}

sub in_cksum {
    my ($packet) = @_;
    my ($plen, $short, $num,  $count, $chk);

    $plen = length($packet);
    $num = int($plen / 2);
    $chk = 0;
    $count = $plen;

    foreach $short (unpack("S$num", $packet)) {
        $chk += $short;
        $count = $count - 2;
    }

    if($count == 1) {
        $chk += unpack("C", substr($packet, $plen -1, 1));
    }

    $chk = ($chk >> 16) + ($chk & 0xffff);
    return(~(($chk >> 16) + $chk) & 0xffff);
}
