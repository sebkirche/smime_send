#!/usr/bin/env perl

# smime_send.pl - simple helper that can send multipart emails w/ attachments,
#                 sign & encrypt messages 

use strict;
use warnings;
use feature 'say';
use utf8;
use Digest::MD5;
use File::Basename;
use Getopt::Std;
use IPC::Open3;
use IO::Select;
use Net::SMTP;
use MIME::Base64 qw( encode_base64 decode_base64);
use MIME::QuotedPrint;
use POSIX;
use Symbol;                     # for gensym

my $VERSION = '1.1';

# Poor man's logger
use constant ERROR => 1;
use constant INFO  => 2;
use constant DEBUG => 3;
use constant TRACE => 4;
my $LOG_LVL = INFO;

$|++;

setlocale(LC_TIME, 'C');        # use standard time formating for Date: header

my $opts = {};
if (scalar @ARGV == 0){
    usage();
    exit 1;
}
unless (getopts("dt:f:s:a:c:k:r:x:SC:?h", $opts)){
    usage();
    exit 1;
}
if ($opts->{h} || $opts->{'?'}){
    usage();
    exit 0;
}

$LOG_LVL = TRACE if $opts->{d};
die "-c needs a valid certificate" if ($opts->{c} && ! -f $opts->{c});
die "-k needs a valid key" if ($opts->{k} && ! -f $opts->{k});
die "-r needs a valid certificate" if ($opts->{r} && ! -f $opts->{r});
# die "-C needs a valid certificate" unless $opts->{C};
die "Missing parameter: -t <recipient>" unless $opts->{t};
# die "Missing parameter: -f <from> when signing" if $opts->{S} && !$opts->{f};
die "Missing parameter: -s <subject>" unless $opts->{s};

my $cert = $opts->{c} || 'smime.cert';
my $key  = $opts->{k} || 'smime.key';
my $root = $opts->{r} ? "-certfile $opts->{r}" : '';
my $crypt  = $opts->{C};
my $sign = $opts->{S};
my $smtp = $opts->{x} || '127.0.0.1';

my $recipient = $opts->{t};
$recipient = parse_address($recipient);

my $from = $opts->{f};
$from = parse_address($from) if $from;

my $subject = is_valid_utf8($opts->{s}) ? encode_quoted_utf8($opts->{s}) : $opts->{s};
my $message = '';
my @attachments = ();
if ($opts->{a}){
    for my $f (split /,/, $opts->{a}){
        if (-f $f){
            push @attachments, $f;
        } else {
            die "incorrect file $f";
        }
    }
}

# read stdin / input file            TODO: need to handle empty input
while (defined (my $line = <>)){
    $message .= $line;
}

my $body;

# say "Message: $message";
my $bound = new_boundary();
$body .= new_mm('multipart/mixed', $bound);

if (is_valid_utf8($message)){
    $body .= add_part(mime => 'text/plain; charset=utf-8', content => $message, boundary => $bound);
} else {
    $body .= add_part(mime => 'text/plain', content => $message, boundary => $bound);
}

# process attachments
for my $a (@attachments){
    $body .= attach_file($a, $bound);
}

$body .= last_part($bound);

say "Body - before enc/sign:\n$body" if $LOG_LVL == TRACE;

# process encryption
if ($crypt){
    my $cmd_crypt = "openssl smime -encrypt -aes256 \"${crypt}\" ";
    my ($enc_body, $err) = run_cmd($cmd_crypt, $body);
    die $err if $err;
    $body = $enc_body;
}

say "Body - before sign:\n$body" if $LOG_LVL == TRACE;
# process signing
if ($sign){
    my $from = '';
    $from = "-from \"$from\"" if $from;
    my $cmd_sign = "openssl smime -sign -signer \"$cert\" -inkey \"$key\" $root $from -to \"$recipient\" -subject \"$subject\"";
    say $cmd_sign;
    my ($signed_body, $err) = run_cmd($cmd_sign, $body);
    die $err if $err;
    # chomp $signed_body;
    say "Body: $signed_body";
    $body = $signed_body;
} else {
    # fill missing headers when not signing
    my $date = strftime ("%a, %d %b %Y %T %z (%Z)", localtime time);
    # my $date = 'Mon,  6 Jan 2020 20:34:38 +0100 (CET)'; # a fixed date for test
    $body = "From: ${from}\n${body}" if $from;
    $body = <<BODY
To: ${recipient}
Subject: ${subject}
Date: ${date}
MIME-Version: 1.0
${body}
BODY
}

say "Final Body:\n$body" if $LOG_LVL == TRACE;

# send to MX
send_mail($from, $recipient, $body);

say "Sent.";

exit 0;

#---------------------------------------------------------------------------------------------------

# run a child command, send the given input and return both STDOUT & STDERR of the process
sub run_cmd {
    my ($cmd, $input) = @_;
    my ($infh,$outfh,$errfh,$pid, $out, $err);
    $out = $err = '';
    $errfh = gensym();          # autovivified lexical cannot be used, generate a new symbol instead
    $pid = open3($infh, $outfh, $errfh, $cmd);
    my $sel = new IO::Select;
    $sel->add($outfh,$errfh);
    print $infh $input;
    close $infh;
    while (my @ready = $sel->can_read){
        foreach my $fh (@ready){
            my $line =<$fh>;
            if (not defined $line){
                $sel->remove($fh);
                next;
            }
            if ($fh == $outfh){
                # chomp($line);
                $out .= $line;
            }
            elsif ($fh == $errfh){
                # chomp $line;
                $err .= $line;
            }
            else {
                die "Reading from something else?!!\n";
            }
        }
    }
    close $outfh;
    close $errfh;
    waitpid($pid, 0);
    return $out, $err;
}

# prepare the content of a Base64 encoded data block from a file on disk
sub attach_file {
    my ($file, $boundary) = @_;
    die "Incorrect file $file" unless -f $file;
    my $get_mime = "file --mime-type --brief \"$file\"";
    my $mime = `$get_mime`; # avoid external dependency to package MIME
    chomp $mime;
    
    my $name = basename($file);
    open my $f, '<', $file or die "Cannot read $file: $!";
    binmode $f;
    my $buf;
    my $b64;
    while (read($f, $buf, 3990)){ # 3990 is multiple of 19x3 bytes, the max number of bytes that can be encoded in a line of 76 characters (3 bytes -> 4 chars)
        $b64 .= encode_base64($buf);
    }
    close $f;
    return add_part(mime => "${mime}; name=\"${name}\"", content => $b64, boundary => $boundary, disposition => "attachment; filename=\"$name\"", encoding => 'base64');
}

# Build a new multipart block
sub add_part {
    my %args = @_;
    my $mime = $args{mime};
    my $content = $args{content};
    my $boundary = $args{boundary};
    my $disposition = $args{disposition};
    my $encoding = $args{encoding} ? "\nContent-Transfer-Encoding: " .$args{encoding} : "";
    $disposition = "\nContent-Disposition: ${disposition}" if $disposition;
    $disposition = '' unless $disposition;
    return "\n--${boundary}\nContent-Type: ${mime}${disposition}${encoding}\n\n${content}";
}

# generate a new boundary "unique" ID
sub new_boundary {
    my $d = new Digest::MD5;
    $d->add(time);
    return $d->hexdigest;
}

# return the end boundary for a multipart
sub last_part {
    my ($boundary) = @_;
    return "\n--${boundary}--\n";
}

# return the beginning of a new multipart
sub new_mm {
    my ($type, $boundary) = @_;
    my $r = "Content-Type: ${type};\n\tboundary=\"${boundary}\"\n\n";
    return $r;
}

# send mail helper
sub send_mail {
    my ($from, $to, $message) = @_;
    
    
    my $agent = sprintf "%s v%s", basename($0), $VERSION;
    my $smtp = new Net::SMTP($smtp,
                           Timeout => 180,
                           $LOG_LVL == TRACE ? (Debug => 1) : ()
        ) or die "Cannot connect to SMTP: $@";
    $smtp->mail($from);
    $smtp->to(split /,/, $to);
    $smtp->data();
    $smtp->datasend(<<"MSG");
User-Agent: ${agent}
${message}
MSG
    $smtp->dataend();
    $smtp->quit();
}

sub encode_quoted_utf8 {
    my $str = shift;
    $str = '=?utf-8?Q?' . encode_qp($str, '') . '?=';
    return $str;
}

# sanitize address
sub parse_address {
    my $address = shift;
    my $display_name = '';
    $address =~ s/\([^\)]*\)//g;   # remove comments - or old way to give display name
    if ($address =~ /(.*)?\s?<([^>]+)>/){
        $display_name = $1;
        $address = $2;
    }
    if ($display_name){
        if (is_valid_utf8($display_name)){
            $display_name = encode_quoted_utf8($display_name);
        }
        $display_name = "${display_name} <${address}>";
    }
    return $display_name || $address;
}

# is_valid_utf8 came from: http://people.netscape.com/ftang/utf8/isutf8.pl
sub is_valid_utf8 {
    my $utf8 = pop (@_);
    
    if($utf8 =~ /^(([\0-\x7F])|([\xC0-\xDF][\x80-\xBF])|([\xE0-\xEF][\x80-\xBF][\x80-\xBF])|([\xF0-\xF7][\x80-\xBF][\x80-\xBF][\x80-\xBF])|([\xF8-\xFB][\x80-\xBF][\x80-\xBF][\x80-\xBF][\x80-\xBF])|([\xFC-\xFE][\x80-\xBF][\x80-\xBF][\x80-\xBF][\x80-\xBF][\x80-\xBF]))*$/)
    {
            return ! ($utf8 =~ /([\xC0-\xC1])|([\xE0][\x80-\x9F])|([\xF0][\x80-\x8F])|([\xF8][\x80-\x87])|([\xFC][\x80-\x83])/);
        }
    else {
        return 0;
    }
}

# poor man's hex dumper :)
sub hexdump {
    my $data = shift;
    my $data_len = shift || 16;
    my $hex_len = $data_len * 3;
    my $addr = 0;
    my @out;
    for my $s (unpack("(a${data_len})*", $data)){
        last unless $s;
        my $h = join' ', unpack('(H2)*', $s);
        $s =~ s/[\x00-\x1f]/./g;
        push @out, sprintf("%06x  %-${hex_len}s %s", $addr, $h, $s);
        $addr += length($s);
    }
    return @out;
}

sub usage {
    my $cmd = basename($0);
    say "Usage: ${cmd} [options] <message_or_file>
    -x smtp_server         - default is 127.0.0.1
    -t to                  - mail recipient (multiple coma-separated values accepted
                                             NOT SUPPORTED YET FOR ENCRYPTION)
    -f from                - optional, but strongly encouraged
    -s subject
    -a file1[,file2,fileN] - optional, several filenames separated by coma accepted
    -S                     - sign the mail (optional)
    -c cert                - certificate for signing (optional, default = smime.cert)
    -k key                 - key for signing         (optional, default = smime.key)
    -r root-ca             - optional, to avoid validation problems use the cert authority signer bundle
    -C recipent-cert       - encrypt the mail (optional)
    -d                     - debug = be very verbose

  Send simple mail:
    echo 'Some message' | ${cmd} -to alice [-f bob] -s 'some stuff'
    ${cmd} -to alice [-f bob] -s 'some stuff' message.txt
    Note: 'from' is optional but strongly encouraged to avoid \"From: MAILER-DAEMON\", machine owner or no sender.

  Send w/ attachments:
    ${cmd} -t alice [-f bob] -s 'some stuff' -a file1,file2,fileN message.txt

  Sign a clear message (including possible attachments)
    ${cmd} -t alice [-f bob] -s 'some stuff' -S message.txt # use default smime.cert/smime.key
    ${cmd} -t alice [-f bob] -s 'some stuff' -S -c mycert.pem -k mykey.pem -r myca.pem message.txt 

  Encrypt a message (including possible attachments)
    ${cmd} -t alice [-f bob] -s 'some stuff' -C recipent_public_key.pem message.txt

  You can combine -S and -C to send an encrypted message w/ signature.

  To get your recipient's public cert you can query an AD/LDAP server:
    DST=your.recipient\@mail.com; \
        ${cmd} -t \"\$DST\" -S -r root-ca.pem -C <(ldapsearch -x -h ldapsvr:389 -D 'your_bind_DN' -w 'yourpwd' -b 'your_base_DN' -s sub -o ldif-wrap=no -LLL \"(userPrincipalName=\$DST)\" userCertificate | grep userCertificate | cut -d' ' -f2 | base64 -d | openssl x509 -inform der) -f alice -s 'somer stuff' msg.txt
";

}
