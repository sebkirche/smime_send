#!/usr/bin/env perl

# smime_send.pl - simple helper that can send multipart emails w/ attachments,
#                 sign & encrypt messages 

use strict;
use warnings;
use feature 'say';
use utf8;
use Digest::MD5;
use File::Basename;
use Getopt::Long qw( :config no_ignore_case bundling) ;
use IPC::Open3;
use IO::Select;
use Net::SMTP;
use MIME::Base64 qw( encode_base64 decode_base64);
use MIME::QuotedPrint;
use POSIX;
use Symbol;                     # for gensym

my $VERSION = '1.3';

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
GetOptions($opts,
           "debug|d",
           "to|t=s",
           "cc=s",
           "bcc=s",
           "from|f=s",
           "subject|s=s",
           "attach|a=s",
           "cert|c=s",
           "key|k=s",
           "root|r=s",
           "mime|m=s",
           "smtp|x=s",
           "sign|S",
           "cipher|C=s",
           "help|?|h"
    ) or usage_and_quit(1);

if ($opts->{help}){
    usage_and_quit(0);
}

$LOG_LVL = TRACE if $opts->{debug};
die "-c needs a valid certificate" if ($opts->{cert} && ! -f $opts->{cert});
die "-k needs a valid key" if ($opts->{key} && ! -f $opts->{key});
die "-r needs a valid certificate" if ($opts->{root} && ! -f $opts->{root});
# die "-C needs a valid certificate" unless $opts->{C};
die "Missing parameter: -t <recipient>" unless $opts->{to} || $opts->{bcc};
# die "Missing parameter: -f <from> when signing" if $opts->{S} && !$opts->{f};
die "Missing parameter: -s <subject>" unless $opts->{subject};

my $cert = $opts->{cert} || 'smime.cert';
my $key  = $opts->{key} || 'smime.key';
my $root = $opts->{root} ? "-certfile $opts->{root}" : '';
my $crypt  = $opts->{cipher};
my $sign = $opts->{sign};
my $smtp = $opts->{smtp} || '127.0.0.1';
my $mime_type = $opts->{mime};

my $from = $opts->{from} || $ENV{USER};
$from = parse_address($from) if $from;

my $recipients;
if ($opts->{to}){
    $recipients = join ',', map { parse_address($_) } split(/,/, $opts->{to});
} else {
    $recipients = 'undisclosed-recipients:;';
}

my $cc;
if ($opts->{cc}){
    $cc = join ',', map { parse_address($_) } split(/,/, $opts->{cc});
}
    
my $bcc;
if ($opts->{bcc}){
    $bcc = join ',', map { parse_address($_) } split(/,/, $opts->{bcc});
}
    
my $subject = is_valid_utf8($opts->{subject}) ? encode_quoted_utf8($opts->{subject}) : $opts->{subject};
my $message = '';
my $date = strftime ("%a, %d %b %Y %T %z (%Z)", localtime time);
my $agent = sprintf "%s v%s", basename($0), $VERSION;

my @attachments = ();
if ($opts->{attach}){
    for my $a (split /,/, $opts->{attach}){
        my ($p, $t, $n) = split /:/, $a;
        if (-r $p || -p $p){
            push @attachments, {path => $p, type => $t, name => $n};
        } else {
            die "Incorrect / non accessible file $p";
        }
    }
}

# read stdin / input file            TODO: need to handle empty input
while (defined (my $line = <>)){
    $message .= $line;
}

my $body;

# say "Message: $message";
my $bound = new_boundary_id();
$body .= new_mm('multipart/mixed', $bound);

if ($mime_type){
    $body .= add_part(mime => $mime_type, content => $message, boundary => $bound);
} elsif (is_valid_utf8($message)){
    $body .= add_part(mime => 'text/plain; charset=utf-8', content => $message, boundary => $bound);
} else {
    $body .= add_part(mime => 'text/plain', content => $message, boundary => $bound);
}

# process attachments
for my $a (@attachments){
    $body .= attach_file($a, $bound);
}

$body .= last_part($bound);

say boxquote($body, "Body - before enc/sign") if $LOG_LVL == TRACE;

my @heads;

# process encryption
if ($crypt){
    my $cmd_crypt = "openssl smime -encrypt -aes256 \"${crypt}\" ";
    say "Encrypting with command: $cmd_crypt";
    my ($enc_body, $err) = run_cmd($cmd_crypt, $body);
    die $err if $err;
    $body = $enc_body;
}

say boxquote($body, "Body - before sign") if $LOG_LVL == TRACE;
# process signing
if ($sign){
    my ($s_from, $s_to, $s_subject) = ('', '', '');
    $s_from = "-from \"$from\"" if $from;
    $s_to = "-to \"$recipients\"" if $recipients;
    $s_subject = "-subject \"$subject\"" if $subject;
    my $cmd_sign = "openssl smime -sign -signer \"$cert\" -inkey \"$key\" $root $s_from $s_to $s_subject";
    say "Signing with command: $cmd_sign";
    my ($signed_body, $err) = run_cmd($cmd_sign, $body);
    die $err if $err;
    # chomp $signed_body;
    say boxquote($signed_body, "signed body") if $LOG_LVL == TRACE;
    $body = $signed_body;
} else {
    # fill missing headers when not signing
    # my $date = 'Mon,  6 Jan 2020 20:34:38 +0100 (CET)'; # a fixed date for test
}

push @heads, "From: ${from}" unless $sign;
push @heads, "To: ${recipients}" if $recipients && ! $sign;
push @heads, "Cc: ${cc}" if $cc;
push @heads, "Subject: $opts->{subject}" if $opts->{subject} && ! $sign;
push @heads, "Date: ${date}";
push @heads, "MIME-Version: 1.0";
push @heads, "User-Agent: ${agent}";
my $heads_str = join "\n", @heads;
$body = $heads_str . "\n" . $body;

say boxquote($body, "Final Body") if $LOG_LVL == TRACE;

# send to MX
send_mail({
    from    => $from,
    to      => $recipients,
    cc      => $cc,
    bcc     => $bcc,
    message => $body
          });

say "Sent.";

exit 0;

#---------------------------------------------------------------------------------------------------

# run a child command, send the given input and return both STDOUT & STDERR of the process
sub run_cmd {
    my ($cmd, $input) = @_;
    my ($infh,$outfh,$errfh,$pid, $out, $err);

    my $send_offset = 0;
    my $data_len = length($input);
    my $write_block_len = 1024 * 100;
    my $read_block_len = 1024 * 100;
    
    $out = $err = '';
    $errfh = gensym();          # autovivified lexical cannot be used, generate a new symbol instead
    $pid = open3($infh, $outfh, $errfh, $cmd);
    my $r_sel = new IO::Select($outfh,$errfh);
    my $w_sel = new IO::Select($infh);
    
    # read/write loop
    do {
        # write part
      WRITE:
        # for(;;){
            my @ready_w = $w_sel->can_write(0.05);
            
            # last WRITE if not @ready_w;   # pipe is full
            
            die if @ready_w !=1;
            die if $ready_w[0] != $infh;
            
            my $wrote_bytes = syswrite($infh, $input, $write_block_len, $send_offset);
            if (not defined $wrote_bytes){
                die "unable to write to the pipe\n";
            }
            if (not $wrote_bytes){
                die "unable to write to the pipe: 0 byte written??";
            }
            $infh->flush();
            print 'W';
            $send_offset += $wrote_bytes;
            close $infh if $send_offset == $data_len;
      # }

        # read part
      READ:
            while (my @ready = $r_sel->can_read(0.08)){
                last READ if @ready < 1;
                foreach my $fh (@ready){
                    my $read_bytes = $fh->sysread(my $buf, $read_block_len);
                    print'R';
                    if($read_bytes){
                        if ($fh == $outfh){
                            $out .= $buf;
                        } elsif ($fh == $errfh){
                            $err .= $buf;
                        } else {
                            die "Reading from something else?!!\n";
                        }
                    } else {
                        if ($fh->eof){
                            $r_sel->remove($fh);
                        }
                        next READ;
                    }
                    
                }
      }
    } while ($send_offset < $data_len);
    close $outfh;
    close $errfh;
    waitpid($pid, 0);
    return $out, $err;
}

# prepare the content of a Base64 encoded data block from a file on disk
sub attach_file {
    my ($attach, $boundary) = @_;
    my $file = $attach->{path};
    my $mime = $attach->{type};
    my $name = $attach->{name};
    
    die "Incorrect file $file" unless -f $file || -p $file;
    my $get_mime = "file --mime-type --brief \"$file\"";
    $mime = `$get_mime` unless $mime; # avoid external dependency to package MIME
    chomp $mime;
    
    $name = basename($file) unless $name;
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
sub new_boundary_id {
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
    my $args = shift;
    my @heads;

    my $mx = new Net::SMTP($smtp,
                           Timeout => 180,
                           $LOG_LVL == TRACE ? (Debug => 1) : ()
        );
    unless ($mx){
        say "Cannot use the default SMTP at $smtp: $@\nPlease look at the -x <smtp_server> parameter.";
        exit 1;
    }
    
    $mx->mail($args->{from});
    $mx->to(split /,/, $args->{to}) if $args->{to};
    $mx->cc(split /,/, $args->{cc}) if $args->{cc};
    $mx->bcc(split /,/, $args->{bcc}) if $args->{bcc};
    $mx->data();
    $mx->datasend($args->{message});
    $mx->dataend();
    $mx->quit();
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

# improved quoting of text
sub boxquote {
    my ($txt, $label) = @_;
    my $res = ',----';
    my $sep = $\;
    $res .= "[ $label ]\n" if $label;
    $res .= join "\n", map { "| $_" } split $/, $txt;
    $res .= "\n`----";
    return $res;
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
                             you can specify a single path or a tuple path:mime:name for each attachment
    -m mime-type           - optional, force mime-type for message encoding (disable utf-8 validation)
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

    Note: since v1.2 you can specify the mime-type and/or the name of the attachment if it cannot be determined
          automatically, or if you want to rename it
          ${cmd} -t alice [-f bob] -s 'some stuff' -a path/to/fileFOO::fileBAR,path/to/fileBAR::fileBROL
          ${cmd} -t alice [-f bob] -s 'some stuff' -a <(some command output | gzip -c):application/gzip:data.txt.gz

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

sub usage_and_quit {
    my $code = shift;
    
    usage();
    exit $code;
}
