# smime_send.pl #

A simple command-line Perl email helper that can send multipart messages with attachments and support S/MIME signature and encryption (we are calling openSSL for this).

    Usage: smime_send.pl [options] <message_or_file>
    -x smtp_server         - default is 127.0.0.1
    -t to                  - mail recipient (multiple coma-separated values accepted
                                             NOT SUPPORTED YET FOR ENCRYPTION)
    -f from                - optional, but strongly encouraged
    -s subject
    -a file1[,file2,fileN] - optional, several filenames separated by coma accepted
    -m mime-type           - optional, force mime-type for message encoding (disable utf-8 validation)
    -S                     - sign the mail (optional)
    -c cert                - certificate for signing (optional, default = smime.cert)
    -k key                 - key for signing         (optional, default = smime.key)
    -r root-ca             - optional, to avoid validation problems use the cert authority signer bundle
    -C recipent-cert       - encrypt the mail (optional)
    -d                     - debug = be very verbose

Send simple mail:
--

    echo 'Some message' | smime_send.pl -to alice [-f bob] -s 'some stuff'
    smime_send.pl -to alice [-f bob] -s 'some stuff' message.txt

Note: 'from' is optional but strongly encouraged to avoid "From: MAILER-DAEMON", machine owner or no sender.

Send w/ attachments:
--

    smime_send.pl -t alice [-f bob] -s 'some stuff' -a file1,file2,fileN message.txt

Sign a clear message (including possible attachments)
--

    smime_send.pl -t alice [-f bob] -s 'some stuff' -S message.txt # use default smime.cert/smime.key
    smime_send.pl -t alice [-f bob] -s 'some stuff' -S -c mycert.pem -k mykey.pem -r myca.pem message.txt

Encrypt a message (including possible attachments)
--

    smime_send.pl -t alice [-f bob] -s 'some stuff' -C recipent_public_key.pem message.txt

  You can combine -S and -C to send an encrypted message w/ signature.

Getting recipient certificate from a directory
--

To get your recipient's public cert you can query an AD/LDAP server:

    DST=your.recipient@mail.com;
    smime_send.pl -t "$DST" -S -r root-ca.pem -C <(ldapsearch -x -h ldapsvr:389 -D 'your_bind_DN' -w 'yourpwd' -b 'your_base_DN' -s sub -o ldif-wrap=no -LLL "(userPrincipalName=$DST)" userCertificate | grep userCertificate | cut -d' ' -f2 | base64 -d | openssl x509 -inform der) -f alice -s 'somer stuff' msg.txt

