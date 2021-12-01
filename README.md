# smime_send.pl #

A simple command-line Perl email helper that can send multipart messages with attachments and support S/MIME signature and encryption (we are calling openSSL for this).

    Usage: smime_send.pl [options] <message_or_file>
    --smtp|-x smtp_server           - default is 127.0.0.1
    --to|-t to                      - mail recipient(s) - multiple coma-separated values accepted
                                                        - each recipient can be suffixed with encryption cert
                                      e.g.: -t j.doe\@domain.com:jdoe.pem,foo.bar\@baz.brol:foobar.pem
                                      if not provided but you have cc/bcc, will use undisclosed-recipients
    --cc                            - optional, list of carbon-copy recipients
    --bcc                           - optional, list of blind-carbon-copy recipients
    --from|-f from                  - optional (but strongly encouraged), specify the sender
    --replyto                       - optional, address to send responses to instead of the sender
    --subject|-s subject            - what you want to fill as email subject
    --attach|-a file1[,file2,fileN] - optional, attach a file to the message, its MIME-type will be guessed with 'file'
                                      several filenames separated by coma accepted
                                      you can specify a single path or a tuple path:mime[:name] for each attachment
                                      Note: MS Outlook DOES NOT CARE OF MIME TYPE
                                            -> you should specify a name with proper extension
    --mime|-m mime-type             - optional, force mime-type for message encoding (disable utf-8 validation)
    --plain|p                       - optional, force plain-text body and disable mime encoding and attachments
    --sign|-S                       - optional, sign the mail (will need the signing key and cert)
    --cert|-c cert                  - certificate for signing (optional, default = smime.cert)
    --key|-k key                    - key for signing         (optional, default = smime.key)
    --root|-r root-ca               - optional, to avoid validation problems use the cert authority signer bundle
    --cipher|-C recipent-cert       - encrypt the mail with the given cert (optional)
                                      you can use instead the alternative way with the ':certificate' after recipients
    --quiet|-q                      - quiet = do not print progression messages
    --version|-V                    - display the version and quit
    --debug|-d                      - debug = be very verbose

Send simple mail:
--

    echo 'Some message' | smime_send.pl -to alice [-f bob] -s 'some stuff'
    smime_send.pl -to alice [-f bob] -s 'some stuff' message.txt

Note: 'from' is optional but strongly encouraged to avoid "From: MAILER-DAEMON", machine owner or no sender.

Send w/ attachments:
--

    smime_send.pl -t alice [-f bob] -s 'some stuff' -a file1,file2,fileN message.txt


    Note: since v1.2 you can specify the mime-type and/or the name of the attachment if it cannot be determined
          automatically, or if you want to rename it
          ${cmd} -t alice [-f bob] -s 'some stuff' -a path/to/fileFOO::fileBAR,path/to/fileBAR::fileBROL
          ${cmd} -t alice [-f bob] -s 'some stuff' -a <(some command output | gzip -c):application/gzip:data.txt.gz

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

