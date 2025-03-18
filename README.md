# Yet Another Cert Generator

## Why

Its not as of I haven't made plenty of self signed certs using other tools
Or creates signing certs
Or even created an internal CA
However, that was mostly done using tools like openssl

The goal of this project is not to use openssl and also to have the flexability to create the type of cert I want.
Currently I require private keys in PKCS#8 (done)
Add the major sticking point right now is if I want the public keys in PKCS#7 or another pem format
When something describes it input requirements as x.509 pem formated certificate chain it a little hard to tell

At any rate I can fairly easily create a PKCS#7 stream of bytes using

```
// Oracle Security Developer Tools
// maven.oracle.com may have a newer version but requires auth
// com.oracle.jdbc:osdt_core
implementation "com.oracle.ojdbc:osdt_cert:19.3.0.0"
implementation group: 'com.oracle.ojdbc', name: 'osdt_core', version: '19.3.0.0'

import oracle.security.crypto.asn1.*
import oracle.security.crypto.cert.*;

byte[] certAsDER = certificate.getEncoded();
oracle.security.crypto.cert.X509 x509OracleObject =
  new oracle.security.crypto.cert.X509(certAsDER);
oracle.security.crypto.cert.PKCS7 pkcs7OracleObject =
  new oracle.security.crypto.cert.PKCS7(x509OracleObject);
// ASN1 DER
byte[] pkcs7DER = pkcs7OracleObject.getEncoded();
```

However it seems rather strange that I need to go to all of that work for a pem certificate chain. What I really want to do is find out which format the software libraries I using need.
