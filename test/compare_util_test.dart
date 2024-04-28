import 'dart:io';

import 'package:asn1lib/asn1lib.dart';
import 'package:test/test.dart';
import 'package:x509/src/asn1_util.dart';
import 'package:x509/x509.dart';

void main() {
  group('ASN1 compare utility', () {
    test('compare 2 ASN1 objects with differences', () {
      var serverPem = File('test/files/self-signed/server.crt').readAsStringSync();
      var caPem = File('test/files/self-signed/rootCA.crt').readAsStringSync();
      var serverKeyPem = File('test/files/self-signed/server.key').readAsStringSync();
      var caKeyPem = File('test/files/self-signed/rootCA.key').readAsStringSync();
      var csrPem = File('test/files/self-signed/csr.pem').readAsStringSync();
      var serverCert = parsePem(serverPem).single as X509Certificate;
      var caCert = parsePem(caPem).single as X509Certificate;
      var serverKey = parsePem(serverKeyPem).single as PrivateKeyInfo;
      var caKey = parsePem(caKeyPem).single as PrivateKeyInfo;
      var csr = parsePem(csrPem).single as CertificationRequest;

      var extensions = <Extension>[
        BasicConstraintsExtension(),
        KeyUsageExtension.optional(digitalSignature: true, nonRepudiation: true, keyEncipherment: true, dataEncipherment: true),
        // The sample is 'demo.mlopshub.com'
        SubjectAltNameExtension(names: [DNSName('demo1.mlopshub.com')]),
      ];

      var serverCert2 = X509Certificate.selfSigned(caKey.keyPair.privateKey!,
          csr, caCert: caCert, serialNumber: BigInt.parse('302062104447233620017396921218438266574345124003'),
          from: DateTime.utc(2024,1,4,3,16,44), days: 365, extensions: extensions);

      var result = ASN1CompareUtil.compareTree(serverCert.toAsn1(), serverCert2.toAsn1());
      if(result.isDifferent){
        result.printDiff();
      }
      expect(result.isDifferent, true);
    });
  });
}