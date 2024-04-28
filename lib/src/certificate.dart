part of 'x509_base.dart';

const beginCert = '-----BEGIN CERTIFICATE-----';
const endCert = '-----END CERTIFICATE-----';

/// A Certificate.
abstract class Certificate {

  /// The public key from this certificate.
  PublicKey get publicKey;
}

/// A X.509 Certificate
class X509Certificate implements Certificate {
  /// The to-be-signed certificate
  final TbsCertificate tbsCertificate;

  ///
  final AlgorithmIdentifier signatureAlgorithm;
  final List<int>? signatureValue;

  @override
  PublicKey get publicKey =>
      tbsCertificate.subjectPublicKeyInfo!.subjectPublicKey;

  const X509Certificate(
      this.tbsCertificate, this.signatureAlgorithm, this.signatureValue);

  factory X509Certificate.generateCA({BigInt? serialNumber, String signatureType = 'sha256WithRSAEncryption',
    required Name name,
    int days = 30, required KeyPair keyPair, DateTime? from}){
    serialNumber ??= BigInt.from(1);
    if(keyPair.publicKey == null || keyPair.privateKey == null){
      throw ArgumentError('The keyPair must have a valid public and private key that is not null', 'keyPair');
    }
    var now = from ?? DateTime.now();
    var validity = Validity(notBefore: now, notAfter: now.add(Duration(days: days)));
    var subjectPublicKeyInfo = SubjectPublicKeyInfo.fromPublicKey(keyPair.publicKey!);
    var extensions = [
      Extension(extnId: ObjectIdentifier.fromOiReadableName('subjectKeyIdentifier'),
          extnValue: SubjectKeyIdentifier.fromPublicKeyBytes(subjectPublicKeyInfo.publicKeyBytes)),
      Extension(extnId: ObjectIdentifier.fromOiReadableName('authorityKeyIdentifier'),
          extnValue: AuthorityKeyIdentifier.fromPublicKeyBytes(subjectPublicKeyInfo.publicKeyBytes)),
      Extension(extnId: ObjectIdentifier.fromOiReadableName('basicConstraints'),
          extnValue: BasicConstraints(cA: true),
          isCritical: true
      ),
      // Extension(extnId: ObjectIdentifier.fromOiReadableName('keyUsage'),
      //     extnValue: KeyUsage.optional(keyCertSign: true),
      //     isCritical: true)
    ];
    var tbsCertificate = TbsCertificate(
        version: 3,
        serialNumber: serialNumber,
        signature: AlgorithmIdentifier.fromOiReadableName(signatureType),
        issuer: name,
        validity: validity,
        subject: name,
        subjectPublicKeyInfo: SubjectPublicKeyInfo.fromPublicKey(keyPair.publicKey!),
        extensions: extensions);

    var signer = keyPair.privateKey!.createSigner(algorithms.signing.rsa.sha256);
    var data = tbsCertificate.toAsn1();
    var signature = signer.sign(data.encodedBytes);

    var cert = X509Certificate(tbsCertificate,
        AlgorithmIdentifier.fromOiReadableName(signatureType),
        signature.data);
    return cert;
  }

  factory X509Certificate.selfSigned(PrivateKey privateKey, CertificationRequest certificationRequest, {int days = 30,
    BigInt? serialNumber, Name? issuer, X509Certificate? caCert, DateTime? from, List<Extension>? extensions}){
    var now = from ?? DateTime.now();
    var validity = Validity(notBefore: now, notAfter: now.add(Duration(days: days)));
    var extensionsMap = Map.fromEntries(extensions?.map((e) => MapEntry(e.extnId, e)).toList() ?? <MapEntry<ObjectIdentifier,Extension>>[]);
    serialNumber ??= BigInt.from(1);

    for(var attribute in (certificationRequest.certificationRequestInfo.attributes?.attributes ?? [])){
      if(attribute is ExtensionRequestAttribute){
        for (var element in attribute.extensions) {
          if(!extensionsMap.containsKey(element.extnId)){
            extensionsMap[element.extnId] = element;
          }
        }
      }
    }

    caCert?.tbsCertificate.extensions?.forEach((element) {
      var value = element.extnValue;
      if(value is SubjectKeyIdentifier){
        var newExtension = Extension(extnId: ObjectIdentifier.fromOiReadableName('authorityKeyIdentifier'),
            extnValue: AuthorityKeyIdentifier.fromSubjectKeyIdentifier(value));
        extensionsMap[newExtension.extnId] = newExtension;
      }
    });

    var ski = Extension(extnId: ObjectIdentifier.fromOiReadableName('subjectKeyIdentifier'),
      extnValue: SubjectKeyIdentifier.fromPublicKeyBytes(certificationRequest.certificationRequestInfo.subjectPublicKeyInfo.publicKeyBytes));

    extensionsMap[ski.extnId] = ski;

    var extensionsList = extensionsMap.values.toList();
    extensionsList.sort((a, b) => a.extnId.name.compareTo(b.extnId.name));

    var issuerToUse = issuer;
    issuerToUse ??= caCert?.tbsCertificate.subject;
    issuerToUse ??= certificationRequest.certificationRequestInfo.subject;

    var tbsCertificate = TbsCertificate(
        version: 3,
        serialNumber: serialNumber,
        signature: AlgorithmIdentifier.fromOiReadableName('sha256WithRSAEncryption'),
        issuer: issuerToUse,
        validity: validity,
        subject: certificationRequest.certificationRequestInfo.subject,
        subjectPublicKeyInfo: certificationRequest.certificationRequestInfo.subjectPublicKeyInfo,
        extensions: extensionsList);

    var signer = privateKey.createSigner(algorithms.signing.rsa.sha256);
    var data = tbsCertificate.toAsn1();
    var signature = signer.sign(data.encodedBytes);

    var cert = X509Certificate(tbsCertificate,
        AlgorithmIdentifier.fromOiReadableName('sha256WithRSAEncryption'),
        signature.data);
    return cert;

  }

  /// Creates a certificate from an [ASN1Sequence].
  ///
  /// The ASN.1 definition is:
  ///
  ///   Certificate  ::=  SEQUENCE  {
  ///     tbsCertificate       TBSCertificate,
  ///     signatureAlgorithm   AlgorithmIdentifier,
  ///     signatureValue       BIT STRING  }
  factory X509Certificate.fromAsn1(ASN1Sequence sequence) {
    final algorithm =
        AlgorithmIdentifier.fromAsn1(sequence.elements[1] as ASN1Sequence);
    return X509Certificate(
        TbsCertificate.fromAsn1(sequence.elements[0] as ASN1Sequence),
        algorithm,
        toDart(sequence.elements[2]));
  }

  ASN1Sequence toAsn1() {
    return ASN1Sequence()
      ..add(tbsCertificate.toAsn1())
      ..add(signatureAlgorithm.toAsn1())
      ..add(fromDart(signatureValue));
  }

  String toPem(){
    var asn1 = toAsn1();
    var bytes = asn1.encodedBytes;
    var stringValue = base64.encode(bytes);
    var chunks = StringUtils.chunk(stringValue, 64);
    var pem = '$beginCert\n${chunks.join('\n')}\n$endCert';
    return pem;
  }

  @override
  String toString([String prefix = '']) {
    var buffer = StringBuffer();
    buffer.writeln('Certificate: ');
    buffer.writeln('\tData:');
    buffer.writeln(tbsCertificate.toString('\t\t'));
    buffer.writeln('\tSignature Algorithm: $signatureAlgorithm');
    buffer.writeln(toHexString(toBigInt(signatureValue!), '$prefix\t\t', 18));
    return buffer.toString();
  }
}

/// An unsigned (To-Be-Signed) certificate.
class TbsCertificate {
  /// The version number of the certificate.
  final int? version;

  /// The serial number of the certificate.
  final BigInt? serialNumber;

  /// The signature of the certificate.
  final AlgorithmIdentifier? signature;

  /// The issuer of the certificate.
  final Name? issuer;

  /// The time interval for which this certificate is valid.
  final Validity? validity;

  /// The subject of the certificate.
  final Name? subject;

  final SubjectPublicKeyInfo? subjectPublicKeyInfo;

  /// The issuer unique id.
  final List<int>? issuerUniqueID;

  /// The subject unique id.
  final List<int>? subjectUniqueID;

  /// List of extensions.
  final List<Extension>? extensions;

  const TbsCertificate(
      {this.version,
      this.serialNumber,
      this.signature,
      this.issuer,
      this.validity,
      this.subject,
      this.subjectPublicKeyInfo,
      this.issuerUniqueID,
      this.subjectUniqueID,
      this.extensions});

  /// Creates a to-be-signed certificate from an [ASN1Sequence].
  ///
  /// The ASN.1 definition is:
  ///
  ///   TBSCertificate  ::=  SEQUENCE  {
  ///     version         [0]  EXPLICIT Version DEFAULT v1,
  ///     serialNumber         CertificateSerialNumber,
  ///     signature            AlgorithmIdentifier,
  ///     issuer               Name,
  ///     validity             Validity,
  ///     subject              Name,
  ///     subjectPublicKeyInfo SubjectPublicKeyInfo,
  ///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
  ///                          -- If present, version MUST be v2 or v3
  ///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
  ///                          -- If present, version MUST be v2 or v3
  ///     extensions      [3]  EXPLICIT Extensions OPTIONAL
  ///                          -- If present, version MUST be v3 }
  ///
  ///   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
  ///
  ///   CertificateSerialNumber  ::=  INTEGER
  ///
  ///   UniqueIdentifier  ::=  BIT STRING
  ///
  ///   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
  ///
  factory TbsCertificate.fromAsn1(ASN1Sequence sequence) {
    var elements = sequence.elements;
    var version = 1;
    if (elements.first.tag == 0xa0) {
      var e =
          ASN1Parser(elements.first.valueBytes()).nextObject() as ASN1Integer;
      version = e.valueAsBigInteger.toInt() + 1;
      elements = elements.skip(1).toList();
    }
    var optionals = elements.skip(6);
    Uint8List? iUid, sUid;
    List<Extension>? ex;
    for (var o in optionals) {
      if (o.tag >> 6 == 2) {
        // context
        switch (o.tag & 0x1f) {
          case 1:
            iUid = o.contentBytes();
            break;
          case 2:
            sUid = o.contentBytes();
            break;
          case 3:
            ex = (ASN1Parser(o.contentBytes()).nextObject() as ASN1Sequence)
                .elements
                .map((v) => Extension.fromAsn1(v as ASN1Sequence))
                .toList();
        }
      }
    }

    return TbsCertificate(
        version: version,
        serialNumber: (elements[0] as ASN1Integer).valueAsBigInteger,
        signature: AlgorithmIdentifier.fromAsn1(elements[1] as ASN1Sequence),
        issuer: Name.fromAsn1(elements[2] as ASN1Sequence),
        validity: Validity.fromAsn1(elements[3] as ASN1Sequence),
        subject: Name.fromAsn1(elements[4] as ASN1Sequence),
        subjectPublicKeyInfo:
            SubjectPublicKeyInfo.fromAsn1(elements[5] as ASN1Sequence),
        issuerUniqueID: iUid,
        subjectUniqueID: sUid,
        extensions: ex);
  }

  ASN1Sequence toAsn1() {
    var seq = ASN1Sequence();

    if (version != 1) {
      var v = ASN1Integer(BigInt.from(version! - 1));
      var o = ASN1Object.preEncoded(0xa0, v.encodedBytes);
      var b = o.encodedBytes
        ..setRange(o.encodedBytes.length - v.encodedBytes.length,
            o.encodedBytes.length, v.encodedBytes);
      o = ASN1Object.fromBytes(b);
      seq.add(o);
    }
    seq
      ..add(fromDart(serialNumber))
      ..add(signature!.toAsn1())
      ..add(issuer!.toAsn1())
      ..add(validity!.toAsn1())
      ..add(subject!.toAsn1())
      ..add(subjectPublicKeyInfo!.toAsn1());
    if (version! > 1) {
      if(extensions?.isNotEmpty ?? false){
        var extensionsSequence = ASN1Sequence();
        for(var extension in extensions!){
          extensionsSequence.add(extension.toAsn1());
        }
        var bytes = extensionsSequence.encodedBytes;
        seq.add(ASN1Object.preEncoded(0xA3, bytes));
      }
      if (issuerUniqueID != null) {
        // TODO
        // var iuid = ASN1BitString.fromBytes(issuerUniqueID);
        //ASN1Object.preEncoded(tag, valBytes)
      }
    }
    return seq;
  }

  @override
  String toString([String prefix = '']) {
    var buffer = StringBuffer();
    buffer.writeln('${prefix}Version: $version');
    buffer.writeln('${prefix}Serial Number: $serialNumber');
    buffer.writeln('${prefix}Signature Algorithm: $signature');
    buffer.writeln('${prefix}Issuer: $issuer');
    buffer.writeln('${prefix}Validity:');
    buffer.writeln(validity?.toString('$prefix\t') ?? '');
    buffer.writeln('${prefix}Subject: $subject');
    buffer.writeln('${prefix}Subject Public Key Info:');
    buffer.writeln(subjectPublicKeyInfo?.toString('$prefix\t') ?? '');
    if (extensions != null && extensions!.isNotEmpty) {
      buffer.writeln('${prefix}X509v3 extensions:');
      for (var e in extensions!) {
        buffer.writeln(e.toString('$prefix\t'));
      }
    }
    return buffer.toString();
  }
}
