part of 'x509_base.dart';

/// https://tools.ietf.org/html/rfc2986
class CertificationRequest {
  final CertificationRequestInfo certificationRequestInfo;
  final AlgorithmIdentifier signatureAlgorithm;
  final Uint8List signature;

  CertificationRequest(
      this.certificationRequestInfo, this.signatureAlgorithm, this.signature);

  factory CertificationRequest.generate(CertificationRequestInfo certificationRequestInfo, PrivateKey privateKey) {
    var bytes = certificationRequestInfo.toAsn1().encodedBytes;
    if(privateKey is RsaPrivateKey){
      var signature = privateKey.createSigner(algorithms.signing.rsa.sha256).sign(bytes).data;
      return CertificationRequest(certificationRequestInfo, AlgorithmIdentifier.fromOiReadableName('sha256WithRSAEncryption'), signature);
    }
    throw UnimplementedError('Keys of type ${privateKey.runtimeType} are currently not supported');
  }


  /// CertificationRequest ::= SEQUENCE {
  ///   certificationRequestInfo CertificationRequestInfo,
  ///   signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
  ///   signature          BIT STRING
  /// }
  factory CertificationRequest.fromAsn1(ASN1Sequence sequence) {
    final algorithm = AlgorithmIdentifier.fromAsn1(sequence.elements[1] as ASN1Sequence);
    return CertificationRequest(
        CertificationRequestInfo.fromAsn1(sequence.elements[0] as ASN1Sequence),
        algorithm,
        (sequence.elements[2] as ASN1BitString).contentBytes());
  }

  ASN1Sequence toAsn1(){
    var sequence = ASN1Sequence();
    sequence.add(certificationRequestInfo.toAsn1());
    sequence.add(signatureAlgorithm.toAsn1());
    sequence.add(fromDart(signature));
    return sequence;
  }
}

class CertificationRequestInfo {
  final int? version;
  final Name subject;
  final SubjectPublicKeyInfo subjectPublicKeyInfo;
  final Attributes? attributes;

  CertificationRequestInfo._(
      this.version, this.subject, this.subjectPublicKeyInfo, this.attributes);

  factory CertificationRequestInfo(Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo, {int version = 1, Attributes? attributes}){
    return CertificationRequestInfo._(version, subject, subjectPublicKeyInfo, attributes);
  }

  /// CertificationRequestInfo ::= SEQUENCE {
  ///   version       INTEGER { v1(0) } (v1,...),
  ///   subject       Name,
  ///   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
  ///   attributes    [0] Attributes{{ CRIAttributes }}
  /// }
  factory CertificationRequestInfo.fromAsn1(ASN1Sequence sequence) {
    return CertificationRequestInfo._(
        toDart(sequence.elements[0]).toInt() + 1,
        Name.fromAsn1(sequence.elements[1] as ASN1Sequence),
        SubjectPublicKeyInfo.fromAsn1(sequence.elements[2] as ASN1Sequence),
        Attributes.fromAsn1(sequence.elements[3]));
  }

  ASN1Sequence toAsn1(){
    var sequence = ASN1Sequence();
    sequence.add(fromDart((version ?? 1) - 1));
    sequence.add(subject.toAsn1());
    sequence.add(subjectPublicKeyInfo.toAsn1());
    if(attributes != null) sequence.add(attributes!.toAsn1());
    return sequence;
  }
}

///    Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
///
///    CRIAttributes  ATTRIBUTE  ::= {
///         ... -- add any locally defined attributes here -- }
///
class Attributes{

  final List<Attribute> attributes;

  Attributes(this.attributes);

  ASN1Object toAsn1(){
    // It is not really a set but it is convenient to use set
    var set = ASN1Set(tag: 0xA0);
    for(var attribute in attributes){
      set.add(attribute.toAsn1());
    }
    return set;
  }

  factory Attributes.fromAsn1(ASN1Object element) {
    if(element.tag != 0xA0){
      throw BadAttributesError('The tag from the Attributes ASN1Octet String does not equal 0xA0');
    }
    var parser = ASN1Parser(element.valueBytes());
    var attributes = <Attribute>[];
    while(parser.hasNext()){
      attributes.add(Attribute.fromAsn1(parser.nextObject()));
    }
    return Attributes(attributes);
  }
}

class BadAttributesError extends StateError{
  BadAttributesError(super.message);
}

///    Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
///         type   ATTRIBUTE.&id({IOSet}),
///         values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
///    }
abstract class Attribute {
  final ObjectIdentifier oi;

  Attribute(this.oi);

  ASN1Object toAsn1();

  factory Attribute.fromAsn1(ASN1Object object) {
    if(object is ASN1Sequence){
      var oi = ObjectIdentifier.fromAsn1(object.elements[0] as ASN1ObjectIdentifier);
      if(oi.name == 'extensionRequest'){
        return ExtensionRequestAttribute.fromAsn1(object);
      }
    }
    throw BadAttributesError('It is expected that an Attribute would be an ASN1Sequence');
  }
}

class ExtensionRequestAttribute extends Attribute{
  List<Extension> extensions;

  ExtensionRequestAttribute(this.extensions) : super(ObjectIdentifier.fromOiReadableName('extensionRequest'));

  factory ExtensionRequestAttribute.fromAsn1(ASN1Sequence object) {
    var set = object.elements[1] as ASN1Set;
    var sequence = set.elements.first as ASN1Sequence;
    var extensions = <Extension>[];
    for(var extSeq in sequence.elements){
      if(extSeq is! ASN1Sequence){
        throw BadAttributesError('It was expected that an extension would be a sequence');
      }
      extensions.add(Extension.fromAsn1(extSeq));
    }
    return ExtensionRequestAttribute(extensions);
  }

  @override
  ASN1Sequence toAsn1(){
    var outer = ASN1Sequence();
    outer.add(oi.toAsn1());
    var set = ASN1Set();
    outer.add(set);
    var inner = ASN1Sequence();
    set.add(inner);
    for(var extension in extensions){
      inner.add(extension.toAsn1());
    }

    return outer;
  }
}
