import 'package:asn1lib/asn1lib.dart';

extension ASN1BitStringExtension on ASN1BitString{
 static ASN1BitString fromBitArray(List<bool> bits){
   var firstBit = int.parse('80', radix: 16);
   var unusedBits = 0;
   var stringValue = <int>[];
   bits = bits.sublist(0, bits.lastIndexOf(true) + 1);
   var numBitsLastByte = bits.length % 8;
   unusedBits = 8 - numBitsLastByte;
   var bytesCount = bits.length / 8;
   var bitCount = 0;
   for(var byteIndex = 0; byteIndex < bytesCount; byteIndex++){
     var byteValue = 0;
     var lastBit = 8;
     if(byteIndex > (bytesCount - 1)){
       lastBit = numBitsLastByte;
     }
     for(var bitIndex = 0; bitIndex < lastBit; bitIndex++){
       if(bits[bitCount]){
         byteValue |= firstBit >> bitIndex;
       }
       bitCount++;
     }
     stringValue.add(byteValue);
   }
   return ASN1BitString(stringValue, unusedbits: unusedBits);
 }
}