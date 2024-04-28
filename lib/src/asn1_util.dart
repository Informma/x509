import 'dart:io';

import 'package:asn1lib/asn1lib.dart';
import 'package:basic_utils/basic_utils.dart';
import 'package:collection/collection.dart';
import 'package:x509/x509.dart';

/// This is a utility class for comparing 2 ASN.1 Objects
/// This is useful for finding the difference between 2 objects
class ASN1CompareUtil{
  static ASN1CompareResult compareTreeBranch(List<ASN1Object> branch1, List<ASN1Object> branch2){
    var object1 = branch1.last;
    var object2 = branch2.last;
    if(object1.runtimeType != object2.runtimeType){
      return ASN1CompareResult.different(branch1, branch2);
    }
    if(object1 is ASN1Sequence){
      object2 = object2 as ASN1Sequence;
      if(object1.elements.length != object2.elements.length){
        return ASN1CompareResult.different(branch1, branch2);
      }
      for(var i = 0; i < object1.elements.length; i++){
        var result = compareTreeBranch(
            [...branch1,object1.elements[i]],
            [...branch2,object2.elements[i]]
        );
        if(result.isDifferent){
          return result;
        }
      }
    }else if(object1 is ASN1Set){
      object2 = object2 as ASN1Set;
      if(object1.elements.length != object2.elements.length){
        return ASN1CompareResult.different(branch1, branch2);
      }
      // TODO: This is probably incorrect as a set is not ordered. Will need to look at
      // the specification to see what are the rules for a unique element in ASN.1 Set
      var object1List = object1.elements.toList();
      var object2List = object2.elements.toList();
      for(var i = 0; i < object1List.length; i++){
        var result = compareTreeBranch(
            [...branch1,object1List[i]],
            [...branch2,object2List[i]]
        );
        if(result.isDifferent){
          return result;
        }
      }
    }else{
      var bytes1 = object1.encodedBytes;
      var bytes2 = object2.encodedBytes;
      var equal = ListEquality().equals(bytes1, bytes2);
      if(!equal){
        // See if the content is a ASN1 Object.
        try{
          var object1List = ASN1Parser(object1.contentBytes()).toList();
          var object2List = ASN1Parser(object2.contentBytes()).toList();
          if(object1List.length != object2List.length){
            return ASN1CompareResult.different(branch1, branch2);
          }
          for(var i = 0; i < object1List.length; i++){
            var result = compareTreeBranch(
                [...branch1,object1List[i]],
                [...branch2,object2List[i]]
            );
            if(result.isDifferent){
              return result;
            }
          }
        }catch(_){
          return ASN1CompareResult.different(branch1, branch2);
        }
      }
    }
    return ASN1CompareResult.same();
  }

  static ASN1CompareResult compareTree(ASN1Object object1, ASN1Object object2){
    return compareTreeBranch([object1], [object2]);
  }

  static String listToBinary(List<int> list) {
    var b = StringBuffer('[');
    var doComma = false;
    for (var v in list) {
      doComma ? b.write(', ') : doComma = true;
      b.write(v.toRadixString(2).padLeft(8,'0'));
    }
    b.write(']');
    return b.toString();
  }
}

class ASN1CompareResult{
  final bool same;
  final List<ASN1Object> branch1;
  final List<ASN1Object> branch2;

  ASN1CompareResult.same() : same = true, branch1 = [], branch2 = [];
  ASN1CompareResult.different(this.branch1, this.branch2): same = false;

  bool get isDifferent => !same;

  void printDiff(){
    if(same){
      print('No difference');
    }
    _printDiffLevel(0);
  }

  void _printDiffLevel(int level){
    if(level == branch1.length - 1){
      stdout.write(' | '.repeat(level));
      stdout.write('${branch1[level].tag} ${branch1[level].runtimeType} ${branch1[level]}\n');
      stdout.write('Bytes from object 1\n');
      stdout.write('${ASN1Util.listToString(branch1[level].encodedBytes)}\n');
      stdout.write('${branch1[level].encodedBytes}\n');
      stdout.write('${ASN1CompareUtil.listToBinary(branch1[level].encodedBytes)}\n');
      stdout.write('${String.fromCharCodes(branch1[level].valueBytes())}\n');
      stdout.write('Bytes from object 2\n');
      stdout.write('${ASN1Util.listToString(branch2[level].encodedBytes)}\n');
      stdout.write('${branch2[level].encodedBytes}\n');
      stdout.write('${ASN1CompareUtil.listToBinary(branch2[level].encodedBytes)}\n');
      stdout.write('${String.fromCharCodes(branch2[level].valueBytes())}\n');
    }else{
      var currentObject = branch1[level];
      stdout.write(' | '.repeat(level));
      if(branch1[level] is ASN1Sequence){
        stdout.write('${branch1[level].tag} ${branch1[level].runtimeType}\n');
        var objectList = (branch1[level] as ASN1Sequence).elements;
        for(var i = 0; i < objectList.length; i++){
          if(objectList[i] == branch1[level + 1]){
            _printDiffLevel(level + 1);
          }else{
            stdout.write(' | '.repeat(level + 1));
            stdout.write('${_objectToString(objectList[i])}\n');
          }
        }
      }else{
        stdout.write('${_objectToString(currentObject)}\n');
        _printDiffLevel(level + 1);
      }
    }
  }

  String _objectToString(ASN1Object object){
    var leader = '${object.tag} ${object.runtimeType}';
    String stringValue;
    if(object is ASN1ObjectIdentifier){
      var oidEntry = OIDDatabase.getEntryByIdentifierString(object.identifier);
      stringValue = '$leader ${object.identifier} ${oidEntry.fullName}';
    }else if(object is ASN1Sequence){
      stringValue = leader;
    }else if(object is ASN1Integer){
      stringValue = '$leader ${object.valueAsBigInteger.toString()}';
    }
    else{
      if(!object.isEncoded){
        object.encodedBytes;
      }
      stringValue = '$leader ${object.toString()}';
    }
    return stringValue.truncate(100);
  }
}

extension on ASN1Parser{
  List<ASN1Object> toList(){
    var objectList = <ASN1Object>[];
    while(hasNext()){
      objectList.add(nextObject());
    }
    return objectList;
  }
}

extension on String{
  String repeat(int count){
    var outputString = '';
    while(count-- > 0){
      outputString += this;
    }
    return outputString;
  }
  
  String truncate(int length, {String symbol = '...'}){
    if(this.length > length){
      return substring(0,length) + symbol;
    }else{
      return this;
    }
  }
}