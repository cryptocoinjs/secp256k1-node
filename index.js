var secpNode = require('bindings')('secp256k1');


exports.sign = function(privKey, msg, cb){
  if(cb){
    secpNode.signAsync(privKey, msg, cb);
  }else{
    return secpNode.sign(privKey, msg);
  }
};

exports.signCompact = function(privKey, msg, cb){
  if(cb){
    secpNode.signCompactAsync(privKey, msg, cb);
  }else{
    var array = secpNode.signCompact(privKey, msg);
    return {
      validNonce: Boolean(array[0]),
      recoveryId: array[1],
      signature: array[2],
      r: array.slice(0, 32),
      s: array.slice(32, 64)
    };
  }
};

exports.verify = function(pubKey, msg, sig, cb){
  if(cb){
    secpNode.verifyAsync(pubKey, msg, sig, cb);
  }else{
    return secpNode.verify(pubKey, msg, sig);
  }
};

exports.createPubKey = function(privKey, compact){
  compact = compact ? compact : 0;
  return secpNode.pubKeyCreate(privKey, compact);
};
