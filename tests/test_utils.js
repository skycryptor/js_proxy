function assert(condition, msg){
    if (!condition){
        throw new Error("FAILED: " + msg);
    }
}

function bytes_equal(data1, data2){
    if (data1.length != data2.length){
        return false;
    }
    for(var i = 0; i < data1.length; i++){
        if (data1[i] != data2[i]){
            return false;
        } 
    }
    return true;
}
