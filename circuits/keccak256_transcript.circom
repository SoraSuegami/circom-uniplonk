pragma circom 2.0.3;

include "circom-pairing/circuits/bn254/curve.circom";
include "circom-pairing/circuits/bigint.circom";
include "circomlib/circuits/bitify.circom";
include "keccak-circom/circuits/keccak.circom";


function computeTranscriptBits(numPoint,numScalar) {
    return 256 * (2*numPoint + numScalar);
}

template Point2Bits() {
    var n = 43;
    var k = 6;
    var remaining = n * k - 256;
    signal input point[2][k];
    signal output out[256*2];
    component toBits[2][k];
    for(var i=0;i<2;i++){
        for(var j=0;j<k-1;j++) {
            toBits[i][j] = Num2Bits(n);
            toBits[i][j].in <== point[i][j];
            for(var m=0;m<n;m++) {
                out[256*i+n*j+m] <== toBits[i][j].out[m];
            }
        }
        toBits[i][k-1] = Num2Bits(n-remaining);
        toBits[i][k-1].in <== point[i][k-1];
        for(var m=0;m<(n-remaining);m++) {
            out[256*i+n*(k-1)+m] <== toBits[i][k-1].out[m];
        }
    }
}

template Scalar2Bits() {
    var n = 43;
    var k = 6;
    var remaining = n * k - 256;
    signal input scalar[k];
    signal outLittle[256];
    signal output out[256];
    component toBits[k];
    for(var i=0;i<k-1;i++){
        toBits[i] = Num2Bits(n);
        toBits[i].in <== scalar[i];
        for(var m=0;m<n;m++) {
            outLittle[n*i+m] <== toBits[i].out[m];
        }
    }
    toBits[k-1] = Num2Bits(n-remaining);
    toBits[k-1].in <== scalar[k-1];
    for(var m=0;m<(n-remaining);m++) {
        outLittle[n*(k-1)+m] <== toBits[k-1].out[m];
    }
    for(var i=0;i<256;i++) {
        out[i] <== outLittle[256-i];
    }
}


template SqueezeTranscripts(numPoint,numScalar) {
    var n = 43;
    var k = 6;
    var numBits = computeTranscriptBits(numPoint,numScalar);
    signal input in[numBits];
    signal outBits[256] <== Keccak(numBits,256)(in);
    signal output out[k];
    component bit2num[k];
    for(var i=0;i<k-1;i++) {
        bit2num[i] = Bits2Num(n);
        for(var j=0;j<n;j++) {
            bit2num[i].in[j] <== outBits[255-n*i-j];
        }
        out[i] <== bit2num[i].out;
    }
    bit2num[k-1] = Bits2Num(n-2);
    for(var j=0;j<n-2;j++) {
        bit2num[k-1].in[j] <== outBits[255-n*(k-2)-j];
    }
    out[k-1] <== bit2num[k-1].out;
}

