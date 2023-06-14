pragma circom 2.1.5;

include "circom-pairing/circuits/bn254/curve.circom";
include "circom-pairing/circuits/bn254/bn254_func.circom";
include "circom-pairing/circuits/bn254/subgroup_check.circom";
include "circom-pairing/circuits/bigint.circom";
include "circom-pairing/circuits/fp.circom";
include "circom-pairing/circuits/curve.circom";
include "circomlib/circuits/bitify.circom";
include "./keccak256_transcript.circom";


template verifyProof(degreeMaxK,rootOfUnityMin) {
    // BN254 facts
    var n = 43;
    var k = 6;
    var p[50] = get_bn254_prime(n, k);

    // commitments
    signal input a[2][k];
    signal input b[2][k];
    signal input c[2][k];
    signal input z[2][k];
    signal input tLo[2][k];
    signal input tMid[2][k];
    signal input tHi[2][k];
    signal input w[2][k];
    signal input wRotate[2][k];

    // challenges
    signal input aCha[k];
    signal input bCha[k];
    signal input cCha[k];
    signal input s1Cha[k];
    signal input s2Cha[k];
    signal input zCha[k];

    // verifying key (8 points)
    signal input vkQm[2][k];
    signal input vkQl[2][k];
    signal input vkQr[2][k];
    signal input vkQo[2][k];
    signal input vkQc[2][k];
    signal input vkS1[2][k];
    signal input vkS2[2][k];
    signal input vkS3[2][k];
    signal input degree;

    // public input commitment (1 point)
    signal input pubIn[2][k];

    // Check that proof consists of valid G1 and F points.
    component commitG1Checks[9];
    for(var i=0; i<9; i++) {
        commitG1Checks[i] = SubgroupCheckG1(n,k);
    }
    commitG1Checks[0].in <== a;
    commitG1Checks[1].in <== b;
    commitG1Checks[2].in <== c;
    commitG1Checks[3].in <== z;
    commitG1Checks[4].in <== tLo;
    commitG1Checks[5].in <== tMid;
    commitG1Checks[6].in <== tHi;
    commitG1Checks[7].in <== w;
    commitG1Checks[8].in <== wRotate;
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[0].in[i][j] <== a[i][j];
    //     }
    // }
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[1].in[i][j] <== b[i][j];
    //     }
    // }
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[2].in[i][j] <== c[i][j];
    //     }
    // }
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[3].in[i][j] <== z[i][j];
    //     }
    // }
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[4].in[i][j] <== tLo[i][j];
    //     }
    // }
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[5].in[i][j] <== tMid[i][j];
    //     }
    // }
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[6].in[i][j] <== tHi[i][j];
    //     }
    // }
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[7].in[i][j] <== w[i][j];
    //     }
    // }
    // for(var i=0; i<2; i++) {
    //     for(var j=0;j<k;j++) {
    //         commitG1Checks[8].in[i][j] <== wRotate[i][j];
    //     }
    // }

    component challengeFqChecks[6];
    for(var i=0; i<6; i++) {
        challengeFqChecks[i] = BigLessThan(n,k);
    }
    challengeFqChecks[0].a <== aCha;
    for(var i=0; i<k; i++) {
        challengeFqChecks[0].b[i] <== p[i];
    }
    challengeFqChecks[0].out === 1;
    challengeFqChecks[1].a <== bCha;
    for(var i=0; i<k; i++) {
        challengeFqChecks[1].b[i] <== p[i];
    }
    challengeFqChecks[1].out === 1;
    challengeFqChecks[2].a <== cCha;
    for(var i=0; i<k; i++) {
        challengeFqChecks[2].b[i] <== p[i];
    }
    challengeFqChecks[2].out === 1;
    challengeFqChecks[3].a <== s1Cha;
    for(var i=0; i<k; i++) {
        challengeFqChecks[3].b[i] <== p[i];
    }
    challengeFqChecks[3].out === 1;
    challengeFqChecks[4].a <== s2Cha;
    for(var i=0; i<k; i++) {
        challengeFqChecks[4].b[i] <== p[i];
    }
    challengeFqChecks[4].out === 1;
    challengeFqChecks[5].a <== zCha;
    for(var i=0; i<k; i++) {
        challengeFqChecks[5].b[i] <== p[i];
    }
    challengeFqChecks[5].out === 1;

    // Compute the bit representation of degree
    signal degreeBits[degreeMaxK+1] <== Num2Bits(degreeMaxK+1)(degree);

    // Compute the challenge points β, γ, α, z, v, u 
    signal transcriptBeta[computeTranscriptBits(12,0)];
    component pointBits1[12];
    for(var i=0;i<12;i++) {
        pointBits1[i] = Point2Bits();
    }
    pointBits1[0].point <== vkQm;
    pointBits1[1].point <== vkQl;
    pointBits1[2].point <== vkQr;
    pointBits1[3].point <== vkQo;
    pointBits1[4].point <== vkQc;
    pointBits1[5].point <== vkS1;
    pointBits1[6].point <== vkS2;
    pointBits1[7].point <== vkS3;
    pointBits1[8].point <== pubIn;
    pointBits1[9].point <== a;
    pointBits1[10].point <== b;
    pointBits1[11].point <== c;
    for(var i=0;i<12;i++) {
        for(var j=0;j<2*256;j++) {
            transcriptBeta[2*256*i+j] <== pointBits1[i].out[j];
        }
    }
    signal beta[k] <== SqueezeTranscripts(12,0)(transcriptBeta);

    signal transcriptGamma[computeTranscriptBits(0,1)] <== Scalar2Bits()(beta);
    signal gamma[k] <== SqueezeTranscripts(0,1)(transcriptGamma);

    signal transcriptAlpha[computeTranscriptBits(1,0)] <== Point2Bits()(z);
    signal alpha[k] <== SqueezeTranscripts(1,9)(transcriptAlpha);

    signal transcriptZeta[computeTranscriptBits(3,0)];
    component pointBits2[3];
    for(var i=0;i<3;i++) {
        pointBits2[i] = Point2Bits();
    }
    pointBits2[0].point <== tLo;
    pointBits2[1].point <== tMid;
    pointBits2[2].point <== tHi;
     for(var i=0;i<3;i++) {
        for(var j=0;j<2*256;j++) {
            transcriptZeta[2*256*i+j] <== pointBits2[i].out[j];
        }
    }
    signal zeta[k] <== SqueezeTranscripts(3,0)(transcriptZeta);

    signal transcriptV[computeTranscriptBits(0,6)];
    component scalarBits1[6];
    for(var i=0;i<6;i++) {
        scalarBits1[i] = Scalar2Bits();
    }
    scalarBits1[0].scalar <== aCha;
    scalarBits1[1].scalar <== bCha;
    scalarBits1[2].scalar <== cCha;
    scalarBits1[3].scalar <== s1Cha;
    scalarBits1[4].scalar <== s2Cha;
    scalarBits1[5].scalar <== zCha;
     for(var i=0;i<6;i++) {
        for(var j=0;j<256;j++) {
            transcriptV[256*i+j] <== scalarBits1[i].out[j];
        }
    }
    signal v[k] <== SqueezeTranscripts(0,6)(transcriptV);

    signal transcriptU[computeTranscriptBits(2,0)];
    component pointBits3[2];
    for(var i=0;i<2;i++) {
        pointBits3[i] = Point2Bits();
    }
    pointBits3[0].point <== w;
    pointBits3[1].point <== wRotate;
     for(var i=0;i<2;i++) {
        for(var j=0;j<2*256;j++) {
            transcriptU[2*256*i+j] <== pointBits2[i].out[j];
        }
    }
    signal u[k] <== SqueezeTranscripts(2,0)(transcriptU);


    // Compute all powers of z and zeta^n
    signal zetaPowers[degreeMaxK+1][k];
    zetaPowers[0] <== zeta;
    for(var i=0;i<degreeMaxK;i++) {
        zetaPowers[i+1] <== FpMultiply(n,k,p)(zetaPowers[i],zetaPowers[i]);
    }
    signal zetaIP[degreeMaxK+1][k];
    for(var i=0;i<degreeMaxK+1;i++) {
        for(var j=0;j<k;j++) {
            if(i==0) {
                zetaIP[i][k] <== zetaPowers[i][k] * degreeBits[i];
            } else {
                zetaIP[i][k] <== zetaPowers[i][k] * degreeBits[i] + zetaIP[i-1][k];
            }
        }
    }
    signal zetaN[k] <== zetaIP[degreeMaxK];

    // Compute omegas;
    var omegaPowers[degreeMaxK+1][k];
    // omegaPowers[0] = rootOfUnityMin;
    // for(var i=0;i<degreeMaxK;i++) {
    //     omegaPowers[i+1] = omegaPowers[i] * omegaPowers[i];
    // }
    signal omegaIP[degreeMaxK+1][k];
    for(var i=0;i<degreeMaxK+1;i++) {
        for(var j=0;j<k;j++) {
            if(i==0) {
                omegaIP[i][k] <== omegaPowers[i][k] * degreeBits[i];
            } else {
                omegaIP[i][k] <== omegaPowers[i][k] * degreeBits[i] + omegaIP[i-1][k];
            }
        }
    }
    signal omegaK[k] <== omegaIP[degreeMaxK];

    var one[k] = [1,0,0,0,0,0];
    signal zZeta[k] <== FpSubtract(n,k,p)(zetaN,one);
    signal l1Nume[k] <== FpMultiply(n,k,p)(omegaK,zZeta);
    signal l1FracSub[k] <== FpSubtract(n,k,p)(zeta,omegaK);
    signal degreeFq[k] <== [degree,0,0,0,0,0];
    signal l1Frac[k] <== FpMultiply(n,k,p)(degreeFq,zZeta);
    component modInv = BigModInv(n,k);
    modInv.in <== l1Frac;
    for(var i=0;i<k;i++) {
        modInv.p[i] <== p[i];
    }
    signal l1FracInv[k] <== modInv.out;
    signal l1[k] <== FpMultiply(n,k,p)(l1Nume,l1FracInv);

    signal alpha2[k] <== FpMultiply(n,k,p)(alpha,alpha);
    signal r0Term1[k] <== FpNegate(n,k,p)(in<==FpMultiply(n,k,p)(alpha2,l1));




}

component main = verifyProof(1,1);