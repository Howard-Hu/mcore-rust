//use mcore::bls12381::bls::{self, BLS_FAIL, BLS_OK};
//use mcore::bls12381::big;

use crate::bls12381::bls::{self, BLS_FAIL, BLS_OK};
use crate::bls12381::big;

use rand;
use rand::RngCore;


pub fn test_aggregate_and_verify() {
    let (_sk1,pk1,m1,sig1) = generator_sk_pk_m_sig();
    let (_sk2,pk2,m2,sig2) = generator_sk_pk_m_sig();
    let (_sk3,pk3,_m3,_sig3) = generator_sk_pk_m_sig();
    const N:usize = 2;

    let mut sig:[u8;big::MODBYTES+1]=[0;big::MODBYTES+1];
    // 聚合签名
    assert_eq!(bls::signature_aggregate::<N>(sig.as_mut_slice(),[sig1.as_slice(),sig2.as_slice()]),BLS_OK);

    // 聚合验证
    assert_eq!(bls::core_aggregate_verify::<N>([pk1.as_slice(),pk2.as_slice()],[m1.as_slice(),m2.as_slice()],sig.as_mut_slice()),BLS_OK);
    assert_eq!(bls::core_aggregate_verify::<N>([pk1.as_slice(),pk3.as_slice()],[m1.as_slice(),m2.as_slice()],sig.as_mut_slice()),BLS_FAIL);

}

fn generator_sk_pk_m_sig()->([u8;48],[u8;2*big::MODBYTES+1],[u8;32],[u8;big::MODBYTES+1]){
    //println!("Hello, world!");
    let mut rng = rand::thread_rng();
    let mut m:[u8;32]=[0;32];
    rng.fill_bytes(m.as_mut_slice());


    // 私钥长度48字节
    let mut sk:[u8;big::MODBYTES]=[0;big::MODBYTES];

    // 公钥长度压缩格式
    let mut pk:[u8;2*big::MODBYTES+1]=[0;2*big::MODBYTES+1];

    // ikm长度至少为32字节
    let mut ikm:[u8;big::MODBYTES]=[0;big::MODBYTES];
    rng.fill_bytes(ikm.as_mut_slice());


    // 生成密钥对
    bls::key_pair_generate(ikm.as_slice(), sk.as_mut_slice(), pk.as_mut_slice());

    // 签名值长度为48+1
    let mut sig:[u8;big::MODBYTES+1]=[0;big::MODBYTES+1];

    assert_eq!(bls::core_sign(sig.as_mut_slice(), m.as_slice(), sk.as_slice()), BLS_OK);
    assert_eq!(bls::core_verify(sig.as_slice(), m.as_slice(), pk.as_slice()), BLS_OK);

    //println!("sk is:{:?}",sk);
    //println!("pk is:{:?}",pk);
    //println!("ikm is:{:?}",ikm);
    //println!("m is:{:?}",m);
    //println!("sig is:{:?}",sig);

    (sk,pk,m,sig)

}
