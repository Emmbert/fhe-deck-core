#include "keyswitch/lwe_to_rgsw_keyswitch.h"

using namespace FHEDeck;


LWEToRGSWKeySwitchKey::LWEToRGSWKeySwitchKey(const LWESK& sk_origin, const RLWEGadgetSK& sk_dest_ksk,
                                              const RLWEGadgetSK& sk_dest_rgsw)
    : lwe_to_rlwe_ks_key(sk_origin, sk_dest_ksk)
{
    // CHANGED: both of these now come from sk_dest_rgsw, not sk_dest_ksk.
    // ct_of_sk_dest's row count/scaling must match whatever base the
    // client's LWEGadgetCT (LWE') was built with, so that when
    // lwe_to_rlwe_key_switch below switches each of its rows individually,
    // the resulting "message row" and this "message*sk row" agree on what
    // each row represents (m * base^i for the SAME base). gadget_param is
    // stored on the OUTPUT RLWEGadgetCT and later drives how
    // RLWEGadgetCT::mul decomposes incoming ciphertexts -- it must be the
    // same base too, for exactly the same reason.
    ct_of_sk_dest = sk_dest_rgsw.gadget_encrypt_sk();
    rlwe_param = sk_dest_rgsw.param();
    gadget_param = sk_dest_rgsw.gadget();
}

 

RLWEGadgetCT LWEToRGSWKeySwitchKey::lwe_to_rlwe_key_switch(const LWEGadgetCT& lwe_ct_in)
{ 

    std::vector<RLWECT> rlwe_ct_out;
    for(const auto& lwe_ct : lwe_ct_in.m_ct_content){
        RLWECT rlwe_ct(rlwe_param);
        lwe_to_rlwe_ks_key.lwe_to_rlwe_key_switch(rlwe_ct, lwe_ct);
        rlwe_ct_out.push_back(rlwe_ct);       
    }
    std::vector<RLWECT> rlwe_ct_out_sk;
    for(const auto& rlwe_ct : rlwe_ct_out){
        RLWECT rlwe_ct_sk(rlwe_param);
        ct_of_sk_dest.mul(rlwe_ct_sk, rlwe_ct);
        rlwe_ct_out_sk.push_back(rlwe_ct_sk);
    } 
    return RLWEGadgetCT(rlwe_param, gadget_param, rlwe_ct_out, rlwe_ct_out_sk);
}
