#include "keyswitch/lwe_to_rgsw_keyswitch.h"

using namespace FHEDeck;


LWEToRGSWKeySwitchKey::LWEToRGSWKeySwitchKey(std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key,
                                              const RLWEGadgetSK& sk_dest_rgsw)
    : lwe_to_rlwe_ks_key(std::move(lwe_to_rlwe_ks_key))
{
    ct_of_sk_dest = sk_dest_rgsw.gadget_encrypt_sk();
    rlwe_param = sk_dest_rgsw.param();
    gadget_param = sk_dest_rgsw.gadget();
}

LWEToRGSWKeySwitchKey::LWEToRGSWKeySwitchKey(std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key,
                                              RLWEGadgetCT ct_of_sk_dest,
                                              std::shared_ptr<const RLWEParam> rlwe_param,
                                              std::shared_ptr<Gadget> gadget_param)
    : lwe_to_rlwe_ks_key(std::move(lwe_to_rlwe_ks_key)),
      ct_of_sk_dest(std::move(ct_of_sk_dest)),
      rlwe_param(std::move(rlwe_param)),
      gadget_param(std::move(gadget_param))
{
}

RLWEGadgetCT LWEToRGSWKeySwitchKey::lwe_to_rlwe_key_switch(const LWEGadgetCT& lwe_ct_in)
{

    std::vector<RLWECT> rlwe_ct_out;
    for(const auto& lwe_ct : lwe_ct_in.m_ct_content){
        RLWECT rlwe_ct(rlwe_param);
        lwe_to_rlwe_ks_key->lwe_to_rlwe_key_switch(rlwe_ct, lwe_ct); // CHANGED: -> instead of .
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

const RLWEGadgetCT& LWEToRGSWKeySwitchKey::get_ct_of_sk_dest()const{
    return ct_of_sk_dest;
}
