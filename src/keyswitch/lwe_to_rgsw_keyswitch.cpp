#include "keyswitch/lwe_to_rgsw_keyswitch.h"

using namespace FHEDeck;



LWEToRGSWKeySwitchKey::LWEToRGSWKeySwitchKey(std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key,
                                              const RLWEGadgetSK& sk_dest_rgsw)
    : lwe_to_rlwe_ks_key(std::move(lwe_to_rlwe_ks_key))
{
    ct_of_sk_squared = sk_dest_rgsw.extended_encrypt_sk_squared();
    rlwe_param = sk_dest_rgsw.param();
    gadget_param = sk_dest_rgsw.gadget();
}

LWEToRGSWKeySwitchKey::LWEToRGSWKeySwitchKey(std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key,
                                              ExtendedRLWECT ct_of_sk_squared,
                                              std::shared_ptr<const RLWEParam> rlwe_param,
                                              std::shared_ptr<Gadget> gadget_param)
    : lwe_to_rlwe_ks_key(std::move(lwe_to_rlwe_ks_key)),
      ct_of_sk_squared(std::move(ct_of_sk_squared)),
      rlwe_param(std::move(rlwe_param)),
      gadget_param(std::move(gadget_param))
{
}

RLWEGadgetCT LWEToRGSWKeySwitchKey::lwe_to_rlwe_key_switch(const LWEGadgetCT& lwe_ct_in)
{
    // Step 1: LWE'(m) --> RLWE'(m), one LWE-to-RLWE key switch per digit.
    std::vector<RLWECT> rlwe_ct_out;
    for(const auto& lwe_ct : lwe_ct_in.m_ct_content){
        RLWECT rlwe_ct(rlwe_param);
        lwe_to_rlwe_ks_key->lwe_to_rlwe_key_switch(rlwe_ct, lwe_ct);
        rlwe_ct_out.push_back(rlwe_ct);
    }
    // Step 2: RLWE'(m) --> RGSW(m).
    return rlwe_prime_to_rgsw(rlwe_ct_out);
}

RLWEGadgetCT LWEToRGSWKeySwitchKey::rlwe_prime_to_rgsw(std::vector<RLWECT>& rlwe_prime_ct)
{
    // Scheme switching of ePrint 2023/112, Sec. 3.1.
    //
    // FHE-Deck convention: RLWE(m) = (a, b) with b = -a*s + e + m, i.e. the
    // phase is b + a*s. For a row (a, b) = RLWE(B^i m) we want RLWE(B^i m s):
    //
    //   s * (b + a*s) = b*s + a*s^2
    //
    //   a*s^2 : a (.) RLWE'(s^2) = (alpha, beta) with beta + alpha*s ~= a*s^2
    //   b*s   : (b, 0), i.e. a-part = b, b-part = 0 -- noiseless, since
    //           0 + b*s = b*s exactly.
    //
    // => RLWE(B^i m s) = (alpha + b, beta), with error e*s + (error of the ⊙).
    // Previously this was RGSW(s) ⊡ (a, b) = b (.) RLWE'(s) + a (.) RLWE'(s^2):
    // two decompositions + two multisums per row, and an extra noise term from
    // b (.) RLWE'(s).
    std::vector<RLWECT> rlwe_ct_out_sk;
    rlwe_ct_out_sk.reserve(rlwe_prime_ct.size());
    for(const auto& rlwe_ct : rlwe_prime_ct){
        RLWECT a_times_sk_sq(rlwe_param);
        ct_of_sk_squared.mul(a_times_sk_sq, rlwe_ct.a());   // a (.) RLWE'(s^2)
        Polynomial a_out(a_times_sk_sq.a());
        a_out.add(a_out, rlwe_ct.b());                      // + (b, 0)
        Polynomial b_out(a_times_sk_sq.b());
        rlwe_ct_out_sk.emplace_back(rlwe_param, std::move(a_out), std::move(b_out));
    }
    return RLWEGadgetCT(rlwe_param, gadget_param, rlwe_prime_ct, rlwe_ct_out_sk);
}

const ExtendedRLWECT& LWEToRGSWKeySwitchKey::get_ct_of_sk_squared()const{
    return ct_of_sk_squared;
}
