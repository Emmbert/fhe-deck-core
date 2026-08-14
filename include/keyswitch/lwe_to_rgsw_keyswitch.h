

#ifndef LWE_TO_RGSW_KEYSWITCH_H
#define LWE_TO_RGSW_KEYSWITCH_H

/**
 * @file lwe_to_rgsw_keyswitch.h
 */
#include "global_headers.h"

#include "ciphertexts/lwe.h"
#include "ciphertexts/rlwe.h"
#include "keyswitch/lwe_to_rlwe_keyswitch.h"

namespace FHEDeck{

    class LWEToRGSWKeySwitchKey{


    protected:

    // CHANGED: shared, not owned by value. Lets the SAME LWEToRLWEKeySwitchKey
    // instance (e.g. a client's pub.lwe_to_rlwe_ksk, already built for the
    // plain query-embedding switch) be reused here instead of generating a
    // second, redundant set of automorphism keys.
    std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key;
    RLWEGadgetCT ct_of_sk_dest;
    std::shared_ptr<const RLWEParam> rlwe_param;
    std::shared_ptr<Gadget> gadget_param;


    public:

        // CHANGED: takes an ALREADY-BUILT LWEToRLWEKeySwitchKey (shared,
        // reused -- see the class comment above) instead of (sk_origin,
        // sk_dest_ksk), which used to build its own independent copy.
        // sk_dest_rgsw is unchanged: still what builds ct_of_sk_dest (the
        // message*sk row) and what gets stored as this ciphertext's own
        // gadget_param -- its base MUST match whatever base the client's
        // LWEGadgetCT (LWE') was built with, exactly as before.
        LWEToRGSWKeySwitchKey(std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key,
                              const RLWEGadgetSK& sk_dest_rgsw);
    public:

        LWEToRGSWKeySwitchKey(const LWESK& sk_origin, const RLWEGadgetSK& sk_dest);
 
        LWEToRGSWKeySwitchKey(const LWEToRGSWKeySwitchKey &other) = delete;

        LWEToRGSWKeySwitchKey& operator=(const LWEToRGSWKeySwitchKey other) = delete;


        // NEW: for server-side reconstruction. No secret key is available
        // server-side, so ct_of_sk_dest can't be computed via
        // gadget_encrypt_sk() -- it has to be handed in already-built,
        // reconstructed from a seed + received b-values exactly like
        // lwe_to_rlwe_ks_key's own content.
        LWEToRGSWKeySwitchKey(std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key,
                              RLWEGadgetCT ct_of_sk_dest,
                              std::shared_ptr<const RLWEParam> rlwe_param,
                              std::shared_ptr<Gadget> gadget_param);


        RLWEGadgetCT lwe_to_rlwe_key_switch(const LWEGadgetCT& lwe_ct_in);

        // NEW: read access to ct_of_sk_dest -- needed to extract its
        // b-values for the seed-compressed wire format.
        const RLWEGadgetCT& get_ct_of_sk_dest()const;

        std::shared_ptr<const RLWEParam> dest_param()const;


    #if defined(USE_CEREAL)
        template <class Archive>
        void save( Archive & ar ) const
        {
            ar(m_ext_key_content, m_dest_param);
        }

        template <class Archive>
        void load( Archive & ar )
        {
            ar(m_ext_key_content, m_dest_param);
            init();
        }

    #endif

    };


} /// End of namespace FHEDeck


#endif //LWE_TO_RGSW_KEYSWITCH_H
