

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

        LWEToRLWEKeySwitchKey lwe_to_rlwe_ks_key;
        RLWEGadgetCT ct_of_sk_dest;
        std::shared_ptr<const RLWEParam> rlwe_param;
        std::shared_ptr<Gadget> gadget_param;


        public:

        // CHANGED: now takes two RLWEGadgetSK objects instead of one.
        //   sk_dest_ksk:  used ONLY for the plain per-digit LWE->RLWE switch
        //                 (the automorphism-key mechanism). Its base does not
        //                 need to match anything about the RGSW ciphertext's
        //                 own structure.
        //   sk_dest_rgsw: used for ct_of_sk_dest (the message*sk row) AND
        //                 stored as gadget_param, i.e. the base later used to
        //                 decompose incoming ciphertexts in RLWEGadgetCT::mul.
        //                 Its base MUST match whatever base the client used to
        //                 build the LWEGadgetCT (LWE') passed into
        //                 lwe_to_rlwe_key_switch below -- that's the
        //                 decomposition_base_prime side.
        //
        //   Both sk_dest_ksk and sk_dest_rgsw are expected to wrap the SAME
        //   underlying RLWESK (same secret key) -- only their Gadget objects
        //   (and therefore bases) differ.
        LWEToRGSWKeySwitchKey(const LWESK& sk_origin, const RLWEGadgetSK& sk_dest_ksk,
                              const RLWEGadgetSK& sk_dest_rgsw);

        LWEToRGSWKeySwitchKey(const LWEToRGSWKeySwitchKey &other) = delete;

        LWEToRGSWKeySwitchKey& operator=(const LWEToRGSWKeySwitchKey other) = delete;

        RLWEGadgetCT lwe_to_rlwe_key_switch(const LWEGadgetCT& lwe_ct_in);

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
