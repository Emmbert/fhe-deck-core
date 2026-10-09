

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
    // CHANGED (ePrint 2023/112, Sec. 3.1): scheme switching key RLWE'(sk^2)
    // instead of RGSW(sk) = (RLWE'(sk), RLWE'(sk^2)). Half the size, half
    // the external products, and less noise in the message*sk row.
    ExtendedRLWECT ct_of_sk_squared;
    std::shared_ptr<const RLWEParam> rlwe_param;
    std::shared_ptr<Gadget> gadget_param;


    public:

        // CHANGED: takes an ALREADY-BUILT LWEToRLWEKeySwitchKey (shared,
        // reused -- see the class comment above) instead of (sk_origin,
        // sk_dest_ksk), which used to build its own independent copy.
        // sk_dest_rgsw builds ct_of_sk_squared = RLWE'(sk^2) and its gadget
        // is stored as this ciphertext's own gadget_param -- its base MUST
        // match whatever base the client's LWEGadgetCT (LWE') was built
        // with, exactly as before.
        LWEToRGSWKeySwitchKey(std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key,
                              const RLWEGadgetSK& sk_dest_rgsw);
    public:

        LWEToRGSWKeySwitchKey(const LWESK& sk_origin, const RLWEGadgetSK& sk_dest);
 
        LWEToRGSWKeySwitchKey(const LWEToRGSWKeySwitchKey &other) = delete;

        LWEToRGSWKeySwitchKey& operator=(const LWEToRGSWKeySwitchKey other) = delete;


        // For server-side reconstruction. No secret key is available
        // server-side, so ct_of_sk_squared can't be computed via
        // extended_encrypt_sk_squared() -- it has to be handed in
        // already-built, reconstructed from a seed + received b-values
        // (digits polynomials, one per gadget digit) exactly like
        // lwe_to_rlwe_ks_key's own content.
        LWEToRGSWKeySwitchKey(std::shared_ptr<LWEToRLWEKeySwitchKey> lwe_to_rlwe_ks_key,
                              ExtendedRLWECT ct_of_sk_squared,
                              std::shared_ptr<const RLWEParam> rlwe_param,
                              std::shared_ptr<Gadget> gadget_param);


        /// LWE'(m) --> RLWE'(m) --> RGSW(m). For every row RLWE(B^i m) = (a, b)
        /// the message*sk row is a (.) RLWE'(sk^2) + (b, 0), see .cpp.
        RLWEGadgetCT lwe_to_rlwe_key_switch(const LWEGadgetCT& lwe_ct_in);

        /// The scheme switching step alone: RLWE'(m) --> RGSW(m).
        /// @param rlwe_prime_ct The rows RLWE(B^i * m), i = 0..digits-1.
        RLWEGadgetCT rlwe_prime_to_rgsw(std::vector<RLWECT>& rlwe_prime_ct);

        // CHANGED (was get_ct_of_sk_dest): read access to RLWE'(sk^2) --
        // call get_b_coefficients() on it for the seed-compressed wire format.
        const ExtendedRLWECT& get_ct_of_sk_squared()const;

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
