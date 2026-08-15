#ifndef PORTABLE_NTT_ENGINE_H
#define PORTABLE_NTT_ENGINE_H

/**
 * @file portable_ntt_engine.h
 */
#include "global_headers.h"

#include <vector>

#include "math/polynomial.h"

namespace FHEDeck{

/**
 * @brief Implementation of PolynomialMultiplicationEngine using a portable, real
 * (O(n log n)) negacyclic Number Theoretic Transform. Unlike
 * NaiveNegacyclicMultiplicationEngine (O(n^2), portable) or IntelHexlNTTEngine
 * (O(n log n), x86-only via HEXL/AVX-512), this engine is both fast and portable:
 * plain C++20 with no platform-specific intrinsics, so it compiles and runs
 * correctly under WebAssembly (Emscripten) as well as natively.
 *
 * Its evaluation form is PolynomialEvalFormLongInteger, matching
 * IntelHexlNTTEngine, so it is interchangeable with the HEXL engine at the
 * PolynomialMultiplicationEngine interface level.
 *
 * Algorithm: standard "twist + cyclic NTT + untwist" construction.
 *   - psi: a primitive 2*degree-th root of unity mod coef_modulus (requires
 *     coef_modulus - 1 to be divisible by 2*degree, i.e. an NTT-friendly prime).
 *   - omega = psi^2: a primitive degree-th root of unity, used for a standard
 *     textbook radix-2 DIT cyclic NTT (explicit bit-reversal permutation,
 *     natural-order output).
 *   - Forward: multiply coefficient i by psi^i (the "twist"), then run the
 *     cyclic NTT with omega.
 *   - Inverse: run the cyclic NTT with omega^{-1} (unnormalized inverse DFT),
 *     then multiply by degree^{-1} and by psi^{-i} (the "untwist").
 * This avoids the more error-prone "merged" Cooley-Tukey/Gentleman-Sande
 * negacyclic butterfly (with twiddle factors baked directly into a
 * bit-reversed-indexed zeta table), at the cost of two extra O(n) passes,
 * which is negligible next to the O(n log n) transform itself. Verified by
 * direct comparison against schoolbook negacyclic multiplication before being
 * wired into this class -- see the project conversation history for the
 * standalone verification harness.
 */
class PortableNTTEngine : public PolynomialMultiplicationEngine{

    protected:

    int32_t m_degree;
    int64_t m_coef_modulus;

    /// @brief primitive degree-th root of unity, and its inverse
    int64_t m_omega;
    int64_t m_omega_inv;
    /// @brief modular inverse of m_degree
    int64_t m_n_inv;
    /// @brief psi^i and psi^{-i} for i = 0 .. m_degree - 1, where psi is a
    /// primitive (2*m_degree)-th root of unity and psi^2 == m_omega
    std::vector<int64_t> m_psi_pow;
    std::vector<int64_t> m_psi_inv_pow;

    public:

    PortableNTTEngine(int32_t degree, int64_t coef_modulus);

    std::shared_ptr<PolynomialEvalForm> init_polynomial_eval_form();

    std::shared_ptr<PolynomialArrayEvalForm> init_polynomial_array_eval_form(int32_t array_size);

    void to_eval(PolynomialEvalForm &out, const Polynomial &in);

    void to_eval(PolynomialArrayEvalForm &out, const PolynomialArray &in);

    void to_coef(Polynomial &out, const PolynomialEvalForm &in);

    void to_coef(PolynomialArray &out, const PolynomialArrayEvalForm &in);

    void mul(PolynomialEvalForm &out, const PolynomialEvalForm &in_1, const PolynomialEvalForm &in_2);

    void multisum(Polynomial &out, const PolynomialArray &in_1, const PolynomialArrayEvalForm &in_2);

    void multisum(Polynomial &out, const PolynomialArrayEvalForm &in_1, const PolynomialArrayEvalForm &in_2);

    void multisum(Polynomial &out_multisum, PolynomialArrayEvalForm &out_in_1_eval, const PolynomialArray &in_1, const PolynomialArrayEvalForm &in_2);

    private:

    /// @brief modular multiplication, a and b assumed to be in [0, m_coef_modulus)
    inline int64_t mulmod(int64_t a, int64_t b) const;

    inline int64_t addmod(int64_t a, int64_t b) const;

    inline int64_t submod(int64_t a, int64_t b) const;

    static int64_t modpow(int64_t base, int64_t exp, int64_t mod);

    static int64_t mod_inv(int64_t a, int64_t mod);

    static std::vector<int64_t> factor(int64_t n);

    static int64_t find_primitive_root(int64_t mod);

    /// @brief in-place bit-reversal permutation
    void bitreverse_permute(int64_t* a) const;

    /// @brief in-place textbook radix-2 DIT cyclic NTT with the given root
    /// (must be a primitive m_degree-th root of unity mod m_coef_modulus).
    /// Natural-order input, natural-order output.
    void ntt_cyclic(int64_t* a, int64_t root) const;

    /// @brief in-place forward negacyclic NTT: coefficient (natural) order in,
    /// evaluation (natural, untwisted-DFT) order out.
    void ntt_forward(int64_t* a) const;

    /// @brief in-place inverse negacyclic NTT: evaluation order in,
    /// coefficient (natural) order out.
    void ntt_inverse(int64_t* a) const;
};

}/// End of namespace FHEDeck

#endif
