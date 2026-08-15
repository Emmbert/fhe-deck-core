#include "math/portable_ntt_engine.h"

using namespace FHEDeck;

// ---------------------------------------------------------------------------
// Modular arithmetic helpers. int64_t coef_modulus values in this project go
// up to ~2^58 (see intel_hexl_engine / naive_multiplication_engine usage), so
// a*b can overflow 64 bits; __int128 is used for the multiplication, exactly
// like NaiveNegacyclicMultiplicationEngine::mul already does elsewhere in
// this codebase (see naive_multiplication_engine.cpp) -- so this is already
// proven portable to wasm32 in this project (Emscripten supports __int128
// via compiler-rt).
// ---------------------------------------------------------------------------

inline int64_t PortableNTTEngine::mulmod(int64_t a, int64_t b) const{
    return (int64_t)(((__int128) a * (__int128) b) % (__int128) m_coef_modulus);
}

inline int64_t PortableNTTEngine::addmod(int64_t a, int64_t b) const{
    int64_t s = a + b;
    return s >= m_coef_modulus ? s - m_coef_modulus : s;
}

inline int64_t PortableNTTEngine::submod(int64_t a, int64_t b) const{
    return a >= b ? a - b : a + m_coef_modulus - b;
}

int64_t PortableNTTEngine::modpow(int64_t base, int64_t exp, int64_t mod){
    __int128 result = 1 % mod;
    __int128 b = base % mod;
    if(b < 0) b += mod;
    while(exp > 0){
        if(exp & 1) result = (result * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    return (int64_t) result;
}

int64_t PortableNTTEngine::mod_inv(int64_t a, int64_t mod){
    return Utils::mod_inv(a, mod);
}

std::vector<int64_t> PortableNTTEngine::factor(int64_t n){
    std::vector<int64_t> fac;
    for(int64_t p = 2; p * p <= n; ++p){
        if(n % p == 0){
            fac.push_back(p);
            while(n % p == 0) n /= p;
        }
    }
    if(n > 1) fac.push_back(n);
    return fac;
}

int64_t PortableNTTEngine::find_primitive_root(int64_t mod){
    int64_t phi = mod - 1;
    std::vector<int64_t> fac = factor(phi);
    for(int64_t g = 2; g < mod; ++g){
        bool ok = true;
        for(int64_t p : fac){
            if(modpow(g, phi / p, mod) == 1){
                ok = false;
                break;
            }
        }
        if(ok) return g;
    }
    throw std::logic_error("PortableNTTEngine: no primitive root found for the given modulus.");
}

// ---------------------------------------------------------------------------
// Construction: find psi (primitive 2*degree-th root of unity), derive omega
// = psi^2 (primitive degree-th root), and precompute the psi^i / psi^{-i}
// twist tables.
// ---------------------------------------------------------------------------

PortableNTTEngine::PortableNTTEngine(int32_t degree, int64_t coef_modulus){
    m_degree = degree;
    m_coef_modulus = coef_modulus;
    m_type = PolynomialArithmetic::ntt64;

    if((degree & (degree - 1)) != 0){
        throw std::logic_error("PortableNTTEngine: degree must be a power of two.");
    }
    if((coef_modulus - 1) % (2 * (int64_t) degree) != 0){
        throw std::logic_error("PortableNTTEngine: coef_modulus is not NTT-friendly "
            "(coef_modulus - 1 must be divisible by 2*degree).");
    }

    int64_t g = find_primitive_root(coef_modulus);
    int64_t psi = modpow(g, (coef_modulus - 1) / (2 * (int64_t) degree), coef_modulus);

    // Defensive correctness checks -- cheap (O(log degree)), and this is a
    // crypto-correctness-critical primitive, so verify the root actually has
    // the order we need rather than assuming find_primitive_root /
    // modpow / the divisibility check above are jointly bug-free.
    if(modpow(psi, degree, coef_modulus) != coef_modulus - 1){
        throw std::logic_error("PortableNTTEngine: psi^degree != -1 mod coef_modulus; "
            "psi is not a primitive 2*degree-th root of unity.");
    }
    if(modpow(psi, 2 * (int64_t) degree, coef_modulus) != 1){
        throw std::logic_error("PortableNTTEngine: psi^(2*degree) != 1 mod coef_modulus.");
    }

    m_omega = mulmod(psi, psi);
    m_omega_inv = mod_inv(m_omega, coef_modulus);
    m_n_inv = mod_inv((int64_t) degree, coef_modulus);

    int64_t psi_inv = mod_inv(psi, coef_modulus);
    m_psi_pow.assign(degree, 1);
    m_psi_inv_pow.assign(degree, 1);
    for(int32_t i = 1; i < degree; ++i){
        m_psi_pow[i] = mulmod(m_psi_pow[i - 1], psi);
        m_psi_inv_pow[i] = mulmod(m_psi_inv_pow[i - 1], psi_inv);
    }
}

// ---------------------------------------------------------------------------
// Core transform
// ---------------------------------------------------------------------------

void PortableNTTEngine::bitreverse_permute(int64_t* a) const{
    for(int32_t i = 1, j = 0; i < m_degree; ++i){
        int32_t bit = m_degree >> 1;
        for(; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if(i < j) std::swap(a[i], a[j]);
    }
}

void PortableNTTEngine::ntt_cyclic(int64_t* a, int64_t root) const{
    bitreverse_permute(a);
    for(int32_t len = 2; len <= m_degree; len <<= 1){
        int64_t w_len = modpow(root, m_degree / len, m_coef_modulus);
        for(int32_t start = 0; start < m_degree; start += len){
            int64_t w = 1;
            for(int32_t j = 0; j < len / 2; ++j){
                int64_t u = a[start + j];
                int64_t v = mulmod(a[start + j + len / 2], w);
                a[start + j] = addmod(u, v);
                a[start + j + len / 2] = submod(u, v);
                w = mulmod(w, w_len);
            }
        }
    }
}

void PortableNTTEngine::ntt_forward(int64_t* a) const{
    for(int32_t i = 0; i < m_degree; ++i) a[i] = mulmod(a[i], m_psi_pow[i]);
    ntt_cyclic(a, m_omega);
}

void PortableNTTEngine::ntt_inverse(int64_t* a) const{
    ntt_cyclic(a, m_omega_inv); // unnormalized inverse DFT
    for(int32_t i = 0; i < m_degree; ++i){
        a[i] = mulmod(a[i], m_n_inv);
        a[i] = mulmod(a[i], m_psi_inv_pow[i]);
    }
}

// ---------------------------------------------------------------------------
// PolynomialMultiplicationEngine interface. Same evaluation-form types and
// overall structure as IntelHexlNTTEngine, so this engine is a drop-in
// substitute wherever NTT_ENGINE=Hexl was used.
// ---------------------------------------------------------------------------

std::shared_ptr<PolynomialEvalForm> PortableNTTEngine::init_polynomial_eval_form(){
    return std::make_shared<PolynomialEvalFormLongInteger>(m_degree, m_coef_modulus);
}

std::shared_ptr<PolynomialArrayEvalForm> PortableNTTEngine::init_polynomial_array_eval_form(int32_t array_size){
    return std::make_shared<PolynomialArrayEvalFormLong>(array_size, m_degree, m_coef_modulus);
}

void PortableNTTEngine::to_eval(PolynomialEvalForm &out, const Polynomial &in){
    PolynomialEvalFormLongInteger& out_cast = static_cast<PolynomialEvalFormLongInteger&>(out);
    for(int32_t i = 0; i < m_degree; ++i){
        out_cast[i] = in[i];
    }
    ntt_forward(out_cast.get());
}

void PortableNTTEngine::to_eval(PolynomialArrayEvalForm &out, const PolynomialArray &in){
    PolynomialArrayEvalFormLong& out_cast = static_cast<PolynomialArrayEvalFormLong&>(out);
    for(int32_t i = 0; i < in.size(); ++i){
        int64_t* row = out_cast[i].data();
        for(int32_t j = 0; j < m_degree; ++j){
            row[j] = in[i][j];
        }
        ntt_forward(row);
    }
}

void PortableNTTEngine::to_coef(Polynomial &out, const PolynomialEvalForm &in){
    const PolynomialEvalFormLongInteger& in_cast = static_cast<const PolynomialEvalFormLongInteger&>(in);
    for(int32_t i = 0; i < m_degree; ++i){
        out[i] = in_cast[i];
    }
    ntt_inverse(out.get());
}

void PortableNTTEngine::to_coef(PolynomialArray &out, const PolynomialArrayEvalForm &in){
    const PolynomialArrayEvalFormLong& in_cast = static_cast<const PolynomialArrayEvalFormLong&>(in);
    for(int32_t i = 0; i < in.size(); ++i){
        for(int32_t j = 0; j < m_degree; ++j){
            out[i][j] = in_cast[i][j];
        }
        ntt_inverse(out[i].get());
    }
}

void PortableNTTEngine::mul(PolynomialEvalForm &out, const PolynomialEvalForm &in_1, const PolynomialEvalForm &in_2){
    PolynomialEvalFormLongInteger& out_cast = static_cast<PolynomialEvalFormLongInteger&>(out);
    const PolynomialEvalFormLongInteger& in_1_cast = static_cast<const PolynomialEvalFormLongInteger&>(in_1);
    const PolynomialEvalFormLongInteger& in_2_cast = static_cast<const PolynomialEvalFormLongInteger&>(in_2);
    for(int32_t i = 0; i < m_degree; ++i){
        out_cast[i] = mulmod(in_1_cast[i], in_2_cast[i]);
    }
}

void PortableNTTEngine::multisum(Polynomial &out, const PolynomialArray &in_1, const PolynomialArrayEvalForm &in_2){
    const PolynomialArrayEvalFormLong& in_2_cast = static_cast<const PolynomialArrayEvalFormLong&>(in_2);
    std::vector<int64_t> temp(m_degree);
    std::vector<int64_t> acc(m_degree);

    for(int32_t i = 0; i < m_degree; ++i) temp[i] = in_1[0][i];
    ntt_forward(temp.data());
    const int64_t* in_2_row0 = in_2_cast[0].data();
    for(int32_t i = 0; i < m_degree; ++i) acc[i] = mulmod(temp[i], in_2_row0[i]);

    for(int32_t k = 1; k < in_2_cast.size(); ++k){
        for(int32_t i = 0; i < m_degree; ++i) temp[i] = in_1[k][i];
        ntt_forward(temp.data());
        const int64_t* in_2_row = in_2_cast[k].data();
        for(int32_t i = 0; i < m_degree; ++i){
            acc[i] = addmod(acc[i], mulmod(temp[i], in_2_row[i]));
        }
    }
    ntt_inverse(acc.data());
    for(int32_t i = 0; i < m_degree; ++i) out[i] = acc[i];
}

void PortableNTTEngine::multisum(Polynomial &out, const PolynomialArrayEvalForm &in_1, const PolynomialArrayEvalForm &in_2){
    const PolynomialArrayEvalFormLong& in_1_cast = static_cast<const PolynomialArrayEvalFormLong&>(in_1);
    const PolynomialArrayEvalFormLong& in_2_cast = static_cast<const PolynomialArrayEvalFormLong&>(in_2);
    std::vector<int64_t> acc(m_degree);

    const int64_t* in_1_row0 = in_1_cast[0].data();
    const int64_t* in_2_row0 = in_2_cast[0].data();
    for(int32_t i = 0; i < m_degree; ++i) acc[i] = mulmod(in_1_row0[i], in_2_row0[i]);

    for(int32_t k = 1; k < in_2_cast.size(); ++k){
        const int64_t* in_1_row = in_1_cast[k].data();
        const int64_t* in_2_row = in_2_cast[k].data();
        for(int32_t i = 0; i < m_degree; ++i){
            acc[i] = addmod(acc[i], mulmod(in_1_row[i], in_2_row[i]));
        }
    }
    ntt_inverse(acc.data());
    for(int32_t i = 0; i < m_degree; ++i) out[i] = acc[i];
}

void PortableNTTEngine::multisum(Polynomial &out_multisum, PolynomialArrayEvalForm &out_in_1_eval, const PolynomialArray &in_1, const PolynomialArrayEvalForm &in_2){
    PolynomialArrayEvalFormLong& out_in_1_eval_cast = static_cast<PolynomialArrayEvalFormLong&>(out_in_1_eval);
    const PolynomialArrayEvalFormLong& in_2_cast = static_cast<const PolynomialArrayEvalFormLong&>(in_2);
    std::vector<int64_t> acc(m_degree);

    int64_t* out_row0 = out_in_1_eval_cast[0].data();
    for(int32_t i = 0; i < m_degree; ++i) out_row0[i] = in_1[0][i];
    ntt_forward(out_row0);
    const int64_t* in_2_row0 = in_2_cast[0].data();
    for(int32_t i = 0; i < m_degree; ++i) acc[i] = mulmod(out_row0[i], in_2_row0[i]);

    for(int32_t k = 1; k < in_2_cast.size(); ++k){
        int64_t* out_row = out_in_1_eval_cast[k].data();
        for(int32_t i = 0; i < m_degree; ++i) out_row[i] = in_1[k][i];
        ntt_forward(out_row);
        const int64_t* in_2_row = in_2_cast[k].data();
        for(int32_t i = 0; i < m_degree; ++i){
            acc[i] = addmod(acc[i], mulmod(out_row[i], in_2_row[i]));
        }
    }
    ntt_inverse(acc.data());
    for(int32_t i = 0; i < m_degree; ++i) out_multisum[i] = acc[i];
}
