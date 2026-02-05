// iq2pcap.cpp - Read complex-float I/Q, decode BLE, dump PCAP + features + aligned IQ chunks
// FIXED VERSION: I/Q chunks now properly align with detected packet boundaries 

// Recommended Actions:

// • Consider using 4 samples per transition (2 bits) for better SNR
// • Filter packets with insufficient transition counts

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <iostream>
#include <fstream>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <complex>
#include <limits>
#include <random>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "modified_lib/BLESDR.hpp"

// ============================================================================
// PCAP writer
// ============================================================================
namespace pcap {

static constexpr uint32_t MAGIC   = 0xa1b2c3d4u;
static constexpr uint16_t VMAJOR  = 2;
static constexpr uint16_t VMINOR  = 4;
static constexpr uint32_t LINKTYPE_BLE_LL_WITH_PHDR = 256;
static constexpr uint32_t SNAPLEN = 65535;

#pragma pack(push, 1)
struct le_phdr {
    uint8_t  rf_channel;
    int8_t   signal_power;
    int8_t   noise_power;
    uint8_t  access_address_offenses;
    uint32_t ref_access_address;
    uint16_t flags;
};
#pragma pack(pop)

static constexpr uint16_t LE_FLAG_DEWHITENED        = 0x0002;
static constexpr uint16_t LE_FLAG_REF_AA_VALID      = 0x0010;
static constexpr uint16_t LE_FLAG_AA_OFFENSES_OK    = 0x0020;
static constexpr uint16_t LE_FLAG_CRC_CHECKED       = 0x0400;
static constexpr uint16_t LE_FLAG_CRC_VALID         = 0x0800;

struct Writer {
    std::FILE* f = nullptr;

    explicit Writer(const std::string& path) {
        f = std::fopen(path.c_str(), "wb");
        if (!f) {
            std::perror(("fopen " + path).c_str());
            std::exit(1);
        }
        uint32_t magic = MAGIC;
        uint16_t vmaj = VMAJOR, vmin = VMINOR;
        uint32_t thiszone = 0, sigfigs = 0, snaplen = SNAPLEN;
        uint32_t network = LINKTYPE_BLE_LL_WITH_PHDR;

        std::fwrite(&magic,   4, 1, f);
        std::fwrite(&vmaj,    2, 1, f);
        std::fwrite(&vmin,    2, 1, f);
        std::fwrite(&thiszone,4, 1, f);
        std::fwrite(&sigfigs, 4, 1, f);
        std::fwrite(&snaplen, 4, 1, f);
        std::fwrite(&network, 4, 1, f);
    }

    double write_pkt(const uint8_t* data, size_t len, double ts_sec_f = -1.0) {
        using clock = std::chrono::system_clock;
        double now = ts_sec_f >= 0
                   ? ts_sec_f
                   : std::chrono::duration<double>(clock::now().time_since_epoch()).count();

        uint32_t ts_sec  = static_cast<uint32_t>(now);
        uint32_t ts_usec = static_cast<uint32_t>((now - ts_sec) * 1e6 + 0.5);
        uint32_t incl    = static_cast<uint32_t>(len);
        uint32_t orig    = incl;

        std::fwrite(&ts_sec,  4, 1, f);
        std::fwrite(&ts_usec, 4, 1, f);
        std::fwrite(&incl,    4, 1, f);
        std::fwrite(&orig,    4, 1, f);
        std::fwrite(data,     1, len, f);
        return now;
    }

    ~Writer() {
        if (f) std::fclose(f);
    }
};

} // namespace pcap

// ============================================================================
// Helpers
// ============================================================================
static void die(const std::string& s) {
    std::cerr << "error: " << s << "\n";
    std::exit(1);
}

struct FeatureRow {
    size_t pkt_idx;
    double pcap_ts;
    int rf_channel;
    int pdu_type;
    std::string adv_addr;
    std::string access_address;
    std::string tag_type;     // "APPLE"|"GOOGLE"|"TILE"|"SAMSUNG"|"UNKNOWN"
    std::string ground_truth_apple;  // "ff"|"fc"|"fd"|"fe"|"0"
    std::string payload_hex;  // hex of BLE PDU payload (Length bytes), no spaces
    double cfo_quick_hz, cfo_centroid_hz, cfo_two_stage_hz;
    double cfo_std_hz, cfo_std_sym_hz;
    double iq_gain_alpha, iq_phase_deg_deg;
    double rise_time_us, psd_centroid_hz, psd_pnr_db, bw_3db_hz, gated_len_us;
    double cfo_two_stage_coarse_hz;
    double joint_fo_hz, joint_I0, joint_Q0, joint_eps, joint_phi_deg, joint_A;
    int joint_iters;
    double joint_cost;
    double cfo_exact_quick_hz, cfo_exact_ls_hz;
    uint64_t sample_start, sample_end;  // NEW: Record actual indices
    // NEW: Transition-specific CFOs
    double cfo_equal_hz_00;  // CFO for equal transitions (0→0, 1→1)
    double cfo_equal_hz_11;  // CFO for equal transitions (0→0, 1→1)
    double cfo_jump_hz_10;   // CFO for jump transitions (0→1, 1→0)
    double cfo_jump_hz_01;   // CFO for jump transitions (0→1, 1→0)
};

struct FeatureCSV {
    std::FILE* f = nullptr;

    explicit FeatureCSV(const std::string& path) {
        f = std::fopen(path.c_str(), "w");
        if (!f) throw std::runtime_error("cannot open features csv: " + path);

        std::fprintf(
            f,
            "pkt_idx,pcap_ts,rf_channel,pdu_type,adv_addr,access_address,"
            "tag_type,ground_truth_apple,"
            "cfo_quick_hz,cfo_centroid_hz,cfo_two_stage_hz,cfo_std_hz,cfo_std_sym_hz,"
            "iq_gain_alpha,iq_phase_deg_deg,rise_time_us,psd_centroid_hz,psd_pnr_db,bw_3db_hz,gated_len_us,"
            "cfo_two_stage_coarse_hz,"
            "joint_fo_hz,joint_I0,joint_Q0,joint_eps,joint_phi_deg,joint_A,joint_iters,joint_cost,"
            "cfo_exact_quick_hz,cfo_exact_ls_hz,sample_start,sample_end,"
            "cfo_equal_00_hz,cfo_equal_11_hz,cfo_jump_10_hz,cfo_jump_01_hz\n"
        );
    }

    void row(const FeatureRow& r) {
    std::fprintf(
        f,
        "%zu,%.9f,%d,%d,%s,%s,"
        "%s,%s,"  // tag_type,ground_truth_apple
        "%.6f,%.6f,%.6f,%.6f,%.6f,"
        "%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,"
        "%.6f,"
        "%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%d,%.6f,"
        "%.6f,%.6f,%llu,%llu,"
        "%.6f,%.6f,%.6f,%.6f\n",

        r.pkt_idx, r.pcap_ts, r.rf_channel, r.pdu_type,
        r.adv_addr.c_str(), r.access_address.c_str(),
        r.tag_type.c_str(), r.ground_truth_apple.c_str(),

        r.cfo_quick_hz, r.cfo_centroid_hz, r.cfo_two_stage_hz,
        r.cfo_std_hz, r.cfo_std_sym_hz,
        r.iq_gain_alpha, r.iq_phase_deg_deg,
        r.rise_time_us, r.psd_centroid_hz, r.psd_pnr_db, r.bw_3db_hz, r.gated_len_us,
        r.cfo_two_stage_coarse_hz,
        r.joint_fo_hz, r.joint_I0, r.joint_Q0, r.joint_eps,
        r.joint_phi_deg, r.joint_A, r.joint_iters, r.joint_cost,
        r.cfo_exact_quick_hz, r.cfo_exact_ls_hz,
        (unsigned long long)r.sample_start, (unsigned long long)r.sample_end,
        r.cfo_equal_hz_00, r.cfo_equal_hz_11, r.cfo_jump_hz_10, r.cfo_jump_hz_01
        );
    }

    ~FeatureCSV() { if (f) std::fclose(f); }
};

// struct FeatureCSV {
//     std::FILE* f = nullptr;

//     explicit FeatureCSV(const std::string& path) {
//         f = std::fopen(path.c_str(), "w");
//         if (!f) die("cannot open features CSV: " + path);
//         std::fprintf(
//             f,
//             "pkt_idx,pcap_ts,rf_channel,pdu_type,adv_addr,access_address,"
//             "cfo_quick_hz,cfo_centroid_hz,cfo_two_stage_hz,cfo_std_hz,cfo_std_sym_hz,"
//             "iq_gain_alpha,iq_phase_deg_deg,rise_time_us,psd_centroid_hz,psd_pnr_db,bw_3db_hz,gated_len_us,"
//             "cfo_two_stage_coarse_hz,"
//             "joint_fo_hz,joint_I0,joint_Q0,joint_eps,joint_phi_deg,joint_A,joint_iters,joint_cost,"
//             "cfo_exact_quick_hz,cfo_exact_ls_hz,sample_start,sample_end\n"
//         );
//     }

//     void row(const FeatureRow& r) {
//         std::fprintf(
//             f,
//             "%zu,%.9f,%d,%d,%s,%s,"
//             "%.6f,%.6f,%.6f,%.6f,%.6f,"
//             "%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,"
//             "%.6f,"
//             "%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%d,%.6f,"
//             "%.6f,%.6f,%llu,%llu\n",
//             r.pkt_idx, r.pcap_ts, r.rf_channel, r.pdu_type,
//             r.adv_addr.c_str(), r.access_address.c_str(),
//             r.cfo_quick_hz, r.cfo_centroid_hz, r.cfo_two_stage_hz,
//             r.cfo_std_hz, r.cfo_std_sym_hz,
//             r.iq_gain_alpha, r.iq_phase_deg_deg,
//             r.rise_time_us, r.psd_centroid_hz, r.psd_pnr_db, r.bw_3db_hz, r.gated_len_us,
//             r.cfo_two_stage_coarse_hz,
//             r.joint_fo_hz, r.joint_I0, r.joint_Q0, r.joint_eps,
//             r.joint_phi_deg, r.joint_A, r.joint_iters, r.joint_cost,
//             r.cfo_exact_quick_hz, r.cfo_exact_ls_hz,
//             (unsigned long long)r.sample_start, (unsigned long long)r.sample_end
//         );
//     }

//     ~FeatureCSV() {
//         if (f) std::fclose(f);
//     }
// };

// ============================================================================
// BLE helpers
// ============================================================================
namespace blehelpers {

static inline std::string adv_addr_to_str(const uint8_t* addr) {
    char s[3 * 6];
    std::snprintf(
        s, sizeof(s),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
    );
    return std::string(s);
}

static inline std::string to_adv_addr(const uint8_t* p, int /*pdu_type*/) {
    return adv_addr_to_str(p);
}

static inline std::string aa_to_str(uint32_t aa_le) {
    uint8_t b[4];
    b[0] = (uint8_t)(aa_le & 0xFF);
    b[1] = (uint8_t)((aa_le >> 8) & 0xFF);
    b[2] = (uint8_t)((aa_le >> 16) & 0xFF);
    b[3] = (uint8_t)((aa_le >> 24) & 0xFF);
    char s[9];
    std::snprintf(s, sizeof(s), "%02X%02X%02X%02X", b[3], b[2], b[1], b[0]);
    return std::string(s);
}

} // namespace blehelpers

// ============================================================================
// Feature helpers (simplified)
// ============================================================================
namespace feat {

using cf = std::complex<float>;

static inline std::vector<float> discr(const std::vector<cf>& x) {
    std::vector<float> d;
    if (x.size() < 2) return d;
    d.resize(x.size() - 1);
    for (size_t i = 1; i < x.size(); ++i) {
        cf z = x[i] * std::conj(x[i-1]);
        d[i-1] = std::atan2(z.imag(), z.real());
    }
    return d;
}

static inline double cfo_quick(const std::vector<cf>& x, double fs) {
    if (x.size() < 2) return 0.0;
    long double Re = 0, Im = 0;
    for (size_t i = 1; i < x.size(); ++i) {
        cf z = x[i] * std::conj(x[i-1]);
        Re += (long double)z.real();
        Im += (long double)z.imag();
    }
    long double ang = std::atan2((double)Im, (double)Re);
    return (double)ang * fs / (2.0 * M_PI);
}

static inline float median(std::vector<float> v) {
    if (v.empty()) return 0.f;
    size_t n = v.size() / 2;
    std::nth_element(v.begin(), v.begin() + n, v.end());
    float m = v[n];
    if (v.size() % 2 == 0) {
        std::nth_element(v.begin(), v.begin() + n - 1, v.end());
        m = 0.5f * (m + v[n-1]);
    }
    return m;
}

// ============================================================================
// 1. CFO CENTROID - FFT-based spectral centroid method
// ============================================================================
static inline double cfo_centroid(const std::vector<cf>& x, double fs,
                                  double bw_limit, float /*beta*/) {
    if (x.size() < 32) return cfo_quick(x, fs);
    
    const size_t N = std::min<size_t>(x.size(), 2048); // FFT size
    
    // Simple DFT (for production, use FFT library)
    std::vector<cf> X(N, cf(0, 0));
    for (size_t k = 0; k < N; ++k) {
        cf acc(0, 0);
        for (size_t n = 0; n < N; ++n) {
            double ang = -2.0 * M_PI * (double)k * (double)n / (double)N;
            acc += x[n] * cf(std::cos(ang), std::sin(ang));
        }
        X[k] = acc;
    }
    
    // Compute power spectrum
    std::vector<double> P(N);
    for (size_t i = 0; i < N; ++i) {
        P[i] = std::norm(X[i]);
    }
    
    // Compute frequency bins (fftshift convention)
    std::vector<double> freqs(N);
    for (size_t i = 0; i < N; ++i) {
        double f = ((double)i - (double)N/2.0) / (double)N * fs;
        freqs[i] = f;
    }
    
    // Centroid: weighted average frequency
    double sum_P = 0.0, sum_fP = 0.0;
    for (size_t i = 0; i < N; ++i) {
        size_t idx = (i + N/2) % N; // fftshift
        double f = freqs[i];
        
        if (std::abs(f) <= bw_limit) { // Limit to signal bandwidth
            sum_P += P[idx];
            sum_fP += f * P[idx];
        }
    }
    
    return (sum_P > 0) ? (sum_fP / sum_P) : 0.0;
}

// ============================================================================
// 2. TWO-STAGE CFO - Coarse from centroid + fine from phase slope
// ============================================================================
static inline double cfo_two_stage(const std::vector<cf>& x, double fs, float& coarse_out) {
    if (x.size() < 32) {
        coarse_out = 0.0f;
        return cfo_quick(x, fs);
    }
    
    // Stage 1: Coarse estimate using centroid
    double f_coarse = cfo_centroid(x, fs, 200e3, 0);
    coarse_out = (float)f_coarse;
    
    // Stage 2: De-rotate and fine estimate
    std::vector<cf> x_derot(x.size());
    for (size_t n = 0; n < x.size(); ++n) {
        double ang = -2.0 * M_PI * f_coarse * (double)n / fs;
        x_derot[n] = x[n] * cf(std::cos(ang), std::sin(ang));
    }
    
    // Fine estimate on de-rotated signal
    double f_fine = cfo_quick(x_derot, fs);
    
    return f_coarse + f_fine;
}

// ============================================================================
// 3. CFO STD DEV - Standard deviation of instantaneous CFO
// ============================================================================
static inline double cfo_std_all(const std::vector<cf>& x, double fs) {
    auto d = discr(x);
    if (d.size() < 2) return 0.0;
    
    // Convert discriminator to CFO (Hz)
    std::vector<double> cfo_inst(d.size());
    for (size_t i = 0; i < d.size(); ++i) {
        cfo_inst[i] = d[i] * fs / (2.0 * M_PI);
    }
    
    // Compute std dev
    long double mean = 0;
    for (auto v : cfo_inst) mean += (long double)v;
    mean /= (long double)cfo_inst.size();
    
    long double acc = 0;
    for (auto v : cfo_inst) {
        long double dv = v - mean;
        acc += dv * dv;
    }
    long double var = acc / (long double)(cfo_inst.size() - 1);
    
    return std::sqrt((double)var);
}

// ============================================================================
// 4. CFO STD DEV PER SYMBOL - Average discriminator per symbol then std dev
// ============================================================================
static inline int sps_int(double fs) {
    int v = (int)std::lround(fs / 1e6);
    return std::max(v, 1);
}

static inline double cfo_std_symbol_avg(const std::vector<cf>& x, double fs) {
    int sps = sps_int(fs);
    if ((int)x.size() < sps + 2) return 0.0;
    
    auto d = discr(x);
    
    // Average discriminator over each symbol period
    std::vector<double> sym_cfo;
    for (size_t i = 0; i + (size_t)sps <= d.size(); i += (size_t)sps) {
        double sum = 0;
        for (int k = 0; k < sps; ++k) {
            sum += d[i + k];
        }
        double avg = sum / sps;
        sym_cfo.push_back(avg * fs / (2.0 * M_PI));
    }
    
    if (sym_cfo.size() < 2) return 0.0;
    
    // Compute std dev of symbol-averaged CFO
    double mean = 0;
    for (auto v : sym_cfo) mean += v;
    mean /= sym_cfo.size();
    
    double var = 0;
    for (auto v : sym_cfo) {
        double dv = v - mean;
        var += dv * dv;
    }
    var /= (sym_cfo.size() - 1);
    
    return std::sqrt(var);
}

// ============================================================================
// 5. SPECTRAL STATS - PSD centroid, peak-to-noise ratio, 3dB bandwidth
// ============================================================================
static inline void spectral_stats(const std::vector<cf>& x, double fs,
                                  double& fcent, double& pnr_db, double& bw3) {
    fcent = 0.0;
    pnr_db = 0.0;
    bw3 = 0.0;
    
    if (x.size() < 64) return;
    
    const size_t N = std::min<size_t>(x.size(), 2048);
    
    // Apply Hann window
    std::vector<double> window(N);
    for (size_t i = 0; i < N; ++i) {
        window[i] = 0.5 * (1.0 - std::cos(2.0 * M_PI * i / (N - 1)));
    }
    
    // Windowed signal
    std::vector<cf> xw(N);
    for (size_t i = 0; i < N; ++i) {
        xw[i] = (float)window[i] * x[i];
    }
    
    // DFT
    std::vector<cf> X(N, cf(0, 0));
    for (size_t k = 0; k < N; ++k) {
        cf acc(0, 0);
        for (size_t n = 0; n < N; ++n) {
            double ang = -2.0 * M_PI * (double)k * (double)n / (double)N;
            acc += xw[n] * cf(std::cos(ang), std::sin(ang));
        }
        X[k] = acc;
    }
    
    // Power spectrum
    double window_power = 0;
    for (auto w : window) window_power += w * w;
    
    std::vector<double> S(N);
    for (size_t i = 0; i < N; ++i) {
        S[i] = std::norm(X[i]) / std::max(1e-18, window_power);
    }
    
    // FFTshift and compute frequency bins
    std::vector<double> S_shifted(N);
    std::vector<double> freqs(N);
    for (size_t i = 0; i < N; ++i) {
        size_t shifted_idx = (i + N/2) % N;
        S_shifted[i] = S[shifted_idx];
        freqs[i] = ((double)i - (double)N/2.0) / (double)N * fs;
    }
    
    // 1. Spectral centroid
    double sum_S = 0, sum_fS = 0;
    for (size_t i = 0; i < N; ++i) {
        sum_S += S_shifted[i];
        sum_fS += freqs[i] * S_shifted[i];
    }
    fcent = (sum_S > 0) ? (sum_fS / sum_S) : 0.0;
    
    // 2. Peak-to-Noise Ratio
    double peak = *std::max_element(S_shifted.begin(), S_shifted.end());
    
    // Estimate noise floor as median of spectrum
    std::vector<double> S_sorted = S_shifted;
    std::nth_element(S_sorted.begin(), S_sorted.begin() + S_sorted.size()/2, S_sorted.end());
    double noise_floor = S_sorted[S_sorted.size()/2];
    
    pnr_db = 10.0 * std::log10(std::max(peak, 1e-18) / std::max(noise_floor, 1e-18));
    
    // 3. 3dB Bandwidth
    double threshold = peak * std::pow(10.0, -3.0 / 10.0); // -3dB point
    
    size_t idx_low = 0, idx_high = N - 1;
    for (size_t i = 0; i < N; ++i) {
        if (S_shifted[i] >= threshold) {
            idx_low = i;
            break;
        }
    }
    for (size_t i = N; i-- > 0; ) {
        if (S_shifted[i] >= threshold) {
            idx_high = i;
            break;
        }
    }
    
    bw3 = (idx_high > idx_low) ? std::abs(freqs[idx_high] - freqs[idx_low]) : 0.0;
}

// ============================================================================
// 6. IQ IMBALANCE - Gain and phase mismatch estimation
// ============================================================================
static inline void iq_imbalance(const std::vector<cf>& x,
                                double& alpha, double& phi_deg) {
    alpha = 1.0;
    phi_deg = 0.0;
    
    if (x.empty()) return;
    
    // Compute second-order moments
    double E_I2 = 0, E_Q2 = 0, E_IQ = 0;
    
    for (const auto& z : x) {
        double I = z.real();
        double Q = z.imag();
        E_I2 += I * I;
        E_Q2 += Q * Q;
        E_IQ += I * Q;
    }
    
    E_I2 /= x.size();
    E_Q2 /= x.size();
    E_IQ /= x.size();
    
    // Gain imbalance: alpha = sqrt(E[I²] / E[Q²])
    alpha = std::sqrt(std::max(E_I2, 1e-16) / std::max(E_Q2, 1e-16));
    
    // Phase imbalance: phi = 0.5 * atan2(2*E[IQ], E[I²] - E[Q²])
    double phi_rad = 0.5 * std::atan2(2.0 * E_IQ, E_I2 - E_Q2 + 1e-16);
    phi_deg = phi_rad * 180.0 / M_PI;
}

// ============================================================================
// 7. RISE TIME - 10% to 90% envelope rise time
// ============================================================================
static inline double rise_time_us(const std::vector<cf>& x, double fs) {
    if (x.empty() || fs <= 0) return 0.0;
    
    const size_t N = x.size();
    
    // Compute envelope (magnitude)
    std::vector<double> env(N);
    for (size_t i = 0; i < N; ++i) {
        env[i] = std::abs(x[i]);
    }
    
    // Estimate steady-state level from last 20% of samples
    size_t tail_start = (size_t)(N * 0.8);
    if (tail_start >= N) tail_start = N / 2;
    
    double steady = 0.0;
    size_t tail_count = 0;
    for (size_t i = tail_start; i < N; ++i) {
        steady += env[i];
        tail_count++;
    }
    steady = (tail_count > 0) ? (steady / tail_count) : 0.0;
    
    if (steady <= 1e-12) return 0.0;
    
    // Find 10% and 90% crossing points
    double level_10 = 0.1 * steady;
    double level_90 = 0.9 * steady;
    
    size_t idx_10 = 0, idx_90 = 0;
    bool found_10 = false, found_90 = false;
    
    for (size_t i = 0; i < N; ++i) {
        if (!found_10 && env[i] >= level_10) {
            idx_10 = i;
            found_10 = true;
        }
        if (!found_90 && env[i] >= level_90) {
            idx_90 = i;
            found_90 = true;
            break;
        }
    }
    
    if (found_10 && found_90 && idx_90 > idx_10) {
        double rise_samples = (double)(idx_90 - idx_10);
        return rise_samples * 1e6 / fs; // Convert to microseconds
    }
    
    return 0.0;
}

// static inline double cfo_centroid(const std::vector<cf>& x, double fs,
//                                   double /*bw*/, float /*beta*/) {
//     return cfo_quick(x, fs);
// }

// static inline double cfo_two_stage(const std::vector<cf>& x, double fs, float& coarse_out) {
//     double c = cfo_quick(x, fs);
//     coarse_out = (float)c;
//     return c;
// }

// static inline double cfo_std_all(const std::vector<cf>& x, double fs) {
//     auto d = discr(x);
//     if (d.size() < 2) return 0.0;
//     long double mean = 0;
//     for (auto v : d) mean += (long double)v;
//     mean /= (long double)d.size();
//     long double acc = 0;
//     for (auto v : d) {
//         long double dv = v - mean;
//         acc += dv * dv;
//     }
//     long double var = acc / (long double)(d.size() - 1);
//     double std_r = std::sqrt((double)var);
//     return std_r * fs / (2.0 * M_PI);
// }

// static inline double cfo_std_symbol_avg(const std::vector<cf>& x, double fs) {
//     return cfo_std_all(x, fs);
// }

// static inline void spectral_stats(const std::vector<cf>& /*x*/, double /*fs*/,
//                                   double& fcent, double& pnr_db, double& bw3) {
//     fcent = 0.0;
//     pnr_db = 0.0;
//     bw3    = 0.0;
// }

// static inline void iq_imbalance(const std::vector<cf>& /*x*/,
//                                 double& alpha, double& phi_deg) {
//     alpha = 1.0;
//     phi_deg = 0.0;
// }

// static inline double rise_time_us(const std::vector<cf>& /*x*/, double /*fs*/) {
//     return 0.0;
// }

// static inline int sps_int(double fs_eff) {
//     int v = (int)std::lround(fs_eff / 1e6);
//     return std::max(v, 1);
// }

} // namespace feat

// ============================================================================
// Joint model (placeholder)
// ============================================================================
namespace joint {

using cf = feat::cf;

struct Params {
    double fo_hz = 0.0;
    double I0 = 0.0, Q0 = 0.0;
    double eps = 0.0;
    double phi = 0.0;
    double A   = 1.0;
    double pnr_db = 0.0;
    double bw3 = 0.0;
};

static inline std::vector<int> recover_symbols(const std::vector<cf>& x, int sps) {
    std::vector<int> m;
    if (x.empty() || sps <= 0) return m;
    size_t nsyms = x.size() / (size_t)sps;
    m.resize(nsyms);
    for (size_t k = 0; k < nsyms; ++k) {
        cf acc(0,0);
        for (int i = 0; i < sps; ++i) acc += x[k * sps + (size_t)i];
        m[k] = (acc.real() >= 0) ? +1 : -1;
    }
    return m;
}

static inline Params init_from_signal(const std::vector<cf>& /*x*/, double /*fs*/) {
    Params p;
    return p;
}

static inline void nesterov_fit(const std::vector<int>& /*m_pm1*/, int /*sps*/, double /*fs*/,
                                const std::vector<cf>& /*x*/,
                                Params& p, int& iters, double& J,
                                double /*BT*/, double /*h*/, int maxI,
                                double /*lr*/, double /*mu*/) {
    (void)maxI;
    iters = 0;
    J = 0.0;
}

} // namespace joint

// ============================================================================
// Ring buffer for IQ with absolute indices
// ============================================================================
struct Ring {
    std::vector<float> buf;   // interleaved I,Q
    size_t   cap = 0;         // capacity in complex samples
    uint64_t head_abs = 0;    // absolute complex index of NEXT write
    uint64_t oldest_abs = 0;  // absolute complex index of OLDEST retained sample

    void init(size_t complex_len) {
        cap = std::max<size_t>(complex_len, 4096);
        buf.assign(2*cap, 0.0f);
        head_abs   = 0;
        oldest_abs = 0;
    }

    inline void push(float I, float Q) {
        uint64_t idx = head_abs;
        size_t slot  = (size_t)(idx % cap);
        buf[2*slot]   = I;
        buf[2*slot+1] = Q;
        head_abs++;
        if (head_abs - oldest_abs > cap) {
            oldest_abs = head_abs - cap;
        }
    }

    inline uint64_t size_complex() const {
        return head_abs - oldest_abs;
    }

    bool copy_absolute_window(uint64_t a, uint64_t b,
                              std::vector<std::complex<float>>& out) const
    {
        if (b <= a) return false;
        if (a < oldest_abs || b > head_abs) return false;
        size_t N = (size_t)(b - a);
        out.resize(N);
        for (size_t k = 0; k < N; ++k) {
            uint64_t idx = a + k;
            size_t slot  = (size_t)(idx % cap);
            float I = buf[2*slot];
            float Q = buf[2*slot+1];
            out[k] = std::complex<float>(I, Q);
        }
        return true;
    }
};

// ============================================================================
// Gating
// ============================================================================
enum class GateMode { NONE, ENERGY, STRUCT, MID };

static bool find_energy_window(const std::vector<feat::cf>& x, double fs, size_t prepad_samps,
                               double K, size_t pad_samps,
                               size_t& best_a, size_t& best_b)
{
    if (x.size() < 64) return false;
    const size_t N = x.size();
    std::vector<double> e(N);
    for (size_t i=0;i<N;i++){
        e[i] = (double)std::norm(x[i]);
    }
    double mean=0, var=0;
    for (size_t i=0;i<N;i++) mean += e[i];
    mean /= (double)N;
    for (size_t i=0;i<N;i++){
        double d = e[i] - mean;
        var += d*d;
    }
    var /= std::max<size_t>(1, N-1);
    double sig = std::sqrt(var);

    double thr = mean + K*sig;
    size_t a=N, b=0;
    for (size_t i=0;i<N;i++){
        if (e[i] > thr){
            if (a==N) a=i;
            b=i;
        }
    }
    if (a==N || b<=a) return false;

    if (a > prepad_samps) a -= prepad_samps;
    else a = 0;
    b = std::min(N, b + pad_samps);
    best_a = a;
    best_b = b;
    return true;
}

static void apply_gate_energy(std::vector<feat::cf>& x, double fs, size_t prepad_samps,
                              double K, int pad_us)
{
    size_t pad = (size_t)std::llround(std::max(0, pad_us) * 1e-6 * fs);
    size_t a=0,b=0;
    if (find_energy_window(x, fs, prepad_samps, K, pad, a, b) && b>a && (b-a)>=32) {
        x = std::vector<feat::cf>(x.begin()+a, x.begin()+b);
    }
}

static void apply_gate_struct(std::vector<feat::cf>& x, double fs, size_t prepad_samps)
{
    size_t a0=0,b0=0;
    if (!find_energy_window(x, fs, prepad_samps, 4.0, 0, a0, b0)) return;
    size_t off  = (size_t)std::llround(8e-6 * fs);
    size_t span = (size_t)std::llround(56e-6 * fs);
    size_t a = std::min(a0 + off, x.size());
    size_t b = std::min(a + span, x.size());
    if (b>a && (b-a)>=32) x = std::vector<feat::cf>(x.begin()+a, x.begin()+b);
}

static void apply_gate_mid(std::vector<feat::cf>& x, double fs, size_t prepad_samps,
                           int a_us, int b_us)
{
    size_t a0=0,b0=0;
    if (!find_energy_window(x, fs, prepad_samps, 4.0, 0, a0, b0)) return;
    if (b_us < a_us) std::swap(b_us, a_us);
    size_t a = std::min(a0 + (size_t)std::llround(std::max(0,a_us)*1e-6*fs), x.size());
    size_t b = std::min(a0 + (size_t)std::llround(std::max(0,b_us)*1e-6*fs), x.size());
    if (b>a && (b-a)>=32) x = std::vector<feat::cf>(x.begin()+a, x.begin()+b);
}

// ============================================================================
// Args
// ============================================================================
struct Args {
    std::string file;
    std::string out = "out.pcap";
    int channel = 37;
    double fs = 4e6;
    int decim = 1;
    size_t chunk = 1'000'000;
    std::string dump_iq_dir = "";
    int prepad_us = 200;
    std::string features_out = "features.csv";
    GateMode gate = GateMode::NONE;
    double gate_k = 4.0;
    int gate_pad_us = 8;
    int gate_mid_a_us = 12;
    int gate_mid_b_us = 80;
};

static Args parse(int argc, char** argv) {
    Args a;
    for (int i=1;i<argc;i++) {
        std::string k = argv[i];
        auto need = [&](const char* what)->std::string{
            if (i+1>=argc) die(std::string("missing value for ")+what);
            return std::string(argv[++i]);
        };
        if      (k=="--file")          a.file = need("--file");
        else if (k=="--out")           a.out  = need("--out");
        else if (k=="--channel")       a.channel = std::stoi(need("--channel"));
        else if (k=="--fs")            a.fs      = std::stod(need("--fs"));
        else if (k=="--decim")         a.decim   = std::stoi(need("--decim"));
        else if (k=="--chunk")         a.chunk   = (size_t)std::stoll(need("--chunk"));
        else if (k=="--dump-iq-dir")   a.dump_iq_dir = need("--dump-iq-dir");
        else if (k=="--prepad-us")     a.prepad_us   = std::stoi(need("--prepad-us"));
        else if (k=="--features-out")  a.features_out = need("--features-out");
        else if (k=="--gate") {
            std::string v = need("--gate");
            if      (v=="none")   a.gate = GateMode::NONE;
            else if (v=="energy") a.gate = GateMode::ENERGY;
            else if (v=="struct") a.gate = GateMode::STRUCT;
            else if (v=="mid")    a.gate = GateMode::MID;
            else die("unknown gate: "+v);
        } else if (k=="--gate-k")        a.gate_k = std::stod(need("--gate-k"));
        else if (k=="--gate-pad-us")     a.gate_pad_us = std::stoi(need("--gate-pad-us"));
        else if (k=="--gate-mid-a-us")   a.gate_mid_a_us = std::stoi(need("--gate-mid-a-us"));
        else if (k=="--gate-mid-b-us")   a.gate_mid_b_us = std::stoi(need("--gate-mid-b-us"));
        else die("unknown arg: "+k);
    }
    if (a.file.empty()) die("must provide --file");
    return a;
}

// ============================================================================
// Dump context
// ============================================================================
using cf = feat::cf;

struct DumpCtx {
    bool enabled = false;
    std::string dir;
    int sps = 2;
    double fs_eff = 2e6;
    int prepad_us = 200;
    Ring* ring = nullptr;
    uint64_t ring_abs_head = 0;
    size_t pkt_idx = 0;
    FeatureCSV* featcsv = nullptr;

    GateMode gate = GateMode::NONE;
    double gate_k = 4.0;
    int gate_pad_us = 8;
    int gate_mid_a_us = 12;
    int gate_mid_b_us = 80;
};

enum class TagType { APPLE, GOOGLE, TILE, SAMSUNG, UNKNOWN };

static inline const char* tagtype_to_cstr(TagType t) {
    switch (t) {
        case TagType::APPLE:   return "APPLE";
        case TagType::GOOGLE:  return "GOOGLE";
        case TagType::TILE:    return "TILE";
        case TagType::SAMSUNG: return "SAMSUNG";
        default:               return "UNKNOWN";
    }
}

static inline std::string hexlify(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; i++) {
        s[2*i + 0] = H[(p[i] >> 4) & 0xF];
        s[2*i + 1] = H[(p[i] >> 0) & 0xF];
    }
    return s;
}

static TagType detect_tag_type(const uint8_t* pdu_bytes, size_t pdu_len) {
    // PDU bytes: Header(2) + Payload + CRC(3)
    if (pdu_len < 8) return TagType::UNKNOWN;

    const uint8_t* payload = pdu_bytes + 2;  // skip PDU header
    size_t payload_len = pdu_len - 5;        // exclude header(2) + CRC(3)
    if (payload_len < 6) return TagType::UNKNOWN;

    // Skip AdvA
    const uint8_t* ad_data = payload + 6;
    size_t ad_len = payload_len - 6;

    auto uuid_to_tag = [](uint16_t uuid) -> TagType {
        switch (uuid) {
            case 0xFEAA: return TagType::GOOGLE;  // Eddystone (often Google ecosystem)
            case 0xFEED: return TagType::TILE;    // Tile (commonly)
            case 0xFD5A: return TagType::SAMSUNG; // Samsung SmartTag/SmartThings Find (commonly)
            default:     return TagType::UNKNOWN;
        }
    };

    size_t pos = 0;
    while (pos + 1 < ad_len) {
        uint8_t length = ad_data[pos];
        if (length == 0) break;
        if (pos + 1 + length > ad_len) break;

        uint8_t ad_type = ad_data[pos + 1];

        // Manufacturer Specific Data (0xFF) => Apple Find My check
        if (ad_type == 0xFF && length >= 4) {
            uint16_t company_id = (uint16_t)ad_data[pos + 2] | ((uint16_t)ad_data[pos + 3] << 8);
            if (company_id == 0x004C && length >= 6) {
                uint8_t b0 = ad_data[pos + 4];
                uint8_t b1 = ad_data[pos + 5];
                if (b0 == 0x12 && b1 == 0x19) {
                    return TagType::APPLE;
                }
            }
        }

        // Service Data - 16-bit UUID (0x16) => GOOGLE/TILE/SAMSUNG
        if (ad_type == 0x16 && length >= 3) {
            uint16_t svc_uuid = (uint16_t)ad_data[pos + 2] | ((uint16_t)ad_data[pos + 3] << 8);
            TagType t = uuid_to_tag(svc_uuid);
            if (t != TagType::UNKNOWN) return t;
        }

        pos += 1 + length;
    }

    return TagType::UNKNOWN;
}

// Helper function to check if advertising data contains Apple FindMy tag
static bool is_findmy_tag(const uint8_t* pdu_bytes, size_t pdu_len) {
    // PDU format: Header(2) + Payload + CRC(3)
    // We need at least: Header(2) + AdvA(6) + AD structures
    if (pdu_len < 8) return false;
    
    const uint8_t* payload = pdu_bytes + 2;  // Skip PDU header
    size_t payload_len = pdu_len - 5;        // Exclude header(2) + CRC(3)
    
    // Skip AdvA (6 bytes)
    if (payload_len < 6) return false;
    const uint8_t* ad_data = payload + 6;
    size_t ad_len = payload_len - 6;

    // Helper: 16-bit Service UUIDs commonly used by tag ecosystems
    auto is_tag_service_uuid = [](uint16_t uuid) -> bool {
        switch (uuid) {
            case 0xFEAA: // Eddystone
            case 0xFEED: // Tile (commonly)
            case 0xFD5A: // Samsung SmartTag / SmartThings Find (commonly)
            // case 0xFD59: // Samsung (often seen in other states / onboarding)
                return true;
            default:
                return false;
        }
    };
    
    // Parse AD structures: each has [Length][Type][Data...]
    size_t pos = 0;
    while (pos + 1 < ad_len) {
        uint8_t length = ad_data[pos];
        if (length == 0) break;  // End of AD structures
        
        if (pos + 1 + length > ad_len) break;  // Malformed
        
        uint8_t ad_type = ad_data[pos + 1];
        
        // Check for Manufacturer Specific Data (0xFF)
        if (ad_type == 0xFF && length >= 3) {
            // Company ID is 2 bytes, little-endian
            uint16_t company_id = ad_data[pos + 2] | (ad_data[pos + 3] << 8);
            
            // Apple Company ID is 0x004C
            if (company_id == 0x004C && length >= 4) {
                // Check if manufacturer data starts with 0x12
                uint8_t findmy_prefix = ad_data[pos + 4];
                if (findmy_prefix == 0x12 && ad_data[pos + 5] == 0x19) {
                    return true;
                }
            }
        }

        // Check for Service Data - 16-bit UUID (0x16)
        if (ad_type == 0x16 && length >= 3) {
            // Service UUID is 2 bytes, little-endian
            uint16_t svc_uuid = ad_data[pos + 2] | (ad_data[pos + 3] << 8);
            if (is_tag_service_uuid(svc_uuid) && length >= 4) {
                return true;
            }
        }
        
        pos += 1 + length;  // Move to next AD structure
    }
    
    return false;
}

// // Helper function to check if advertising data contains Apple FindMy tag
// // plus common non-Apple tag identifiers via 16-bit Service UUIDs / Service Data.
// static bool is_findmy_tag(const uint8_t* pdu_bytes, size_t pdu_len) {
//     // PDU format: Header(2) + Payload + CRC(3)
//     // We need at least: Header(2) + AdvA(6) + CRC(3) = 11 bytes minimum
//     if (pdu_len < 11) return false;

//     const uint8_t* payload = pdu_bytes + 2;      // Skip PDU header
//     size_t payload_len = pdu_len - 5;            // Exclude header(2) + CRC(3)

//     // Need AdvA (6 bytes)
//     if (payload_len < 6) return false;
//     const uint8_t* ad_data = payload + 6;        // Skip AdvA
//     size_t ad_len = payload_len - 6;

//     // Helper: 16-bit Service UUIDs commonly used by tag ecosystems
//     auto is_tag_service_uuid = [](uint16_t uuid) -> bool {
//         switch (uuid) {
//             case 0xFEAA: // Eddystone
//             case 0xFEED: // Tile (commonly)
//             case 0xFD5A: // Samsung SmartTag / SmartThings Find (commonly)
//             // case 0xFD59: // Samsung (often seen in other states / onboarding)
//                 return true;
//             default:
//                 return false;
//         }
//     };

//     // Parse AD structures: each has [Length][Type][Data...]
//     // 'length' counts bytes following the length byte: [Type + Data...]
//     size_t pos = 0;
//     while (pos < ad_len) {
//         uint8_t length = ad_data[pos];
//         if (length == 0) break;  // End of AD structures

//         size_t struct_total = (size_t)length + 1; // includes the length byte itself
//         if (pos + struct_total > ad_len) break;   // Malformed/truncated

//         if (length < 1) { // must at least contain Type
//             pos += struct_total;
//             continue;
//         }

//         uint8_t ad_type = ad_data[pos + 1];
//         size_t data_start = pos + 2;              // start of Data field
//         size_t data_bytes = (size_t)length - 1;   // bytes available in Data field

//         // --- Apple Find My: Manufacturer Specific Data (0xFF) ---
//         if (ad_type == 0xFF) {
//             // Need at least 2 bytes for Company ID
//             if (data_bytes >= 2) {
//                 uint16_t company_id = (uint16_t)ad_data[data_start]
//                                     | ((uint16_t)ad_data[data_start + 1] << 8);

//                 // Apple Company ID is 0x004C
//                 if (company_id == 0x004C) {
//                     // Your pattern reads two bytes after the company id:
//                     // data_start+2 and data_start+3 => require data_bytes >= 4
//                     if (data_bytes >= 4) {
//                         uint8_t b0 = ad_data[data_start + 2];
//                         uint8_t b1 = ad_data[data_start + 3];
//                         if (b0 == 0x12 && b1 == 0x19) {
//                             return true;
//                         }
//                     }
//                 }
//             }
//         }

//         // --- Non-Apple tags: Service Data - 16-bit UUID (0x16) ---
//         // Format: [UUID LSB][UUID MSB][service data...]
//         if (ad_type == 0x16) {
//             if (data_bytes >= 2) {
//                 uint16_t svc_uuid = (uint16_t)ad_data[data_start]
//                                   | ((uint16_t)ad_data[data_start + 1] << 8);
//                 if (is_tag_service_uuid(svc_uuid)) {
//                     return true;
//                 }
//             }
//         }

//         // // --- Non-Apple tags: 16-bit Service UUID list (0x02/0x03) ---
//         // // Format: repeated 16-bit UUIDs in little-endian
//         // if (ad_type == 0x02 || ad_type == 0x03) {
//         //     if (data_bytes >= 2) {
//         //         for (size_t i = 0; i + 1 < data_bytes; i += 2) {
//         //             uint16_t uuid = (uint16_t)ad_data[data_start + i]
//         //                           | ((uint16_t)ad_data[data_start + i + 1] << 8);
//         //             if (is_tag_service_uuid(uuid)) {
//         //                 return true;
//         //             }
//         //         }
//         //     }
//         // }

//         pos += struct_total;  // Move to next AD structure
//     }

//     return false;
// }

static std::vector<int> extract_bits_from_symbols(const lell_packet& pkt) {
    std::vector<int> bits;
    
    // pkt.symbols contains: AA(4) + Header(2) + Payload(pkt.length) + CRC(3)
    const int total_bytes = 4 + 2 + pkt.length + 3;
    bits.reserve(total_bytes * 8);
    
    // Extract bits in LSB-first order (BLE standard)
    for (int byte_idx = 0; byte_idx < total_bytes; byte_idx++) {
        uint8_t byte = pkt.symbols[byte_idx];
        for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
            bits.push_back((byte >> bit_idx) & 1);
        }
    }
    
    return bits;
}

struct Accum {
    long double Re = 0;
    long double Im = 0;
    size_t n = 0; // number of phase-increment products accumulated
};

static inline void add_prod(Accum& a, const feat::cf& x0, const feat::cf& x1) {
    // z = x[n] * conj(x[n-1])
    auto z = x1 * std::conj(x0);
    a.Re += (long double)z.real();
    a.Im += (long double)z.imag();
    a.n++;
}

static inline double accum_to_cfo(const Accum& a, double fs) {
    if (a.n == 0) return std::numeric_limits<double>::quiet_NaN();
    const double ang = std::atan2((double)a.Im, (double)a.Re);
    return ang * fs / (2.0 * M_PI);
}

// Computes transition CFOs using *phasor sums* (same estimator form as feat::cfo_quick)
// If use_gated=true, it uses iq_gated for transition CFOs + overall recombined CFO,
// so it is directly comparable to feat::cfo_quick(iq_gated, fs).
static void compute_transition_cfos(
    const std::vector<int>& bits,
    const std::vector<feat::cf>& iq_full,     // x_full (ungated)
    const std::vector<feat::cf>& iq_gated,    // x (after gating)
    bool use_gated,                           // match overall CFO window
    int sps,
    double fs,
    double& cfo_equal_00,
    double& cfo_equal_11,
    double& cfo_jump_10,
    double& cfo_jump_01,
    double& cfo_overall_from_transitions      // recombined overall CFO
) {
    cfo_equal_00 = cfo_equal_11 = std::numeric_limits<double>::quiet_NaN();
    cfo_jump_10  = cfo_jump_01  = std::numeric_limits<double>::quiet_NaN();
    cfo_overall_from_transitions = std::numeric_limits<double>::quiet_NaN();

    if (bits.size() < 2 || sps < 1) return;

    const std::vector<feat::cf>& iq = use_gated ? iq_gated : iq_full;
    if (iq.size() < 2) return;

    // IMPORTANT: this assumes iq begins aligned to the first extracted bit in `bits`
    // (AA+Hdr+Payload+CRC bits as you extract them), and PREAMBLE is not included.
    // If your iq slice includes preamble, set PREAMBLE_SAMPLES = 8*sps.
    const size_t PREAMBLE_SAMPLES = 0;  // <- keep consistent with your earlier diagnostic

    Accum A00, A11, A10, A01, Atot;

    // Loop bit-transitions i-1 -> i, map bit i to samples [a,b)
    for (size_t i = 1; i < bits.size(); i++) {
        const size_t a = PREAMBLE_SAMPLES + i * (size_t)sps;       // start of symbol i
        const size_t b = PREAMBLE_SAMPLES + (i + 1) * (size_t)sps; // end of symbol i

        if (b > iq.size()) break;

        Accum* tgt = nullptr;
        if      (bits[i-1] == 0 && bits[i] == 0) tgt = &A00;
        else if (bits[i-1] == 1 && bits[i] == 1) tgt = &A11;
        else if (bits[i-1] == 1 && bits[i] == 0) tgt = &A10;
        else if (bits[i-1] == 0 && bits[i] == 1) tgt = &A01;
        else continue;

        // (1) Boundary product at n=a: includes x[a] * conj(x[a-1])
        // This is crucial so the union of all transition sums can equal cfo_quick(iq,...).
        if (a >= 1 && a < iq.size()) {
            add_prod(*tgt, iq[a - 1], iq[a]);
            add_prod(Atot, iq[a - 1], iq[a]);
        }

        // (2) Products inside the symbol window: n=a+1..b-1
        for (size_t n = a + 1; n < b; n++) {
            add_prod(*tgt, iq[n - 1], iq[n]);
            add_prod(Atot, iq[n - 1], iq[n]);
        }
    }

    // Per-type CFOs (phasor-sum angle)
    cfo_equal_00 = accum_to_cfo(A00, fs);
    cfo_equal_11 = accum_to_cfo(A11, fs);
    cfo_jump_10  = accum_to_cfo(A10, fs);
    cfo_jump_01  = accum_to_cfo(A01, fs);

    // Overall CFO recombined from the same phasor products
    cfo_overall_from_transitions = accum_to_cfo(Atot, fs);

    // // Debug prints: phasor-product counts (not “number of transitions”)
    // std::cout << "[Transition CFO (phasor)] window=" << (use_gated ? "GATED" : "FULL") << "  "
    //           << "counts(products): "
    //           << "00=" << A00.n << ", "
    //           << "11=" << A11.n << ", "
    //           << "10=" << A10.n << ", "
    //           << "01=" << A01.n << ", "
    //           << "total=" << Atot.n
    //           << "\n";

    // std::cout << "[Transition CFO (phasor)] means(Hz): "
    //           << "00=" << cfo_equal_00 << ", "
    //           << "11=" << cfo_equal_11 << ", "
    //           << "10=" << cfo_jump_10  << ", "
    //           << "01=" << cfo_jump_01
    //           << "\n";

    std::cout << "[Transition CFO (phasor)] overall_from_transitions(Hz)="
              << cfo_overall_from_transitions
              << "\n";
}

// // CORRECTED: Account for preamble offset in IQ samples
// static void compute_transition_cfos(
//     const std::vector<int>& bits,
//     const std::vector<feat::cf>& iq_samples,
//     int sps,
//     double fs,
//     double& cfo_equal_00,
//     double& cfo_equal_11,
//     double& cfo_jump_10,
//     double& cfo_jump_01)
// {
//     if (bits.size() < 2 || iq_samples.empty() || sps < 1) {
//         cfo_equal_00 = cfo_equal_11 = std::numeric_limits<double>::quiet_NaN();
//         cfo_jump_10 = cfo_jump_01 = std::numeric_limits<double>::quiet_NaN();
//         return;
//     }
    
//     // CRITICAL: Set based on diagnostic output!
//     // If preamble NOT in iq_samples, use 0
//     // If preamble IS in iq_samples, use 8 * sps
//     const size_t PREAMBLE_SAMPLES = 0;  // ← CHANGE THIS based on diagnostic!
    
//     // Store CFO for each individual transition
//     std::vector<double> cfos_00, cfos_11, cfos_10, cfos_01;
    
//     // Process each bit transition
//     for (size_t i = 1; i < bits.size(); i++) {
//         size_t iq_start = PREAMBLE_SAMPLES + i * sps;
//         size_t iq_end = PREAMBLE_SAMPLES + (i + 1) * sps;
        
//         if (iq_end > iq_samples.size()) break;
        
//         // Extract samples for THIS transition only
//         std::vector<feat::cf> transition_samples;
//         for (size_t idx = iq_start; idx < iq_end; idx++) {
//             transition_samples.push_back(iq_samples[idx]);
//         }
        
//         // Compute CFO for THIS transition (need at least 2 samples)
//         if (transition_samples.size() >= 2) {
//             double cfo = feat::cfo_quick(transition_samples, fs);
            
//             // Store based on transition type
//             if (bits[i-1] == 0 && bits[i] == 0) {
//                 cfos_00.push_back(cfo);
//             } else if (bits[i-1] == 1 && bits[i] == 1) {
//                 cfos_11.push_back(cfo);
//             } else if (bits[i-1] == 1 && bits[i] == 0) {
//                 cfos_10.push_back(cfo);
//             } else if (bits[i-1] == 0 && bits[i] == 1) {
//                 cfos_01.push_back(cfo);
//             }
//         }
//     }
    
//     // Average CFOs per transition type
//     auto compute_mean = [](const std::vector<double>& v) -> double {
//         if (v.empty()) return std::numeric_limits<double>::quiet_NaN();
//         double sum = 0;
//         for (double val : v) sum += val;
//         return sum / v.size();
//     };
    
//     cfo_equal_00 = compute_mean(cfos_00);
//     cfo_equal_11 = compute_mean(cfos_11);
//     cfo_jump_10 = compute_mean(cfos_10);
//     cfo_jump_01 = compute_mean(cfos_01);

//     // Weighted mean across *all* transitions (weights = counts)
//     const size_t n00 = cfos_00.size(), n11 = cfos_11.size(), n10 = cfos_10.size(), n01 = cfos_01.size();
//     const size_t nTot = n00 + n11 + n10 + n01;

//     double weighted_mean_cfo = std::numeric_limits<double>::quiet_NaN();
//     if (nTot > 0) {
//         double sum = 0.0;
//         for (double x : cfos_00) sum += x;
//         for (double x : cfos_11) sum += x;
//         for (double x : cfos_10) sum += x;
//         for (double x : cfos_01) sum += x;
//         weighted_mean_cfo = sum / static_cast<double>(nTot);
//     }

//     // Print counts + per-type means + overall weighted mean
//     std::cout << "Transition counts: "
//               << "00=" << n00 << ", "
//               << "11=" << n11 << ", "
//               << "10=" << n10 << ", "
//               << "01=" << n01
//               << " (total=" << nTot << ")\n";

//     std::cout << "Per-transition CFO means: "
//               << "00=" << cfo_equal_00 << ", "
//               << "11=" << cfo_equal_11 << ", "
//               << "10=" << cfo_jump_10  << ", "
//               << "01=" << cfo_jump_01  << "\n";

//     std::cout << "Overall weighted-mean CFO (by transition counts) = "
//               << weighted_mean_cfo << std::endl;
// }

// static std::vector<int> extract_packet_bits(const lell_packet& pkt) {
//     std::vector<int> bits;
    
//     // Total bits: preamble(8) + AA(32) + header(16) + payload + CRC(24)
//     const int total_bits = 8 + 32 + 16 + (pkt.length * 8) + 24;
//     bits.reserve(total_bits);
    
//     // Preamble: 0xAA (10101010) or 0x55 (01010101) depending on first bit of AA
//     uint8_t preamble = (pkt.access_address & 0x01) ? 0xAA : 0x55;
//     for (int i = 0; i < 8; i++) {
//         bits.push_back((preamble >> (7 - i)) & 1);
//     }
    
//     // Access Address (4 bytes, LSB first in BLE)
//     for (int byte_idx = 0; byte_idx < 4; byte_idx++) {
//         uint8_t byte = pkt.symbols[byte_idx];
//         for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
//             bits.push_back((byte >> bit_idx) & 1);
//         }
//     }
    
//     // Header + Payload + CRC (remaining bytes)
//     const int remaining_bytes = 2 + pkt.length + 3; // header(2) + payload + CRC(3)
//     for (int byte_idx = 0; byte_idx < remaining_bytes; byte_idx++) {
//         uint8_t byte = pkt.symbols[4 + byte_idx];
//         for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
//             bits.push_back((byte >> bit_idx) & 1);
//         }
//     }
    
//     return bits;
// }

// // Compute CFO separately for equal and jump transitions
// static void compute_transition_cfos(
//     const std::vector<int>& bits,
//     const std::vector<feat::cf>& iq_samples,
//     int sps,
//     double fs,
//     double& cfo_equal_00,
//     double& cfo_equal_11,
//     double& cfo_jump_10,
//     double& cfo_jump_01)
// {
//     if (bits.size() < 2 || iq_samples.empty() || sps < 1) {
//         cfo_equal_00 = std::numeric_limits<double>::quiet_NaN();
//         cfo_equal_11 = std::numeric_limits<double>::quiet_NaN();
//         cfo_jump_10 = std::numeric_limits<double>::quiet_NaN();
//         cfo_jump_01 = std::numeric_limits<double>::quiet_NaN();
//         return;
//     }
    
//     std::vector<feat::cf> iq_equal_00;
//     std::vector<feat::cf> iq_equal_11;
//     std::vector<feat::cf> iq_jump_10;
//     std::vector<feat::cf> iq_jump_01;
    
//     // For each bit transition
//     for (size_t i = 1; i < bits.size(); i++) {
//         // Calculate IQ sample range for this bit (symbol)
//         size_t start_idx = (i - 1) * sps;
//         size_t end_idx = i * sps;
        
//         if (end_idx > iq_samples.size()) break;
        
//         // Determine transition type
//         bool is_equal_00 = (bits[i-1] == bits[i] && bits[i] == 0);  // 0→0 or 1→1
//         bool is_equal_11 = (bits[i-1] == bits[i] && bits[i] == 1);  // 0→0 or 1→1
//         bool is_jump_10 = (bits[i-1] == 1 && bits[i] == 0);   // 0→1 or 1→0
//         bool is_jump_01 = (bits[i-1] == 0 && bits[i] == 1);   // 0→1 or 1→0
        
//         // Collect IQ samples for this transition
//         for (size_t idx = start_idx; idx < end_idx; idx++) {
//             if (is_equal_00) {
//                 iq_equal_00.push_back(iq_samples[idx]);
//             } else if (is_equal_11) {
//                 iq_equal_11.push_back(iq_samples[idx]);
//             } else if (is_jump_10) {
//                 iq_jump_10.push_back(iq_samples[idx]);
//             } else if (is_jump_01) {
//                 iq_jump_01.push_back(iq_samples[idx]);
//             }
//         }
//     }
    
//     // Compute CFO for each transition type
//     cfo_equal_00 = (iq_equal_00.size()) >= 8 
//                 ? feat::cfo_quick(iq_equal_00, fs) 
//                 : std::numeric_limits<double>::quiet_NaN();
    
//     cfo_equal_11 = (iq_equal_11.size()) >= 8 
//                 ? feat::cfo_quick(iq_equal_11, fs) 
//                 : std::numeric_limits<double>::quiet_NaN();

//     cfo_jump_10 = (iq_jump_10.size()) >= 8 
//                ? feat::cfo_quick(iq_jump_10, fs) 
//                : std::numeric_limits<double>::quiet_NaN();

//     cfo_jump_01 = (iq_jump_01.size()) >= 8 
//                ? feat::cfo_quick(iq_jump_01, fs) 
//                : std::numeric_limits<double>::quiet_NaN();
    

// }

// ============================================================================
// MAC Address Anonymization Helper Functions
// ============================================================================

// Global HMAC key (generated once at program start)
static std::vector<uint8_t> g_hmac_key;

static void generate_hmac_key() {
    g_hmac_key.resize(32);  // 32 bytes = 256 bits
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    for (auto& byte : g_hmac_key) {
        byte = dis(gen);
    }
    std::fprintf(stderr, "[HMAC] Generated random 256-bit session key\n");
}

static std::string clean_hex(const std::string& hex) {
    std::string result;
    for (char c : hex) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            result += std::tolower(c);
        }
    }
    return result;
}

static std::string hmac_sha256_hide_mac(const std::string& mac_str) {
    if (g_hmac_key.empty() || mac_str.empty()) {
        return mac_str;
    }
    
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    HMAC(EVP_sha256(),
         g_hmac_key.data(), g_hmac_key.size(),
         reinterpret_cast<const unsigned char*>(mac_str.c_str()), mac_str.length(),
         digest, &digest_len);
    
    // Take first 6 bytes and format as MAC address
    char result[18];
    std::snprintf(result, sizeof(result), "%02X:%02X:%02X:%02X:%02X:%02X",
                  digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]);
    
    return std::string(result);
}

static std::string samsung_mac_to_privid(const std::string& payload_hex) {
    // Extract Samsung PRIVID (8 bytes = 16 hex chars) from payload
    // Samsung PRIVID is typically at position 6-13 in the payload after AdvA
    // This is a simplified version; adjust based on actual Samsung structure
    std::string clean = clean_hex(payload_hex);
    if (clean.size() >= 22) {  // Need enough bytes
        return clean.substr(6, 16);  // Extract 8-byte PRIVID
    }
    return "";
}

static std::pair<std::string, std::string> detect_apple_variant_and_mask(const std::string& payload_hex, const std::string& original_mac) {
    // Detect Apple variant manufacturer IDs and return (ground_truth, masked_mac)
    std::string hx = clean_hex(payload_hex);
    
    if (hx.find("4c001219ff") != std::string::npos) {
        return {"ff", "FF:FF:FF:FF:FF:FF"};
    } else if (hx.find("4c001219fc") != std::string::npos) {
        return {"fc", "FC:FC:FC:FC:FC:FC"};
    } else if (hx.find("4c001219fd") != std::string::npos) {
        return {"fd", "FD:FD:FD:FD:FD:FD"};
    } else if (hx.find("4c001219fe") != std::string::npos) {
        return {"fe", "FE:FE:FE:FE:FE:FE"};
    }
    return {"0", original_mac};
}

// ============================================================================
// Attach packet handler
// ============================================================================

// Updated attach_packet_handler
static void attach_packet_handler(BLESDR& b, pcap::Writer& w,
                                  int rf_channel_arg, DumpCtx& dctx) {
    using feat::cf;

    b.callback = [&](lell_packet pkt) {
        // ---------- PCAP packet ----------
        pcap::le_phdr ph{};
        ph.rf_channel = (uint8_t)rf_channel_arg;
        ph.signal_power = 127;
        ph.noise_power  = 127;
        ph.access_address_offenses = pkt.access_address_offenses;
        ph.ref_access_address      = 0x8E89BED6u;
        ph.flags = pcap::LE_FLAG_DEWHITENED |
                   pcap::LE_FLAG_REF_AA_VALID |
                   pcap::LE_FLAG_CRC_CHECKED |
                   pcap::LE_FLAG_CRC_VALID;

        const uint8_t* bytes_aa  = pkt.symbols;
        const uint8_t* bytes_pdu = pkt.symbols + 4;
        const size_t   pdu_len   = (size_t)pkt.length + 5;
        const size_t   frame_len = sizeof(ph) + 4 + pdu_len;
        const int rf_channel = pkt.channel_idx ? pkt.channel_idx : rf_channel_arg;
        ph.rf_channel = (uint8_t)rf_channel;  // overwrite with resolved channel

        std::vector<uint8_t> frame(frame_len);
        std::memcpy(frame.data(), &ph, sizeof(ph));
        std::memcpy(frame.data() + sizeof(ph),     bytes_aa,  4);
        std::memcpy(frame.data() + sizeof(ph) + 4, bytes_pdu, pdu_len);

        // Use sample index to derive packet time so PCAP duration matches capture time
        double ts = (double)pkt.sample_start / dctx.fs_eff;
        w.write_pkt(frame.data(), frame.size(), ts);

        // Basic metadata
        int pdu_type    = (pdu_len >= 2) ? (bytes_pdu[0] & 0x0F) : -1;
        int payload_len = (pdu_len >= 2) ? (bytes_pdu[1] & 0x3F) : 0;

        std::string adv_addr;
        if ((pdu_type == 0 || pdu_type == 2 || pdu_type == 4 || pdu_type == 6) &&
            payload_len >= 6) {
            adv_addr = blehelpers::to_adv_addr(bytes_pdu + 2, pdu_type);
        } else if ((pdu_type == 3 || pdu_type == 5) && payload_len >= 12) {
            adv_addr = blehelpers::to_adv_addr(bytes_pdu + 2, pdu_type);
        }

        std::string aa_be = blehelpers::aa_to_str(pkt.access_address);

        TagType tag_t = detect_tag_type(bytes_pdu, pdu_len);
        std::string tag_type = tagtype_to_cstr(tag_t);
        const bool is_tag_pkt = (tag_t != TagType::UNKNOWN) || is_findmy_tag(bytes_pdu, pdu_len);

        // Payload bytes are bytes_pdu+2 (after 2-byte header), length = payload_len
        std::string payload_hex = (payload_len > 0) ? hexlify(bytes_pdu + 2, (size_t)payload_len) : "";

        // ---------- Check if this is a tag packet we care about ----------
        if (!is_tag_pkt) {
            // Not a recognized tag packet, skip IQ dump + features
            dctx.pkt_idx++;
            return;
        }

        // ---------- Extract exact IQ slice from decoder stamps ----------
        std::vector<cf> x_full;
        const uint64_t prepad_samples = (uint64_t)std::llround(
            dctx.fs_eff * std::max(0, dctx.prepad_us) / 1e6
        );
        uint64_t iq_start = (pkt.sample_start > prepad_samples)
                          ? (pkt.sample_start - prepad_samples)
                          : pkt.sample_start;
        uint64_t iq_end   = pkt.sample_end;

        if (!dctx.ring ||
            !dctx.ring->copy_absolute_window(iq_start, iq_end, x_full)) {
            x_full.clear();
        }

        // Print diagnostic info
        // std::fprintf(stderr,
        //     "[PKT %06zu] ch=%d type=%d len=%d | indices=[%llu,%llu) span=%llu | captured=%zu samples\n",
        //     dctx.pkt_idx, rf_channel, pdu_type, pkt.length,
        //     (unsigned long long)iq_start, (unsigned long long)iq_end,
        //     (unsigned long long)(iq_end - iq_start), x_full.size());

        // ---------- Dump raw IQ chunk ----------
        if (dctx.enabled && !dctx.dir.empty() && !x_full.empty()) {
            std::string mac_safe = adv_addr.empty() ? std::string("NA") : adv_addr;
            std::replace(mac_safe.begin(), mac_safe.end(), ':', '-');
            char fname[512];
            std::snprintf(
                fname, sizeof(fname),
                "%s/ble_pkt_%06zu_%s_%s_ch%02d_%llu_%llu.dat",
                dctx.dir.c_str(),
                (size_t)dctx.pkt_idx,
                tag_type.c_str(),
                mac_safe.c_str(),
                rf_channel,
                (unsigned long long)iq_start,
                (unsigned long long)iq_end
            );
            std::ofstream iq_out(fname, std::ios::binary);
            if (iq_out) {
                for (const auto& z : x_full) {
                    float I = z.real();
                    float Q = z.imag();
                    iq_out.write(reinterpret_cast<const char*>(&I), sizeof(float));
                    iq_out.write(reinterpret_cast<const char*>(&Q), sizeof(float));
                }
                // std::fprintf(stderr, "  -> Saved: %s\n", fname);
            }
        }

        // ---------- Feature window (gated copy of x_full) ----------
        std::vector<cf> x = x_full;

        const size_t prepad_samps = (size_t)std::llround(
            dctx.fs_eff * std::max(0, dctx.prepad_us) / 1e6
        );

        switch (dctx.gate) {
            case GateMode::ENERGY:
                apply_gate_energy(x, dctx.fs_eff, prepad_samps,
                                  dctx.gate_k, dctx.gate_pad_us);
                break;
            case GateMode::STRUCT:
                apply_gate_struct(x, dctx.fs_eff, prepad_samps);
                break;
            case GateMode::MID:
                apply_gate_mid(x, dctx.fs_eff, prepad_samps,
                               dctx.gate_mid_a_us, dctx.gate_mid_b_us);
                break;
            case GateMode::NONE:
            default:
                break;
        }

        double gated_len_us =
            x.empty() ? 0.0 : 1e6 * (double)x.size() / dctx.fs_eff;

        // ---------- RF features ----------
        double fcent=0, pnr_db=0, bw3=0;
        feat::spectral_stats(x, dctx.fs_eff, fcent, pnr_db, bw3);

        double alpha=1.0, phi_deg=0.0;
        feat::iq_imbalance(x, alpha, phi_deg);

        double rt_us = feat::rise_time_us(x, dctx.fs_eff);

        double cfo_q   = feat::cfo_quick(x, dctx.fs_eff);
        double cfo_c   = feat::cfo_centroid(x, dctx.fs_eff, 120e3, 8.0f);
        float  coarse  = std::numeric_limits<float>::quiet_NaN();
        double cfo_two = feat::cfo_two_stage(x, dctx.fs_eff, coarse);
        double cfo_std_all = feat::cfo_std_all(x, dctx.fs_eff);
        double cfo_std_sym = feat::cfo_std_symbol_avg(x, dctx.fs_eff);

        int sps_i = feat::sps_int(dctx.fs_eff);
        auto m_pm1 = joint::recover_symbols(x, sps_i);
        joint::Params p0 = joint::init_from_signal(x, dctx.fs_eff);
        joint::Params p  = p0;
        int iters = 0; double J = 0.0;
        joint::nesterov_fit(m_pm1, sps_i, dctx.fs_eff,
                            x, p, iters, J,
                            0.5, 0.5, 35, 0.2, 0.85);

        // ---------- NEW: Transition-specific CFOs ----------
        double cfo_equal_00 = std::numeric_limits<double>::quiet_NaN();
        double cfo_equal_11 = std::numeric_limits<double>::quiet_NaN();
        double cfo_jump_10 = std::numeric_limits<double>::quiet_NaN();
        double cfo_jump_01 = std::numeric_limits<double>::quiet_NaN();
        double cfo_overall_from_transitions = std::numeric_limits<double>::quiet_NaN();
        
        // Extract bits from packet
        std::vector<int> packet_bits = extract_bits_from_symbols(pkt);

        // // ADD THIS DIAGNOSTIC:
        // size_t expected_with_preamble = (8 + packet_bits.size()) * dctx.sps;
        // size_t expected_no_preamble = packet_bits.size() * dctx.sps;
        // size_t actual = x_full.size();

        // std::fprintf(stderr, "  ALIGNMENT DIAGNOSTIC:\n");
        // std::fprintf(stderr, "    Bits extracted: %zu (AA+Hdr+Payload+CRC, no preamble)\n", packet_bits.size());
        // std::fprintf(stderr, "    IQ samples captured: %zu\n", actual);
        // std::fprintf(stderr, "    Expected WITH preamble: %zu (8 preamble bits + %zu data bits) × %d sps\n", 
        //             expected_with_preamble, packet_bits.size(), dctx.sps);
        // std::fprintf(stderr, "    Expected NO preamble: %zu (%zu data bits × %d sps)\n",
        //             expected_no_preamble, packet_bits.size(), dctx.sps);

        // bool preamble_in_samples = false;
        // if (std::abs((int)actual - (int)expected_no_preamble) < 5) {
        //     std::fprintf(stderr, "    ✓ MATCH: Preamble NOT in x_full\n");
        //     std::fprintf(stderr, "    → MUST set PREAMBLE_SAMPLES = 0 in compute_transition_cfos()\n");
        //     preamble_in_samples = false;
        // } else if (std::abs((int)actual - (int)expected_with_preamble) < 5) {
        //     std::fprintf(stderr, "    ✓ MATCH: Preamble IS in x_full\n");
        //     std::fprintf(stderr, "    → Current PREAMBLE_SAMPLES = 16 is CORRECT\n");
        //     preamble_in_samples = true;
        // } else {
        //     std::fprintf(stderr, "    ✗ NO MATCH! Difference from expected:\n");
        //     std::fprintf(stderr, "       With preamble: %+d samples\n", (int)actual - (int)expected_with_preamble);
        //     std::fprintf(stderr, "       No preamble: %+d samples\n", (int)actual - (int)expected_no_preamble);
        //     std::fprintf(stderr, "    → DECODER BEHAVIOR UNCLEAR - investigate BLESDR\n");
        // }

        // ========== ACCESS ADDRESS VERIFICATION ==========
        uint32_t reconstructed_aa = 0;
        for (int i = 0; i < 32 && i < (int)packet_bits.size(); i++) {
            if (packet_bits[i]) {
                reconstructed_aa |= (1u << i);
            }
        }

        // std::fprintf(stderr, "  AA VERIFICATION:\n");
        // std::fprintf(stderr, "    Original:      0x%08X\n", pkt.access_address);
        // std::fprintf(stderr, "    Reconstructed: 0x%08X\n", reconstructed_aa);

        // if (reconstructed_aa == pkt.access_address) {
        //     std::fprintf(stderr, "    ✓✓✓ PERFECT MATCH! Bit extraction is CORRECT\n");
        // } else {
        //     std::fprintf(stderr, "    ✗✗✗ MISMATCH! Bit extraction is WRONG\n");
        //     std::fprintf(stderr, "    XOR diff: 0x%08X (%d bit errors)\n", 
        //                 reconstructed_aa ^ pkt.access_address,
        //                 __builtin_popcount(reconstructed_aa ^ pkt.access_address));
            
        //     // Test if bit order is reversed
        //     uint32_t aa_reversed = 0;
        //     for (int i = 0; i < 32; i++) {
        //         if (packet_bits[i]) {
        //             aa_reversed |= (1u << (31 - i));
        //         }
        //     }
            
        //     if (aa_reversed == pkt.access_address) {
        //         std::fprintf(stderr, "    → FIX: Change to MSB-first bit extraction\n");
        //     } else {
        //         std::fprintf(stderr, "    → UNKNOWN ERROR in bit extraction\n");
        //     }
        // }

        // // Print bits for manual verification (optional)
        // if (dctx.pkt_idx < 3) {  // Only first 3 packets
        //     std::fprintf(stderr, "    First 32 bits: ");
        //     for (int i = 0; i < 32 && i < (int)packet_bits.size(); i++) {
        //         std::fprintf(stderr, "%d", packet_bits[i]);
        //         if ((i+1) % 8 == 0) std::fprintf(stderr, " ");
        //     }
        //     std::fprintf(stderr, "\n");
        // }
        
        // // Compute CFOs for equal and jump transitions
        // compute_transition_cfos(packet_bits, x_full, dctx.sps, dctx.fs_eff, 
        //                        cfo_equal_00, cfo_equal_11, cfo_jump_10, cfo_jump_01);

        // Compute transition CFOs on the same window you use for overall CFO:
        const bool USE_GATED_FOR_TRANSITIONS = true;

        compute_transition_cfos(
            packet_bits,
            x_full,                    // full IQ slice
            x,                         // gated IQ slice
            USE_GATED_FOR_TRANSITIONS, // match feat::cfo_quick(x,...)
            dctx.sps,
            dctx.fs_eff,
            cfo_equal_00, cfo_equal_11, cfo_jump_10, cfo_jump_01,
            cfo_overall_from_transitions
        );
        
        std::fprintf(stderr, 
            "  -> Transition CFOs: Equal=%.2f Hz, Jump=%.2f Hz\n",
            cfo_equal_00, cfo_equal_11);

        // ---------- Apply MAC transformations (Apple masking, Samsung PRIVID, HMAC) ----------
        std::string original_mac = adv_addr;
        std::string ground_truth_apple = "0";
        
        // Apply Apple variant masking first (if applicable)
        if (tag_t == TagType::APPLE && !payload_hex.empty()) {
            auto [gt, masked] = detect_apple_variant_and_mask(payload_hex, original_mac);
            ground_truth_apple = gt;
            if (gt != "0") {
                adv_addr = masked;
            }
        }
        
        // Apply Samsung PRIVID conversion (if applicable)
        if (tag_t == TagType::SAMSUNG && !payload_hex.empty()) {
            std::string privid = samsung_mac_to_privid(payload_hex);
            if (!privid.empty()) {
                // Format 8-byte PRIVID with colons: XX:XX:XX:XX:XX:XX:XX:XX
                std::string privid_formatted;
                for (size_t i = 0; i < privid.size() && i < 16; i += 2) {
                    if (i > 0) privid_formatted += ":";
                    privid_formatted += std::toupper(privid[i]);
                    privid_formatted += std::toupper(privid[i + 1]);
                }
                adv_addr = privid_formatted;
            }
        }
        
        // Apply HMAC-based MAC hiding to all packets
        if (!original_mac.empty()) {
            adv_addr = hmac_sha256_hide_mac(adv_addr);
        }

        FeatureRow row{
            dctx.pkt_idx, ts, rf_channel, pdu_type, adv_addr, aa_be,
            tag_type, ground_truth_apple, "",  // NEW: added ground_truth_apple, empty payload_hex
            cfo_q, cfo_c, cfo_two, cfo_std_all, cfo_std_sym,
            alpha, phi_deg, rt_us, fcent, pnr_db, bw3, gated_len_us,
            (double)coarse,
            p.fo_hz, p.I0, p.Q0, p.eps,
            p.phi * 180.0 / M_PI, p.A, iters, J,
            pkt.cfo_exact_quick_hz, pkt.cfo_exact_ls_hz,
            iq_start, iq_end,
            cfo_equal_00, cfo_equal_11, cfo_jump_10, cfo_jump_01  // NEW fields
        };

        if (dctx.featcsv) dctx.featcsv->row(row);

        dctx.pkt_idx++;
    };
}

// static void attach_packet_handler(BLESDR& b, pcap::Writer& w,
//                                   int rf_channel, DumpCtx& dctx) {
//     using feat::cf;

//     b.callback = [&](lell_packet pkt) {
//         // ---------- PCAP packet ----------
//         pcap::le_phdr ph{};
//         ph.rf_channel = (uint8_t)rf_channel;
//         ph.signal_power = 127;
//         ph.noise_power  = 127;
//         ph.access_address_offenses = pkt.access_address_offenses;
//         ph.ref_access_address      = 0x8E89BED6u;
//         ph.flags = pcap::LE_FLAG_DEWHITENED |
//                    pcap::LE_FLAG_REF_AA_VALID |
//                    pcap::LE_FLAG_CRC_CHECKED |
//                    pcap::LE_FLAG_CRC_VALID;

//         const uint8_t* bytes_aa  = pkt.symbols;
//         const uint8_t* bytes_pdu = pkt.symbols + 4;
//         const size_t   pdu_len   = (size_t)pkt.length + 5;
//         const size_t   frame_len = sizeof(ph) + 4 + pdu_len;

//         std::vector<uint8_t> frame(frame_len);
//         std::memcpy(frame.data(), &ph, sizeof(ph));
//         std::memcpy(frame.data() + sizeof(ph),     bytes_aa,  4);
//         std::memcpy(frame.data() + sizeof(ph) + 4, bytes_pdu, pdu_len);

//         double ts = w.write_pkt(frame.data(), frame.size());

//         // Basic metadata
//         int pdu_type    = (pdu_len >= 2) ? (bytes_pdu[0] & 0x0F) : -1;
//         int payload_len = (pdu_len >= 2) ? (bytes_pdu[1] & 0x3F) : 0;

//         std::string adv_addr;
//         if ((pdu_type == 0 || pdu_type == 2 || pdu_type == 4 || pdu_type == 6) &&
//             payload_len >= 6) {
//             adv_addr = blehelpers::to_adv_addr(bytes_pdu + 2, pdu_type);
//         } else if ((pdu_type == 3 || pdu_type == 5) && payload_len >= 12) {
//             adv_addr = blehelpers::to_adv_addr(bytes_pdu + 2, pdu_type);
//         }

//         std::string aa_be = blehelpers::aa_to_str(pkt.access_address);

//         // ---------- Check if this is a FindMy tag ----------
//         if (!is_findmy_tag(bytes_pdu, pdu_len)) {
//             // Not a FindMy tag, skip feature extraction
//             dctx.pkt_idx++;
//             return;
//         }

//         // ---------- Extract exact IQ slice from decoder stamps ----------
//         std::vector<cf> x_full;
//         uint64_t iq_start = pkt.sample_start;
//         uint64_t iq_end   = pkt.sample_end;

//         if (!dctx.ring ||
//             !dctx.ring->copy_absolute_window(iq_start, iq_end, x_full)) {
//             x_full.clear();
//         }

//         // Print diagnostic info
//         std::fprintf(stderr,
//             "[PKT %06zu] ch=%d type=%d len=%d | indices=[%llu,%llu) span=%llu | captured=%zu samples\n",
//             dctx.pkt_idx, rf_channel, pdu_type, pkt.length,
//             (unsigned long long)iq_start, (unsigned long long)iq_end,
//             (unsigned long long)(iq_end - iq_start), x_full.size());

//         // ---------- Dump raw IQ chunk ----------
//         if (dctx.enabled && !dctx.dir.empty() && !x_full.empty()) {
//             char fname[512];
//             std::snprintf(
//                 fname, sizeof(fname),
//                 "%s/ble_pkt_%06zu_ch%02d_%llu_%llu.dat",
//                 dctx.dir.c_str(),
//                 (size_t)dctx.pkt_idx,
//                 rf_channel,
//                 (unsigned long long)iq_start,
//                 (unsigned long long)iq_end
//             );
//             std::ofstream iq_out(fname, std::ios::binary);
//             if (iq_out) {
//                 for (const auto& z : x_full) {
//                     float I = z.real();
//                     float Q = z.imag();
//                     iq_out.write(reinterpret_cast<const char*>(&I), sizeof(float));
//                     iq_out.write(reinterpret_cast<const char*>(&Q), sizeof(float));
//                 }
//                 std::fprintf(stderr, "  -> Saved: %s\n", fname);
//             }
//         }

//         // ---------- Feature window (gated copy of x_full) ----------
//         std::vector<cf> x = x_full;

//         const size_t prepad_samps = (size_t)std::llround(
//             dctx.fs_eff * std::max(0, dctx.prepad_us) / 1e6
//         );

//         switch (dctx.gate) {
//             case GateMode::ENERGY:
//                 apply_gate_energy(x, dctx.fs_eff, prepad_samps,
//                                   dctx.gate_k, dctx.gate_pad_us);
//                 break;
//             case GateMode::STRUCT:
//                 apply_gate_struct(x, dctx.fs_eff, prepad_samps);
//                 break;
//             case GateMode::MID:
//                 apply_gate_mid(x, dctx.fs_eff, prepad_samps,
//                                dctx.gate_mid_a_us, dctx.gate_mid_b_us);
//                 break;
//             case GateMode::NONE:
//             default:
//                 break;
//         }

//         double gated_len_us =
//             x.empty() ? 0.0 : 1e6 * (double)x.size() / dctx.fs_eff;

//         // ---------- RF features ----------
//         double fcent=0, pnr_db=0, bw3=0;
//         feat::spectral_stats(x, dctx.fs_eff, fcent, pnr_db, bw3);

//         double alpha=1.0, phi_deg=0.0;
//         feat::iq_imbalance(x, alpha, phi_deg);

//         double rt_us = feat::rise_time_us(x, dctx.fs_eff);

//         double cfo_q   = feat::cfo_quick(x, dctx.fs_eff);
//         double cfo_c   = feat::cfo_centroid(x, dctx.fs_eff, 120e3, 8.0f);
//         float  coarse  = std::numeric_limits<float>::quiet_NaN();
//         double cfo_two = feat::cfo_two_stage(x, dctx.fs_eff, coarse);
//         double cfo_std_all = feat::cfo_std_all(x, dctx.fs_eff);
//         double cfo_std_sym = feat::cfo_std_symbol_avg(x, dctx.fs_eff);

//         int sps_i = feat::sps_int(dctx.fs_eff);
//         auto m_pm1 = joint::recover_symbols(x, sps_i);
//         joint::Params p0 = joint::init_from_signal(x, dctx.fs_eff);
//         joint::Params p  = p0;
//         int iters = 0; double J = 0.0;
//         joint::nesterov_fit(m_pm1, sps_i, dctx.fs_eff,
//                             x, p, iters, J,
//                             0.5, 0.5, 35, 0.2, 0.85);

//         FeatureRow row{
//             dctx.pkt_idx, ts, rf_channel, pdu_type, adv_addr, aa_be,
//             cfo_q, cfo_c, cfo_two, cfo_std_all, cfo_std_sym,
//             alpha, phi_deg, rt_us, fcent, pnr_db, bw3, gated_len_us,
//             (double)coarse,
//             p.fo_hz, p.I0, p.Q0, p.eps,
//             p.phi * 180.0 / M_PI, p.A, iters, J,
//             pkt.cfo_exact_quick_hz, pkt.cfo_exact_ls_hz,
//             iq_start, iq_end
//         };

//         if (dctx.featcsv) dctx.featcsv->row(row);

//         dctx.pkt_idx++;
//     };
// }

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    Args args = parse(argc, argv);
    
    // Generate HMAC key for session
    generate_hmac_key();

    std::FILE* f = std::fopen(args.file.c_str(), "rb");
    if (!f) die(std::string("cannot open file: ") + args.file + " : " + std::strerror(errno));

    const double fs_eff = args.fs / args.decim;
    const int sps = std::max(2, (int)std::lround(fs_eff / 1e6));

    if (!args.dump_iq_dir.empty()) {
        std::string cmd = "mkdir -p '" + args.dump_iq_dir + "'";
        (void)std::system(cmd.c_str());
    }

    pcap::Writer w(args.out);
    FeatureCSV featcsv(args.features_out);

    std::vector<float> bufIQ(2*args.chunk);
    std::vector<float> workIQ;

    Ring ring;
    ring.init((size_t)(fs_eff * 1.0)); // 250 ms ring

    BLESDR blesdr;

    DumpCtx dctx;
    dctx.enabled   = !args.dump_iq_dir.empty();
    dctx.dir       = args.dump_iq_dir;
    dctx.sps       = sps;
    dctx.fs_eff    = fs_eff;
    dctx.prepad_us = args.prepad_us;
    dctx.ring      = &ring;
    dctx.ring_abs_head = 0;
    dctx.pkt_idx   = 0;
    dctx.featcsv   = &featcsv;
    dctx.gate      = args.gate;
    dctx.gate_k    = args.gate_k;
    dctx.gate_pad_us   = args.gate_pad_us;
    dctx.gate_mid_a_us = args.gate_mid_a_us;
    dctx.gate_mid_b_us = args.gate_mid_b_us;

    blesdr.Configure(sps, (uint8_t)args.channel, 0);

    // IQ provider: uses absolute complex indices
    blesdr.set_iq_provider([&](uint64_t a, uint64_t b,
                               std::vector<std::complex<float>>& out) {
        return ring.copy_absolute_window(a, b, out);
    });

    attach_packet_handler(blesdr, w, args.channel, dctx);

    auto decimate_cplx = [](const float* inIQ, size_t n_cplx, int decim,
                            std::vector<float>& outIQ)->size_t {
        if (decim <= 1) {
            outIQ.assign(inIQ, inIQ + 2*n_cplx);
            return n_cplx;
        }
        size_t outN = 0;
        outIQ.resize(2*((n_cplx + decim - 1)/decim));
        for (size_t i=0;i<n_cplx;i+= (size_t)decim) {
            outIQ[2*outN]   = inIQ[2*i];
            outIQ[2*outN+1] = inIQ[2*i+1];
            outN++;
        }
        outIQ.resize(2*outN);
        return outN;
    };

    uint64_t total_complex = 0;
    uint64_t total_complex_fed = 0;

    while (true) {
        size_t nread_cplx = std::fread(bufIQ.data(), sizeof(float)*2, args.chunk, f);
        if (nread_cplx == 0) break;

        size_t n_cplx_out = decimate_cplx(bufIQ.data(), nread_cplx, args.decim, workIQ);

        // Simple DC removal + normalization
        {
            double meanI=0, meanQ=0;
            for (size_t i=0;i<n_cplx_out;i++){
                meanI += workIQ[2*i];
                meanQ += workIQ[2*i+1];
            }
            if (n_cplx_out) { meanI/=n_cplx_out; meanQ/=n_cplx_out; }
            double e=0;
            for (size_t i=0;i<n_cplx_out;i++){
                workIQ[2*i]   = float(workIQ[2*i]   - meanI);
                workIQ[2*i+1] = float(workIQ[2*i+1] - meanQ);
                e += (double)workIQ[2*i]*workIQ[2*i] + (double)workIQ[2*i+1]*workIQ[2*i+1];
            }
            e = std::sqrt(e / std::max<double>(2.0*n_cplx_out,1.0));
            if (e > 1e-12) {
                for (size_t i=0;i<n_cplx_out;i++){
                    workIQ[2*i]   = float(workIQ[2*i]   / e);
                    workIQ[2*i+1] = float(workIQ[2*i+1] / e);
                }
            }
        }

        uint64_t chunk_start = dctx.ring_abs_head;
   
        for (size_t i=0;i<n_cplx_out;i++) {
            ring.push(workIQ[2*i], workIQ[2*i+1]);
            dctx.ring_abs_head++;
        }
        
        blesdr.set_abs_cursor(chunk_start);
        blesdr.Receiver((size_t)args.channel, workIQ.data(), n_cplx_out);
        dctx.ring_abs_head = blesdr.get_abs_cursor();

        total_complex     += nread_cplx;
        total_complex_fed += n_cplx_out;
    }

    std::fclose(f);

    std::cerr << "\nDone. Complex read: " << total_complex
              << ", complex fed: " << total_complex_fed
              << ", packets: " << dctx.pkt_idx
              << "\nPCAP: " << args.out
              << "\nFeatures: " << args.features_out
              << "\n";

    return 0;
}