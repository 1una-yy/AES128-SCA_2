"""
attacks/template.py
Template Attack（v2：以 Hamming Weight 分 9 群 + POI 選取）攻擊模組。

輸入比其他演算法多兩個檔案：
  - template_traces_file     : 建模板用的 traces（10000 條，隨機金鑰）
  - template_plaintexts_file : 建模板用的明文
  - template_keys_file       : 建模板用的金鑰
  - traces_file              : 攻擊目標 traces（100 條，固定金鑰）
  - plaintexts_file          : 攻擊目標明文
"""

import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import multivariate_normal
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from attack_base import BaseAttack, AttackInput, AttackResult, registry

AES_Sbox = np.array([
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
])

hw_list       = np.array([bin(i).count('1') for i in range(256)])
hw_combinations = np.array([1, 8, 28, 56, 70, 56, 28, 8, 1])


class TemplateAttack(BaseAttack):
    name         = "template"
    display_name = "Template Attack (HW 分群)"
    description  = (
        "以 HW 分 9 群建立模板，再以最大似然估計攻擊目標 traces。"
        "需要額外提供 template_traces / template_plaintexts / template_keys 三個檔案。"
    )
    POI_NUM = 10   # 每個 byte 選幾個 POI

    def validate(self, data: AttackInput):
        super().validate(data)
        if data.template_traces is None or data.template_plaintexts is None or data.template_keys is None:
            raise ValueError(
                "Template Attack 需要額外三個模板檔案："
                "template_traces_file、template_plaintexts_file、template_keys_file"
            )

    def run(self, data: AttackInput) -> AttackResult:
        self.validate(data)

        # 攻擊目標
        target_t = (data.preprocessed_traces if data.preprocessed_traces is not None
                    else data.traces).astype(np.float64)
        target_p = data.plaintexts.astype(np.uint8)
        target_num, trace_length = target_t.shape

        # 模板資料
        tmpl_t = data.template_traces.astype(np.float64)
        tmpl_p = data.template_plaintexts.astype(np.uint8)
        tmpl_k = data.template_keys.astype(np.uint8)
        tmpl_num = tmpl_t.shape[0]

        # ── 步驟 1：計算 SNR，找 POI ────────────────────────────
        tmpl_x = tmpl_p ^ tmpl_k                    # 明文 XOR 金鑰
        tmpl_y = AES_Sbox[tmpl_x]                   # SBox 轉換
        tmpl_h = hw_list[tmpl_y]                     # Hamming Weight

        var  = np.zeros((16, trace_length))
        avg  = np.zeros((16, trace_length))
        count = np.zeros((16, 9), dtype=int)
        avg_diff_HW = np.zeros((16, 9, trace_length))

        for b in range(16):
            t_sum  = np.zeros((9, trace_length))
            t2_sum = np.zeros((9, trace_length))

            for j in range(tmpl_num):
                hw = tmpl_h[j, b]
                t_sum[hw]  += tmpl_t[j]
                t2_sum[hw] += tmpl_t[j] ** 2
                count[b, hw] += 1

            prob = count[b] / tmpl_num
            avg_t = np.zeros((9, trace_length))
            var_t = np.zeros((9, trace_length))

            for j in range(9):
                if count[b, j] > 0:
                    avg_t[j] = t_sum[j] / count[b, j]
                    var_t[j] = t2_sum[j] / count[b, j] - avg_t[j] ** 2

            var[b] = (np.sum((avg_t ** 2) * prob[:, None], axis=0)
                      - np.sum(avg_t * prob[:, None], axis=0) ** 2 + 1e-40)
            avg[b] = np.sum(var_t * prob[:, None], axis=0) + 1e-40
            avg_diff_HW[b] = avg_t

        SNR = var / avg  # shape: (16, trace_length)

        # ── 步驟 2：建模板（mean + covariance per byte per HW） ──
        poi_index = np.argsort(SNR, axis=1)[:, -self.POI_NUM:]  # shape: (16, POI_NUM)
        mean       = np.zeros((16, 9, self.POI_NUM))
        covariance = np.zeros((16, 9, self.POI_NUM, self.POI_NUM))

        for b in range(16):
            tmpl_poi = tmpl_t[:, poi_index[b]]      # shape: (tmpl_num, POI_NUM)
            for hw in range(9):
                g = tmpl_poi[tmpl_h[:, b] == hw]
                if len(g) >= 2:
                    mean[b, hw]       = np.mean(g, axis=0)
                    covariance[b, hw] = np.cov(g, rowvar=False)

        # ── 步驟 3：攻擊 ────────────────────────────────────────
        key_log_prob = np.zeros((16, 256))
        Guess_Key    = np.zeros(16, dtype=int)

        for i in range(target_num):
            for b in range(16):
                target_poi = target_t[i, poi_index[b]]  # shape: (POI_NUM,)
                hw_log_prob = np.zeros(9)

                for hw in range(9):
                    try:
                        pdf = multivariate_normal.pdf(
                            target_poi,
                            mean=mean[b, hw],
                            cov=covariance[b, hw],
                            allow_singular=True
                        )
                    except Exception:
                        pdf = 1e-300
                    hw_log_prob[hw] = np.log(pdf / (hw_combinations[hw] + 1e-300) + 1e-300)

                # 把 hw_log_prob 展開到所有 256 個金鑰假設
                sbox_hw = hw_list[AES_Sbox[np.arange(256) ^ target_p[i, b]]]
                key_log_prob[b] += hw_log_prob[sbox_hw]

        for b in range(16):
            Guess_Key[b] = int(np.argmax(key_log_prob[b]))

        # ── 畫圖：SNR ──────────────────────────────────────────
        fig, axes = plt.subplots(4, 4, figsize=(24, 16))
        for b in range(16):
            ax = axes[b // 4, b % 4]
            ax.plot(SNR[b])
            ax.set_title(f"Byte {b} SNR")
            ax.set_xlabel("Samples")
            ax.set_ylabel("SNR")
        plt.suptitle("Template Attack — SNR per Byte", fontsize=14)
        plt.tight_layout()

        return AttackResult(
            algorithm    = self.name,
            key_hex      = bytes(Guess_Key.tolist()).hex(),
            key_bytes    = Guess_Key.tolist(),
            num_traces   = target_num,
            trace_length = trace_length,
            plot_base64  = self.plot_to_base64(fig),
            extra        = {"template_traces_used": tmpl_num, "poi_num": self.POI_NUM},
        )


registry.register(TemplateAttack())
