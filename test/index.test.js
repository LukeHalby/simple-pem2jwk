import pem2jwk from '../src/index.js'

const pkcs1KeyPairs = [
  {
    privateKey: {
      pem: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAm0J0vh6lhop4IAbEyS5uvBuPPN38hAah9EcYNEC6TYnzu9fm
lmxjf3xZAKXPPQbn3S31T+OgnrSB1hZvUySOdxK3NlmKTZn9Okdc8N+46ITKZBhJ
2cyfVTWO+N91IWSZERKwcFc+A7s+p7BdzCOhKdCRWxSJi/OV6Qbd2C/JbS9v/Aic
8dN9fr2mRUm9sgR2WZOeWt8U58AsU8+Wh3BHHMJE2C1IJCERmFG0C9vSiRTgz8hE
Wb6IJz50kH1vCg9Fx9RoVcZOPVaFQ3rK9bCnsuYaWvzYm2QlIqF339u0M/uJpCBO
6MEDkSkqsov78MpPho09J9k0hBL0Zlo6+KQV9QIDAQABAoIBAAwTC0K03fEcaDKv
bBLsSELbTtSwO+Dlpic59zUrGoIIujqP1Bg7NjK2MDLHclo/5PzTw+nyXS2ygo1s
gbxg0a6Ld1Gj/YhC80lavuzhrT7yAs5tgCLO0c5d47BRqomOCgRkpHGcK0+9emYu
pmDHnZNDq+Y+LuNCLpSoisyzDLJvuLAgI/FKSjXPucEc6aDQbz1c8Wt0rLxB63Ok
4QsKCicDsCKQ8cgY1dHYIht6iWFIUtsbroXCQGlTf5FMBeaAOj6cun+ujdpiKazg
ylhRDehclfjx7kH5knjSlO/j/ZKpZbaE56FlDVcI06rhd08WDEPqBLpCOCtixfj9
bf/iFBECgYEA08xG2LFoPsLsIGRoKQoa2SjLWccna+gxiQPImKQLpJnWMy7O+6T4
LheyWGcUh7coD3xiI4OMPDf2h/fSPdrW80/WGtM2fxOwPak0xJ3/jiIGMZvd8/pJ
mOkxHA4lJw6FRXF0qYqS2zoDxVG8jtDCRoFVxsQBHizcUW+yEtqgNrECgYEAu6mB
fxDhATlqwMQ0gfjjv0fNfW2AbL2TJeCXnTdB3gqiRsPY3OztZc9oWR00pVpIumZr
woLnj60I3kEEItsOcdgeZJglBca8sOdc4UGb6t7d26+K0rPfWBSRm/MEmFbs8viD
VJYJjfwzIsPqhwClYdaNlX4Nok76mJQDiODlbIUCgYBu14d0PFQsFGLzCNkiMTGf
2KOjloBhDqFt7Vb7205klEXvf12/gLSJmskxTrEF3arPf+70WxH3KeqRefbDfFXl
/DA21ba9hpZDjtwY0f8+aTwIlmPwHVqK9e9HmXeEGytQDnJZkDYPGSuEBqTBsSsb
LvCvF0Dmg9/Bls0A5P3X4QKBgCJgMYV6LQ1RXDnFdyzbz7RJTd4NAfppW5wToRI+
fgVTg1hdJcuKZw5ASQgR7oPfnvTuMA0od4x9EOPNmxlbcTDvetnIePeu6P+q0fu9
TfdfLdrBNDfWlTIISof7ozrYqXz0gvIqrcNhkGhs5Pgn6SOb7sGUnqC9wO/UJTWc
pMoVAoGBAM/FjHznsXwjqsPhKQTgD2x33qwcfYP/Ox2U9goStfVBkuRNO3MSEr2b
2QUjKVAqgrCnTJagrAGRJSHXYUEXKsauAyzPSJl6Uhg62fhXH5IR9oN5ftEjdsy+
+wxWknakgLQvr8Rqpi6orsyZRClr0e+BMRbC5SnJpMsfF0luZhvX
-----END RSA PRIVATE KEY-----`,
      jwk: {
        p: '08xG2LFoPsLsIGRoKQoa2SjLWccna-gxiQPImKQLpJnWMy7O-6T4LheyWGcUh7coD3xiI4OMPDf2h_fSPdrW80_WGtM2fxOwPak0xJ3_jiIGMZvd8_pJmOkxHA4lJw6FRXF0qYqS2zoDxVG8jtDCRoFVxsQBHizcUW-yEtqgNrE',
        kty: 'RSA',
        q: 'u6mBfxDhATlqwMQ0gfjjv0fNfW2AbL2TJeCXnTdB3gqiRsPY3OztZc9oWR00pVpIumZrwoLnj60I3kEEItsOcdgeZJglBca8sOdc4UGb6t7d26-K0rPfWBSRm_MEmFbs8viDVJYJjfwzIsPqhwClYdaNlX4Nok76mJQDiODlbIU',
        d: 'DBMLQrTd8RxoMq9sEuxIQttO1LA74OWmJzn3NSsaggi6Oo_UGDs2MrYwMsdyWj_k_NPD6fJdLbKCjWyBvGDRrot3UaP9iELzSVq-7OGtPvICzm2AIs7Rzl3jsFGqiY4KBGSkcZwrT716Zi6mYMedk0Or5j4u40IulKiKzLMMsm-4sCAj8UpKNc-5wRzpoNBvPVzxa3SsvEHrc6ThCwoKJwOwIpDxyBjV0dgiG3qJYUhS2xuuhcJAaVN_kUwF5oA6Ppy6f66N2mIprODKWFEN6FyV-PHuQfmSeNKU7-P9kqlltoTnoWUNVwjTquF3TxYMQ-oEukI4K2LF-P1t_-IUEQ',
        e: 'AQAB',
        qi: 'z8WMfOexfCOqw-EpBOAPbHferBx9g_87HZT2ChK19UGS5E07cxISvZvZBSMpUCqCsKdMlqCsAZElIddhQRcqxq4DLM9ImXpSGDrZ-FcfkhH2g3l-0SN2zL77DFaSdqSAtC-vxGqmLqiuzJlEKWvR74ExFsLlKcmkyx8XSW5mG9c',
        dp: 'bteHdDxULBRi8wjZIjExn9ijo5aAYQ6hbe1W-9tOZJRF739dv4C0iZrJMU6xBd2qz3_u9FsR9ynqkXn2w3xV5fwwNtW2vYaWQ47cGNH_Pmk8CJZj8B1aivXvR5l3hBsrUA5yWZA2DxkrhAakwbErGy7wrxdA5oPfwZbNAOT91-E',
        dq: 'ImAxhXotDVFcOcV3LNvPtElN3g0B-mlbnBOhEj5-BVODWF0ly4pnDkBJCBHug9-e9O4wDSh3jH0Q482bGVtxMO962ch4967o_6rR-71N918t2sE0N9aVMghKh_ujOtipfPSC8iqtw2GQaGzk-CfpI5vuwZSeoL3A79QlNZykyhU',
        n: 'm0J0vh6lhop4IAbEyS5uvBuPPN38hAah9EcYNEC6TYnzu9fmlmxjf3xZAKXPPQbn3S31T-OgnrSB1hZvUySOdxK3NlmKTZn9Okdc8N-46ITKZBhJ2cyfVTWO-N91IWSZERKwcFc-A7s-p7BdzCOhKdCRWxSJi_OV6Qbd2C_JbS9v_Aic8dN9fr2mRUm9sgR2WZOeWt8U58AsU8-Wh3BHHMJE2C1IJCERmFG0C9vSiRTgz8hEWb6IJz50kH1vCg9Fx9RoVcZOPVaFQ3rK9bCnsuYaWvzYm2QlIqF339u0M_uJpCBO6MEDkSkqsov78MpPho09J9k0hBL0Zlo6-KQV9Q'
      }
    },
    publicKey: {
      pem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAm0J0vh6lhop4IAbEyS5uvBuPPN38hAah9EcYNEC6TYnzu9fmlmxj
f3xZAKXPPQbn3S31T+OgnrSB1hZvUySOdxK3NlmKTZn9Okdc8N+46ITKZBhJ2cyf
VTWO+N91IWSZERKwcFc+A7s+p7BdzCOhKdCRWxSJi/OV6Qbd2C/JbS9v/Aic8dN9
fr2mRUm9sgR2WZOeWt8U58AsU8+Wh3BHHMJE2C1IJCERmFG0C9vSiRTgz8hEWb6I
Jz50kH1vCg9Fx9RoVcZOPVaFQ3rK9bCnsuYaWvzYm2QlIqF339u0M/uJpCBO6MED
kSkqsov78MpPho09J9k0hBL0Zlo6+KQV9QIDAQAB
-----END RSA PUBLIC KEY-----`,
      jwk: {
        kty: 'RSA',
        e: 'AQAB',
        n: 'm0J0vh6lhop4IAbEyS5uvBuPPN38hAah9EcYNEC6TYnzu9fmlmxjf3xZAKXPPQbn3S31T-OgnrSB1hZvUySOdxK3NlmKTZn9Okdc8N-46ITKZBhJ2cyfVTWO-N91IWSZERKwcFc-A7s-p7BdzCOhKdCRWxSJi_OV6Qbd2C_JbS9v_Aic8dN9fr2mRUm9sgR2WZOeWt8U58AsU8-Wh3BHHMJE2C1IJCERmFG0C9vSiRTgz8hEWb6IJz50kH1vCg9Fx9RoVcZOPVaFQ3rK9bCnsuYaWvzYm2QlIqF339u0M_uJpCBO6MEDkSkqsov78MpPho09J9k0hBL0Zlo6-KQV9Q'
      }
    }
  },
  {
    privateKey: {
      pem: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4aOc6ck9Wh0+PfG4gCsMSaZT9nE+NXxQ8iSbocelFf+ViJE4
vCcEk/1iU4+bEahtem6mBSN+rCUHACg0fWH1GzTmpmUTZFsbLXAWkMuJk+FXAy5d
fXPFUQhE6cZbcrqYke5T5tbXExnu39OR/F+c6hvXahPsfDpIPF9BJ7GA6c3brMCh
1jTYiuk5xAmOLobsC/McgsEhWgHEwv1f85fs5Sn0CHi6OGISpntG0TA7oAnnktfA
xIb+f3ZnaHfPBq6z4/jJjXt0wM/4sxqjvzirI6Wewk0jxQsCsEhE4v251OHectui
HWnG48xpxqHrKEa9LE79x4a2XBLt3RV2NNLpRwIDAQABAoIBAAxMUp0bbtCej2no
5tl1fzH0ctcXzQA1SmQoQqNKsmDEkW3kHGeE6Ob4BIfxZ85Kk8z8guf8y0aurfcA
OfwrfqSA+aFQGQJ7RLvxRAmYTmNVAN0Xhdj0mmiUPs1PFmTmbrJlfwUx6H8OBssE
SQysWW0ZH2CUvWr38j/4ISD8t74GdCJbrKA7R0txaNbSyZCD/9j/MGEPqq6KGMPb
OrAPWY8sNRbAypEPhqi5tsViw6eI2fJR92X4KYNgrlyf8fSh5V85ZESviwcXkW3C
8RUcN+hi+CYpIMsnqjaB4Rd7pZASKIfmG8ANOmMDLUbOpuZJX88pbRwqS2Rtx447
9aeJFaECgYEA9S4smD5aWbbh5gtYxY6yrp0dglwCFBJcgzLS1OWn5PMYBZZlQDPU
0pVTpE6GECXqBv3sYA0N3gG2hXL17dx+8aDFnlO/sCOMFf/ddxbkg+yDwlKlNmBN
OX5JesFoWBztOJUcaOdnXDJJi1VM70GH/VtXP5UsuDyMBLiRYD/sC3UCgYEA65it
6TSrzS6RMnNXmajj+yPLeE5N1YHI2oHVN/hKgQcoRfSqLDJFB0maVy38XunkJJU2
XP6ZjuTLgvntxVDl8J+Y+XtlNoWSZZ1s2F8iMuz20lJS3Cw70xK9vkeog5D86xgK
EhGIHmu8waISWm/Bdz/SdLGtclFTBhiCqQ6BlksCgYEA4Fx0qozEmTxl0+GmRoKi
uG9GRbh0nnF+/wBPNktCLJzX6qUJ2oqTwnCrrbu9qqFHW0aaO/s2KWZf5BajPht8
fxikPpJc445j7u3Jd+UXEDIrEHQYg330rRwHmbHLDnbKDfFFoim/x/qsmjhgwsCw
9QPU/3Y/Cgk+CEPtpKpaEtECgYEAtPGYcEnRwU6ImbTYjN2X62R8ezO4t8hsGNYq
ikgaAKsclU3p/PPG7GftMBPThpogbLBlBltMWOEEJN4LbcZKM9p/xOyuuYcw/vY/
iJbYT0CL+NDdbthSQjRcom2q0RFkDrNx2Jq6bpLUb+soKWk3r3zHCHUF/4zSNRZS
E8Feaa0CgYBLkLeNvUqdvf5oq1lmbLL0lNfgQU4VwsAF0Cyg8HPt3mTXgAA29sgN
CBwEuU85YlBWpDdvdbsYv9Pa4uhn0FNJvbM42vKQH//cgxHDMLHTLmqG7DnTIgTy
pRPSlnhfkr82agPZ22QN9mMUHT173+S0kEOwvrk6pDArArUEVBTXKg==
-----END RSA PRIVATE KEY-----`,
      jwk: {
        p: '9S4smD5aWbbh5gtYxY6yrp0dglwCFBJcgzLS1OWn5PMYBZZlQDPU0pVTpE6GECXqBv3sYA0N3gG2hXL17dx-8aDFnlO_sCOMFf_ddxbkg-yDwlKlNmBNOX5JesFoWBztOJUcaOdnXDJJi1VM70GH_VtXP5UsuDyMBLiRYD_sC3U',
        kty: 'RSA',
        q: '65it6TSrzS6RMnNXmajj-yPLeE5N1YHI2oHVN_hKgQcoRfSqLDJFB0maVy38XunkJJU2XP6ZjuTLgvntxVDl8J-Y-XtlNoWSZZ1s2F8iMuz20lJS3Cw70xK9vkeog5D86xgKEhGIHmu8waISWm_Bdz_SdLGtclFTBhiCqQ6Blks',
        d: 'DExSnRtu0J6Paejm2XV_MfRy1xfNADVKZChCo0qyYMSRbeQcZ4To5vgEh_FnzkqTzPyC5_zLRq6t9wA5_Ct-pID5oVAZAntEu_FECZhOY1UA3ReF2PSaaJQ-zU8WZOZusmV_BTHofw4GywRJDKxZbRkfYJS9avfyP_ghIPy3vgZ0IlusoDtHS3Fo1tLJkIP_2P8wYQ-qrooYw9s6sA9Zjyw1FsDKkQ-GqLm2xWLDp4jZ8lH3Zfgpg2CuXJ_x9KHlXzlkRK-LBxeRbcLxFRw36GL4JikgyyeqNoHhF3ulkBIoh-YbwA06YwMtRs6m5klfzyltHCpLZG3Hjjv1p4kVoQ',
        e: 'AQAB',
        qi: 'S5C3jb1Knb3-aKtZZmyy9JTX4EFOFcLABdAsoPBz7d5k14AANvbIDQgcBLlPOWJQVqQ3b3W7GL_T2uLoZ9BTSb2zONrykB__3IMRwzCx0y5qhuw50yIE8qUT0pZ4X5K_NmoD2dtkDfZjFB09e9_ktJBDsL65OqQwKwK1BFQU1yo',
        dp: '4Fx0qozEmTxl0-GmRoKiuG9GRbh0nnF-_wBPNktCLJzX6qUJ2oqTwnCrrbu9qqFHW0aaO_s2KWZf5BajPht8fxikPpJc445j7u3Jd-UXEDIrEHQYg330rRwHmbHLDnbKDfFFoim_x_qsmjhgwsCw9QPU_3Y_Cgk-CEPtpKpaEtE',
        dq: 'tPGYcEnRwU6ImbTYjN2X62R8ezO4t8hsGNYqikgaAKsclU3p_PPG7GftMBPThpogbLBlBltMWOEEJN4LbcZKM9p_xOyuuYcw_vY_iJbYT0CL-NDdbthSQjRcom2q0RFkDrNx2Jq6bpLUb-soKWk3r3zHCHUF_4zSNRZSE8Feaa0',
        n: '4aOc6ck9Wh0-PfG4gCsMSaZT9nE-NXxQ8iSbocelFf-ViJE4vCcEk_1iU4-bEahtem6mBSN-rCUHACg0fWH1GzTmpmUTZFsbLXAWkMuJk-FXAy5dfXPFUQhE6cZbcrqYke5T5tbXExnu39OR_F-c6hvXahPsfDpIPF9BJ7GA6c3brMCh1jTYiuk5xAmOLobsC_McgsEhWgHEwv1f85fs5Sn0CHi6OGISpntG0TA7oAnnktfAxIb-f3ZnaHfPBq6z4_jJjXt0wM_4sxqjvzirI6Wewk0jxQsCsEhE4v251OHectuiHWnG48xpxqHrKEa9LE79x4a2XBLt3RV2NNLpRw'
      }
    },
    publicKey: {
      pem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4aOc6ck9Wh0+PfG4gCsMSaZT9nE+NXxQ8iSbocelFf+ViJE4vCcE
k/1iU4+bEahtem6mBSN+rCUHACg0fWH1GzTmpmUTZFsbLXAWkMuJk+FXAy5dfXPF
UQhE6cZbcrqYke5T5tbXExnu39OR/F+c6hvXahPsfDpIPF9BJ7GA6c3brMCh1jTY
iuk5xAmOLobsC/McgsEhWgHEwv1f85fs5Sn0CHi6OGISpntG0TA7oAnnktfAxIb+
f3ZnaHfPBq6z4/jJjXt0wM/4sxqjvzirI6Wewk0jxQsCsEhE4v251OHectuiHWnG
48xpxqHrKEa9LE79x4a2XBLt3RV2NNLpRwIDAQAB
-----END RSA PUBLIC KEY-----`,
      jwk: {
        kty: 'RSA',
        e: 'AQAB',
        n: '4aOc6ck9Wh0-PfG4gCsMSaZT9nE-NXxQ8iSbocelFf-ViJE4vCcEk_1iU4-bEahtem6mBSN-rCUHACg0fWH1GzTmpmUTZFsbLXAWkMuJk-FXAy5dfXPFUQhE6cZbcrqYke5T5tbXExnu39OR_F-c6hvXahPsfDpIPF9BJ7GA6c3brMCh1jTYiuk5xAmOLobsC_McgsEhWgHEwv1f85fs5Sn0CHi6OGISpntG0TA7oAnnktfAxIb-f3ZnaHfPBq6z4_jJjXt0wM_4sxqjvzirI6Wewk0jxQsCsEhE4v251OHectuiHWnG48xpxqHrKEa9LE79x4a2XBLt3RV2NNLpRw'
      }
    }
  },
  {
    privateKey: {
      pem: `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDEJNZcY9UAPhpzSjjJXmo+TAR61dGH9rzRI8FhVRlxHWHN+U9d
Rjd4ML2fL09G5QhkdKCNC0LGXETT1z4s4NdobKwyK0vZY/2WuzgCXqVp7JdVDj25
icX3i1Ff4mwW5DdBDlyMtcFu6vkKRPS2MUbaWHHxuj7EQBqySP5pAomZvwIDAQAB
AoGAN5xOHnG7kU8KRsezY/xd2P3Kg10eBBODozQk/siW5wgyk6hsxQBEd9Ix4PET
5ADJqVmbr4GS1BSS+xDasvSofZa9a1jJHS0L+go6OiljGMuGSYAmyaYYsbYMkA2O
N4r8iACEvymc3u91D7DatomH5vLQ3pKzNfka2GMVm2hg6RkCQQDmP8m7aC6+Pjob
pvP6lW8+oPZkzdUp1Ss6IKZCC2MMDwRBlGFUDuRWZ0afIvDsEjRKUXJkx7kuqf8I
rF4cSRqNAkEA2hSWwRZv8HJ0W/FiG72dXqFctpOsz8ghKaGd3PewXp/sRQkX78VM
ewajCZq5WXPacPEY7negW191LzyHcsc4ewJAeYU/Fm8VBIlZJ9EEwcNu1DIl+Ov9
zjdYujQTK5ZQ70NZrrb+a1v0vXmCd2j8mMu+116HLpOOtAc6uDwo62rV3QJBAK0B
PmNpwF34/pReFx24vBpxWpLA7oxb0Oss+oZsvK8koZRW1XVyiOzkY/zfkQEE5ptI
uSWdI0q5nMZfd3i30PcCQGOfbi/5Hnyp/bkYtTApP5o2+5GEaLNtmJQbd1NYfeUi
xv12VGtXh/cXjnVYbi0aBswrqXSkG05zQlQrvh8dR6k=
-----END RSA PRIVATE KEY-----`,
      jwk: {
        p: '5j_Ju2guvj46G6bz-pVvPqD2ZM3VKdUrOiCmQgtjDA8EQZRhVA7kVmdGnyLw7BI0SlFyZMe5Lqn_CKxeHEkajQ',
        kty: 'RSA',
        q: '2hSWwRZv8HJ0W_FiG72dXqFctpOsz8ghKaGd3PewXp_sRQkX78VMewajCZq5WXPacPEY7negW191LzyHcsc4ew',
        d: 'N5xOHnG7kU8KRsezY_xd2P3Kg10eBBODozQk_siW5wgyk6hsxQBEd9Ix4PET5ADJqVmbr4GS1BSS-xDasvSofZa9a1jJHS0L-go6OiljGMuGSYAmyaYYsbYMkA2ON4r8iACEvymc3u91D7DatomH5vLQ3pKzNfka2GMVm2hg6Rk',
        e: 'AQAB',
        qi: 'Y59uL_kefKn9uRi1MCk_mjb7kYRos22YlBt3U1h95SLG_XZUa1eH9xeOdVhuLRoGzCupdKQbTnNCVCu-Hx1HqQ',
        dp: 'eYU_Fm8VBIlZJ9EEwcNu1DIl-Ov9zjdYujQTK5ZQ70NZrrb-a1v0vXmCd2j8mMu-116HLpOOtAc6uDwo62rV3Q',
        dq: 'rQE-Y2nAXfj-lF4XHbi8GnFaksDujFvQ6yz6hmy8ryShlFbVdXKI7ORj_N-RAQTmm0i5JZ0jSrmcxl93eLfQ9w',
        n: 'xCTWXGPVAD4ac0o4yV5qPkwEetXRh_a80SPBYVUZcR1hzflPXUY3eDC9ny9PRuUIZHSgjQtCxlxE09c-LODXaGysMitL2WP9lrs4Al6laeyXVQ49uYnF94tRX-JsFuQ3QQ5cjLXBbur5CkT0tjFG2lhx8bo-xEAaskj-aQKJmb8'
      }
    },
    publicKey: {
      pem: `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMQk1lxj1QA+GnNKOMleaj5MBHrV0Yf2vNEjwWFVGXEdYc35T11GN3gw
vZ8vT0blCGR0oI0LQsZcRNPXPizg12hsrDIrS9lj/Za7OAJepWnsl1UOPbmJxfeL
UV/ibBbkN0EOXIy1wW7q+QpE9LYxRtpYcfG6PsRAGrJI/mkCiZm/AgMBAAE=
-----END RSA PUBLIC KEY-----`,
      jwk: {
        kty: 'RSA',
        e: 'AQAB',
        n: 'xCTWXGPVAD4ac0o4yV5qPkwEetXRh_a80SPBYVUZcR1hzflPXUY3eDC9ny9PRuUIZHSgjQtCxlxE09c-LODXaGysMitL2WP9lrs4Al6laeyXVQ49uYnF94tRX-JsFuQ3QQ5cjLXBbur5CkT0tjFG2lhx8bo-xEAaskj-aQKJmb8'
      }
    }
  },
]

const pkcs8KeyPairs = [
  // 2048 bit
  {
    privateKey: {
      pem: `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDW6grubDBXAEsA
YK+6FzTuFL3IdSOadxrSjf1jrUiUYbUWTrXJkmkaacd2rDAciRAVPS36PcM20tGA
zSWlzpUdAlB5fdVxViDct1+L148CPHOiqNhRzEjpTpn2Gdy2jCmrSLpAR8EdEXdD
kXkKTraHEc4Ar8DvSGehZIcZ4q6Q7kuvFlAuPVYe6a4Pv2eU08ZMyT2nDSH2xJtU
D8Mt2eVeaUnGrqO7qbzKnGvyFH4wEMnbrm0HF3lkMXDPqObkfQGMe2EkXyoUcUYL
njMl2oaeTszmMhrfM49jZrnLS3vd7P+1VvL8s630t3wOtieHxdQwitz6xL7yAsvG
oV8Kc/rxAgMBAAECggEBAJWWceViCIOGAK5Snf25CW5toWtVnWJ2ZIUJr8UhZ9Nf
7tuIDaAv+FgaKGvBjftOq5Mc8lOriaUvOAOexwWRtNhsM/dcTqSEfnsiZ66+axvz
V8lwHKFSv60kuKVDewzUomxGQt1bFF9XONwe9VDnWMTK78gqjPAARaFgh2jNDxRw
geTLR+32YNsM1kq98Cf9jFVaK+RZS7S0Sm6Z4AdC7Le4r9QzdPX9wWP9RzlTH7mi
1+HKljANXzNJyzk8r7++UuihS4MqBrMy3Mr1HJ4+NJ9PzRwOSmxYmEFFTiShOg2p
PRHIXlq7MaEKL8JQS9e2k3xUXrHtq+cis8Mg4G/5fAECgYEA9xwDAypNpQ42U0+u
4VRiiivnl0mpEU8oUWirBxOCieF9GtTcPx25vCUOU/hIVoxY6IJHhKB7qVRhjHqo
qTVh/sv7t49EsN27XPNAjKBNb9uI8SuZ+otbbymkAdfEGmDR5Ik3fUx4geue+x7D
+CTOSCl8haMFG1B6E4isw8jWkukCgYEA3qV/sw7mihZH3VtLAiID7rXmwtZnHiKJ
ht9tRdbM38h/fczmAZyqSBy3yNS+opWbOk7h4ShcsUJQqdwYWEhkoEy7WgAyCKD4
znBaMiGM+6hCVOIKCYzYjIzsNMwz+G/jSNCu28QFlgMxXzHalHLYxmByIRKJ3YVB
z9MqX1wMUskCgYEAgLb1lrt9UEFz6Ldz12lWHrS54GL9DsgVrzn/BCOUdm+e88/2
nWXFbow6x2BnhbV7Rjk+OYZCg7QxT7RAkEr/LXJhPn8A/8Ovqb4HXHjPfTl0PnNA
tHHMgb3F8TPLsRXHnuwenESt7LanzBR9bY72aD4733xH1692tyAVJbJCmqkCgYA6
YAwWR37cj7Dx8cC942tCiEDjrtFEjmueiDAfUo1O00PSGQnpPElNNPJe3qDJAg67
//irTyjWdPuvPXzIkNqJSPUKSOjVaFcz0TNk13UeemRB2y4kiOAyIbTAtxWdOsDN
06E1D7UjOt0UB3820tHRWXIzB6hMA2dY9RW0AO9eOQKBgQCck1WEW7KwyH++50KB
tcgX7VwobM6N1mA1OZ2s6lUrr0N/CQysrOq0Run15DTx0MBG6zsSQ8xjcoFQl/7X
bgtWPG+Wm5qe6nLF3lssesCzEjp40waxZDrcIQtlQAAXOYKnejJu4crR/wWHuBgG
Bzggm5yfYhl9CHkYThGCITVMxw==
-----END PRIVATE KEY-----`,
      jwk: {
        "p": "9xwDAypNpQ42U0-u4VRiiivnl0mpEU8oUWirBxOCieF9GtTcPx25vCUOU_hIVoxY6IJHhKB7qVRhjHqoqTVh_sv7t49EsN27XPNAjKBNb9uI8SuZ-otbbymkAdfEGmDR5Ik3fUx4geue-x7D-CTOSCl8haMFG1B6E4isw8jWkuk",
        "kty": "RSA",
        "q": "3qV_sw7mihZH3VtLAiID7rXmwtZnHiKJht9tRdbM38h_fczmAZyqSBy3yNS-opWbOk7h4ShcsUJQqdwYWEhkoEy7WgAyCKD4znBaMiGM-6hCVOIKCYzYjIzsNMwz-G_jSNCu28QFlgMxXzHalHLYxmByIRKJ3YVBz9MqX1wMUsk",
        "d": "lZZx5WIIg4YArlKd_bkJbm2ha1WdYnZkhQmvxSFn01_u24gNoC_4WBooa8GN-06rkxzyU6uJpS84A57HBZG02Gwz91xOpIR-eyJnrr5rG_NXyXAcoVK_rSS4pUN7DNSibEZC3VsUX1c43B71UOdYxMrvyCqM8ABFoWCHaM0PFHCB5MtH7fZg2wzWSr3wJ_2MVVor5FlLtLRKbpngB0Lst7iv1DN09f3BY_1HOVMfuaLX4cqWMA1fM0nLOTyvv75S6KFLgyoGszLcyvUcnj40n0_NHA5KbFiYQUVOJKE6Dak9EcheWrsxoQovwlBL17aTfFRese2r5yKzwyDgb_l8AQ",
        "e": "AQAB",
        "qi": "nJNVhFuysMh_vudCgbXIF-1cKGzOjdZgNTmdrOpVK69DfwkMrKzqtEbp9eQ08dDARus7EkPMY3KBUJf-124LVjxvlpuanupyxd5bLHrAsxI6eNMGsWQ63CELZUAAFzmCp3oybuHK0f8Fh7gYBgc4IJucn2IZfQh5GE4RgiE1TMc",
        "dp": "gLb1lrt9UEFz6Ldz12lWHrS54GL9DsgVrzn_BCOUdm-e88_2nWXFbow6x2BnhbV7Rjk-OYZCg7QxT7RAkEr_LXJhPn8A_8Ovqb4HXHjPfTl0PnNAtHHMgb3F8TPLsRXHnuwenESt7LanzBR9bY72aD4733xH1692tyAVJbJCmqk",
        "dq": "OmAMFkd-3I-w8fHAveNrQohA467RRI5rnogwH1KNTtND0hkJ6TxJTTTyXt6gyQIOu__4q08o1nT7rz18yJDaiUj1Ckjo1WhXM9EzZNd1HnpkQdsuJIjgMiG0wLcVnTrAzdOhNQ-1IzrdFAd_NtLR0VlyMweoTANnWPUVtADvXjk",
        "n": "1uoK7mwwVwBLAGCvuhc07hS9yHUjmnca0o39Y61IlGG1Fk61yZJpGmnHdqwwHIkQFT0t-j3DNtLRgM0lpc6VHQJQeX3VcVYg3Ldfi9ePAjxzoqjYUcxI6U6Z9hnctowpq0i6QEfBHRF3Q5F5Ck62hxHOAK_A70hnoWSHGeKukO5LrxZQLj1WHumuD79nlNPGTMk9pw0h9sSbVA_DLdnlXmlJxq6ju6m8ypxr8hR-MBDJ265tBxd5ZDFwz6jm5H0BjHthJF8qFHFGC54zJdqGnk7M5jIa3zOPY2a5y0t73ez_tVby_LOt9Ld8DrYnh8XUMIrc-sS-8gLLxqFfCnP68Q"
      }
    },
    publicKey: {
      pem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1uoK7mwwVwBLAGCvuhc0
7hS9yHUjmnca0o39Y61IlGG1Fk61yZJpGmnHdqwwHIkQFT0t+j3DNtLRgM0lpc6V
HQJQeX3VcVYg3Ldfi9ePAjxzoqjYUcxI6U6Z9hnctowpq0i6QEfBHRF3Q5F5Ck62
hxHOAK/A70hnoWSHGeKukO5LrxZQLj1WHumuD79nlNPGTMk9pw0h9sSbVA/DLdnl
XmlJxq6ju6m8ypxr8hR+MBDJ265tBxd5ZDFwz6jm5H0BjHthJF8qFHFGC54zJdqG
nk7M5jIa3zOPY2a5y0t73ez/tVby/LOt9Ld8DrYnh8XUMIrc+sS+8gLLxqFfCnP6
8QIDAQAB
-----END PUBLIC KEY-----`,
      jwk: {
        "kty": "RSA",
        "e": "AQAB",
        "n": "1uoK7mwwVwBLAGCvuhc07hS9yHUjmnca0o39Y61IlGG1Fk61yZJpGmnHdqwwHIkQFT0t-j3DNtLRgM0lpc6VHQJQeX3VcVYg3Ldfi9ePAjxzoqjYUcxI6U6Z9hnctowpq0i6QEfBHRF3Q5F5Ck62hxHOAK_A70hnoWSHGeKukO5LrxZQLj1WHumuD79nlNPGTMk9pw0h9sSbVA_DLdnlXmlJxq6ju6m8ypxr8hR-MBDJ265tBxd5ZDFwz6jm5H0BjHthJF8qFHFGC54zJdqGnk7M5jIa3zOPY2a5y0t73ez_tVby_LOt9Ld8DrYnh8XUMIrc-sS-8gLLxqFfCnP68Q"
      }
    }
  },
  // 1024 bit
  {
    privateKey: {
      pem: `-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANtow9gwOq3XROx8
xwj9pWwoVDQJa3XQY8VBa0q1A/LvT2mpScuAH6e1ATLObxs9TZQNkWg3Z7Uiz+jt
tqQk2p0H79K4eDbXrxL9I/YixxRgMLQhUn2BOWyaml4DrwmXt+5CDkB6TyA3G+4x
nA6wxniKGoLT2hJ2+EpkPMwBxk8tAgMBAAECgYEAyJnVjUAzNiO+eXVvyHGXn/aT
XexK2rGHtp6kSO6NSLyx34oO1Uc0KfIcwWXqQX5gAoARNLaLVBoa+vzz4slrMTvT
ChdWwz/blUxjdMv6LWLKUxh3DP54Jo5riMag5v4fVR/d5jtNu2MS1vh01QEaZ48E
cV1xJPMtbxYhHl9NzUECQQDxKwA7tAAe/N1diQFkqlK2/HNh1aposIr7QT8aeAFT
rEPJhGSFrhCqrxGaZEatrxyCKZhtiGzMeWXwZpNot5udAkEA6OcwpnQGtIf+LQln
/VyPOZnPJi3gaBHY0ITpkI8eYlPDHiAKBA2Ddvw10KCf94HGQ2eh0wdi4u/qDAY5
WRgU0QJBANhhXY8zvFwRQsh2cYKRcy9tKFUicQgHRluSufyUqZQaXqPDHrH2cEvE
UgX1bJjPIcQDcBjuq7d2QKlGT4JIIt0CQQC2Etajqhz70TzRtILJPSzy2N1qeX7v
nNQk32NAkcItGFJ3IJDz7iSSRkVD3e5wrdFzLHcD5MhXpTsRP2Rh1EOhAkANnkL+
O+D1D8sNQQigrr+ibwBYnt69R6wBHpsOTdTO1frpt6crTTf0FfocfY33ks3RBbb1
3pLN6EjuIZSu0HcB
-----END PRIVATE KEY-----`,
      jwk: {
        "p": "8SsAO7QAHvzdXYkBZKpStvxzYdWqaLCK-0E_GngBU6xDyYRkha4Qqq8RmmRGra8cgimYbYhszHll8GaTaLebnQ",
        "kty": "RSA",
        "q": "6OcwpnQGtIf-LQln_VyPOZnPJi3gaBHY0ITpkI8eYlPDHiAKBA2Ddvw10KCf94HGQ2eh0wdi4u_qDAY5WRgU0Q",
        "d": "yJnVjUAzNiO-eXVvyHGXn_aTXexK2rGHtp6kSO6NSLyx34oO1Uc0KfIcwWXqQX5gAoARNLaLVBoa-vzz4slrMTvTChdWwz_blUxjdMv6LWLKUxh3DP54Jo5riMag5v4fVR_d5jtNu2MS1vh01QEaZ48EcV1xJPMtbxYhHl9NzUE",
        "e": "AQAB",
        "qi": "DZ5C_jvg9Q_LDUEIoK6_om8AWJ7evUesAR6bDk3UztX66benK0039BX6HH2N95LN0QW29d6SzehI7iGUrtB3AQ",
        "dp": "2GFdjzO8XBFCyHZxgpFzL20oVSJxCAdGW5K5_JSplBpeo8MesfZwS8RSBfVsmM8hxANwGO6rt3ZAqUZPgkgi3Q",
        "dq": "thLWo6oc-9E80bSCyT0s8tjdanl-75zUJN9jQJHCLRhSdyCQ8-4kkkZFQ93ucK3Rcyx3A-TIV6U7ET9kYdRDoQ",
        "n": "22jD2DA6rddE7HzHCP2lbChUNAlrddBjxUFrSrUD8u9PaalJy4Afp7UBMs5vGz1NlA2RaDdntSLP6O22pCTanQfv0rh4NtevEv0j9iLHFGAwtCFSfYE5bJqaXgOvCZe37kIOQHpPIDcb7jGcDrDGeIoagtPaEnb4SmQ8zAHGTy0"
      }
    },
    publicKey: {
      pem: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbaMPYMDqt10TsfMcI/aVsKFQ0
CWt10GPFQWtKtQPy709pqUnLgB+ntQEyzm8bPU2UDZFoN2e1Is/o7bakJNqdB+/S
uHg2168S/SP2IscUYDC0IVJ9gTlsmppeA68Jl7fuQg5Aek8gNxvuMZwOsMZ4ihqC
09oSdvhKZDzMAcZPLQIDAQAB
-----END PUBLIC KEY-----`,
      jwk: {
        "kty": "RSA",
        "e": "AQAB",
        "n": "22jD2DA6rddE7HzHCP2lbChUNAlrddBjxUFrSrUD8u9PaalJy4Afp7UBMs5vGz1NlA2RaDdntSLP6O22pCTanQfv0rh4NtevEv0j9iLHFGAwtCFSfYE5bJqaXgOvCZe37kIOQHpPIDcb7jGcDrDGeIoagtPaEnb4SmQ8zAHGTy0"
      }
    }
  }
]

describe('pem2jwk', () => {
  it('works for private key (PKCS#1)', () => {
    pkcs1KeyPairs.forEach(({ privateKey}) => {
      expect(pem2jwk(privateKey.pem)).toEqual(privateKey.jwk)
    })
  })

  it('works for public key (PKCS#1)', () => {
    pkcs1KeyPairs.forEach(({ publicKey }) => {
      expect(pem2jwk(publicKey.pem)).toEqual(publicKey.jwk)
    })
  })

  it('works for private key (PKCS#8)', () => {
    pkcs8KeyPairs.forEach(({ privateKey}) => {
      expect(pem2jwk(privateKey.pem)).toEqual(privateKey.jwk)
    })
  })

  it('works for public key (PKCS#8)', () => {
    pkcs8KeyPairs.forEach(({ publicKey }) => {
      expect(pem2jwk(publicKey.pem)).toEqual(publicKey.jwk)
    })
  })

  it('can add options to jwk object', () => {
    const jwk = pem2jwk(pkcs1KeyPairs[0].publicKey.pem, {
      use: 'sig',
      kid: 'foo'
    })

    const expected = { ...pkcs1KeyPairs[0].publicKey.jwk, use: 'sig', kid: 'foo' }

    expect(jwk).toEqual(expected)
  })

  it('throws if "use" is invalid', () => {
    expect(() => pem2jwk(pkcs1KeyPairs[0].publicKey.pem, { use: 'something-else' })).toThrow()
  })

  it('does not throw if "use" is valid', () => {
    expect(() => pem2jwk(pkcs1KeyPairs[0].publicKey.pem, { use: 'enc' })).not.toThrow()
  })

  it('handles when input has additional whitespace', () => {
    const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDEJNZcY9UAPhpzSjjJXmo+TAR61dGH9rzRI8FhVRlxHWHN+U9d
Rjd4ML2fL09G5QhkdKCNC0LGXETT1z4s4NdobKwyK0vZY/2WuzgCXqVp7JdVDj25
icX3i1Ff4mwW5DdBDlyMtcFu6vkKRPS2MUbaWHHxuj7EQBqySP5pAomZvwIDAQAB
AoGAN5xOHnG7kU8KRsezY/xd2P3Kg10eBBODozQk/siW5wgyk6hsxQBEd9Ix4PET
5ADJqVmbr4GS1BSS+xDasvSofZa9a1jJHS0L+go6OiljGMuGSYAmyaYYsbYMkA2O
N4r8iACEvymc3u91D7DatomH5vLQ3pKzNfka2GMVm2hg6RkCQQDmP8m7aC6+Pjob
pvP6lW8+oPZkzdUp1Ss6IKZCC2MMDwRBlGFUDuRWZ0afIvDsEjRKUXJkx7kuqf8I
rF4cSRqNAkEA2hSWwRZv8HJ0W/FiG72dXqFctpOsz8ghKaGd3PewXp/sRQkX78VM
ewajCZq5WXPacPEY7negW191LzyHcsc4ewJAeYU/Fm8VBIlZJ9EEwcNu1DIl+Ov9
zjdYujQTK5ZQ70NZrrb+a1v0vXmCd2j8mMu+116HLpOOtAc6uDwo62rV3QJBAK0B
PmNpwF34/pReFx24vBpxWpLA7oxb0Oss+oZsvK8koZRW1XVyiOzkY/zfkQEE5ptI
uSWdI0q5nMZfd3i30PcCQGOfbi/5Hnyp/bkYtTApP5o2+5GEaLNtmJQbd1NYfeUi
xv12VGtXh/cXjnVYbi0aBswrqXSkG05zQlQrvh8dR6k=
-----END RSA PRIVATE KEY-----
`
    expect(pem2jwk(privateKey)).toEqual({
      p: '5j_Ju2guvj46G6bz-pVvPqD2ZM3VKdUrOiCmQgtjDA8EQZRhVA7kVmdGnyLw7BI0SlFyZMe5Lqn_CKxeHEkajQ',
      kty: 'RSA',
      q: '2hSWwRZv8HJ0W_FiG72dXqFctpOsz8ghKaGd3PewXp_sRQkX78VMewajCZq5WXPacPEY7negW191LzyHcsc4ew',
      d: 'N5xOHnG7kU8KRsezY_xd2P3Kg10eBBODozQk_siW5wgyk6hsxQBEd9Ix4PET5ADJqVmbr4GS1BSS-xDasvSofZa9a1jJHS0L-go6OiljGMuGSYAmyaYYsbYMkA2ON4r8iACEvymc3u91D7DatomH5vLQ3pKzNfka2GMVm2hg6Rk',
      e: 'AQAB',
      qi: 'Y59uL_kefKn9uRi1MCk_mjb7kYRos22YlBt3U1h95SLG_XZUa1eH9xeOdVhuLRoGzCupdKQbTnNCVCu-Hx1HqQ',
      dp: 'eYU_Fm8VBIlZJ9EEwcNu1DIl-Ov9zjdYujQTK5ZQ70NZrrb-a1v0vXmCd2j8mMu-116HLpOOtAc6uDwo62rV3Q',
      dq: 'rQE-Y2nAXfj-lF4XHbi8GnFaksDujFvQ6yz6hmy8ryShlFbVdXKI7ORj_N-RAQTmm0i5JZ0jSrmcxl93eLfQ9w',
      n: 'xCTWXGPVAD4ac0o4yV5qPkwEetXRh_a80SPBYVUZcR1hzflPXUY3eDC9ny9PRuUIZHSgjQtCxlxE09c-LODXaGysMitL2WP9lrs4Al6laeyXVQ49uYnF94tRX-JsFuQ3QQ5cjLXBbur5CkT0tjFG2lhx8bo-xEAaskj-aQKJmb8'
    })
  })
})