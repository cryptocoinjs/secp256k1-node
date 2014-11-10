{
  "targets": [{
    "target_name": "secp256k1",
    "sources": [
      "./secp256k1.cc",
      "./src/include/secp256k1.h",
      "./src/src/secp256k1.c",
      "./src/src/ecdsa.h",
      "./src/src/ecdsa_impl.h",
      "./src/src/ecmult.h",
      "./src/src/ecmult_impl.h",
      "./src/src/field_10x26.h",
      "./src/src/field_10x26_impl.h",
      "./src/src/field_5x52.h",
      "./src/src/field_5x52_impl.h",
      "./src/src/field_5x52_int128_impl.h",
      "./src/src/field.h",
      "./src/src/field_impl.h",
      "./src/src/group.h",
      "./src/src/group_impl.h",
      "./src/src/num.h",
      "./src/src/num_impl.h",
      "./src/src/num_openssl.h",
      "./src/src/num_openssl_impl.h",
      "./src/src/util.h",
      "./src/src/util_impl.h"
    ],
    "cflags": [
      "--std=c1x"
    ],
    "include_dirs": ["<!(node -e \"require('nan')\")"],
    "defines": [
      "USE_NUM_OPENSSL=1",
      "USE_FIELD_INV_BUILTIN=1",
      "NDEBUG=1"
    ],
    'conditions': [
      [
        'target_arch=="ia32"', {
          'defines': [
            'USE_FIELD_10X26=1'
          ]
        }
      ],
      [
        'target_arch=="x64"', {
          'defines': [
            'USE_FIELD_5X52=1',
            'USE_FIELD_5X52_INT128=1'
          ]
        }
      ],

      [
        'OS=="win"', {
          'conditions': [
            [
              'target_arch=="x64"', {
                'variables': {
                  'openssl_root%': 'C:/OpenSSL-Win64'
                },
              }, {
                'variables': {
                  'openssl_root%': 'C:/OpenSSL-Win32'
                }
              }
            ]
          ],
          'libraries': [
            '-l<(openssl_root)/lib/libeay32.lib',
          ],
          'include_dirs': [
            '<(openssl_root)/include',
          ],
        },
        {
          'conditions': [
            [
              'target_arch=="ia32"', {
                'variables': {
                  'openssl_config_path': '<(nodedir)/deps/openssl/config/piii'
                }
              }
            ],
            [
              'target_arch=="x64"', {
                'variables': {
                  'openssl_config_path': '<(nodedir)/deps/openssl/config/k8'
                },
              }
            ],
            [
              'target_arch=="arm"', {
                'variables': {
                  'openssl_config_path': '<(nodedir)/deps/openssl/config/arm'
                }
              }
            ],
          ],
          'include_dirs': [
            "<(nodedir)/deps/openssl/openssl/include",
            "<(openssl_config_path)"
          ]
        }
      ]
    ]
  }]
}
