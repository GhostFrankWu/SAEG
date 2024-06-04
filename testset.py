

FLAG = 'flag{12345678-abcd-ef09}'
FAIL_MAX = 9999
FLAG_FILE_NAMES = ['flag', 'flag.txt']

STACK_TESTS = {
    'BOF_TEST_SET': {
        'path': 'assets/bof_aeg_challenges/',
        'task': {
            "redpwnctf2020_coffer": 6,
            "csictf2020_pwn0x1": 5,
            "csictf2020_pwn0x2": 6,
            "csictf2020_pwn0x3": 6,
            "dctf2021_sanity": 4,
            "umdctf2021_jne": 6,
            "csawctf2021_password": 60,
            "h@cktivityctf2021_retcheck": 8,
            "downunderctf2021_deadcode": 6,
            "downunderctf2021_out": 5,
            "csawctf2020_roppity": 6,
            "downunderctf2020_return": 7,
            "dctf2021_babybof": 5,
            "umdctf2021_jnw": 6,
            "tamilctf2021_name": 4,
            "dicectf2021_babyrop": 6,
            "utctf2021_resolve": 6,
            "nahamconctf2021_smol": 4,
            "sharkyctf2020_give": 4,
            "wpictf2020_dorsia1": 4,
            "dctf2021_hotelrop": 5,
            "lexingtonctf2021_gets": 11,
        },
        'libc': 'libc-2.31.so',
        'ld': 'ld-2.31.so',
    },

    'LAEG_TEST_SET': {
        'path': 'assets/laeg_challenges/',
        'task': {
            "angstrom20_no_canary": 8.6,
            "angstrom21_tranquil": 5.59,
            "crash-backdoor": 5.72,
            "crash-canary": 5.60,
            "crash-pie": 5.74,
            "crash-static": 1.68,
            "defcon27_speedrun-001": 41.26,
            "defcon27_speedrun-002": 6.2,
            "utctf2020_bof": 5.54,
        },
        'libc': 'libc-2.31.so',
        'ld': 'ld-2.31.so',
        'sig': ['libc6_2.27-0ubuntu3_amd64.sig'],
        'static': ['crash-static', 'defcon27_speedrun-001']
    },

    'SIMPLE_TEST_SET': {
        'path': 'assets/simple_stack/',
        'task': {
            'angstrom19_aquarium': FAIL_MAX,
            'angstrom19_chain_of_rope': FAIL_MAX,
            'angstrom21_checks': FAIL_MAX,
            'angstrom21_tranquil': FAIL_MAX,
            'angstrom23_gaga0': FAIL_MAX,
            'angstrom23_gaga1': FAIL_MAX,
            'angstrom23_gaga2': FAIL_MAX,
        }
    },
}

HEAP_TESTS = {
    'SIMPLE_TEST_SET': {
        'path': 'assets/simple_heap/',
        'task': {
            'gyctf_2020_force': FAIL_MAX,
        },
        'libc': 'libc-2.23.so',
        'ld': 'ld-2.23.so',
        'timeout': 500
    },
}

TEST_SET_MAP = {
    'stack': STACK_TESTS,
    'heap': HEAP_TESTS,
}
