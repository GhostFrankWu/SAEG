#!/usr/bin/python3
import json
import os
import requests
import argparse
from pwn import context, log
from aeg_module import *
import time
import subprocess
import sys
from testset import *

DEMON_PORT = 13370
BANNER = "=" * 50 + "\n"


def run_exp(_exp, _debug=False, start_time=time.time()):
    try:
        _exp.exploit()
    except Exception as e:
        c = time.time() - start_time
        if FLAG in str(e) or "locally success" in str(e):  # locally success means challenge GLIBC is not math with ours
            print(f"Flag found as {str(e)}, cost {c} seconds")
            return True, c
        else:
            print(f"Error {str(e)}")
            if _debug:
                raise e
    print(f"Flag not found, cost {time.time() - start_time} seconds")
    return False, time.time() - start_time


def local_aeg(file_name, flirt_file=None, lib=None, d=None, timeout=300, debug=False, interactive=False,
              concurrent=-1):
    subprocess.run(f"chmod +x {file_name}", shell=True)
    start_time = time.time()
    exp = aeg_main.AEGModule(file_name, 'flag.txt', flirt=flirt_file, libc=lib, ld=d, timeout=timeout, _debug=debug,
                             _interactive=interactive, active_size=concurrent)
    return run_exp(exp, debug, start_time)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="binary file path", required=True)
    parser.add_argument("-p", "--flag_path", help="flag path", default="flag")
    parser.add_argument("-F", "--flirt", help="flirt file path", action='append', default=None)
    parser.add_argument("-i", "--ip", help="interactive ip:port", default=None)
    parser.add_argument("-l", "--libc", help="libc path", default=None)
    parser.add_argument("-d", "--ld", help="ld path", default=None)
    parser.add_argument("-T", "--timeout", help="timeout", default=300)
    parser.add_argument("-t", "--batch_test", help="test all (stack, heap, cgc) dataset", default=False)
    parser.add_argument("-D", "--debug", help="debug", default=False, action='store_true')
    parser.add_argument("-v", "--interactive", help="switch into interactive mode after get shell access",
                        default=False, action='store_true')
    parser.add_argument("-c", "--concurrent", help="maximum concurrent active sim", default=1)
    parser.add_argument("-L", "--log_file", help="output log into specific file", default=None)
    args = parser.parse_args()
    if args.log_file:  # fixme: log file not work
        sys.stdout = open(args.log_file, 'w')
        sys.stderr = open(args.log_file, 'w')
    try:
        sys.set_int_max_str_digits(0x9999)  # for higher version of angr
    except AttributeError:
        pass
    if args.ip:
        ip, port = args.ip.split(':')
        s = aeg_main.AEGModule(args.file, flag_path=args.flag_path, flirt=args.flirt, _interactive=args.interactive,
                               ip=ip, port=int(port), libc=args.libc, ld=args.ld, timeout=int(args.timeout),
                               active_size=int(args.concurrent))
        run_exp(s, args.debug)
    else:
        if args.flag_path:
            FLAG_FILE_NAMES.append(args.flag_path)
        for flag_name in FLAG_FILE_NAMES:
            subprocess.run(f"echo '{FLAG}' > {flag_name}", shell=True)
        if not args.batch_test:
            print(local_aeg(args.file, args.flirt, args.libc, args.ld, int(args.timeout), args.debug, args.interactive,
                            int(args.concurrent)))
        else:
            context.log_level = 'error'
            pwd = os.getcwd() + '/'
            if 'ROPgadget' not in os.listdir('/tmp'):
                subprocess.run(f"cd /tmp && git clone https://github.com/JonathanSalwan/ROPgadget.git &&"
                               f"cd ROPgadget && git checkout e38c9d7be9bc68cb637f75ac0f9f4d6f41662025", shell=True)
                subprocess.run(f"cp -r /tmp/ROPgadget/scripts /usr/local/lib/python3.8/dist-packages/"
                               f"ROPGadget-7.3.dist-info", shell=True)
            result = BANNER
            TESTS = TEST_SET_MAP[args.batch_test]
            subprocess.run(f"chmod +x assets/*.so", shell=True)
            subprocess.run(f"chmod +x assets/*.so.?", shell=True)
            for test_set_name, test_set in TESTS.items():
                result += f"Testing {test_set_name} in {test_set['path']}\n"
                failed = 0
                failed_str = ""
                subprocess.run(f"chmod +x {test_set['path']}/*", shell=True)
                for task_name, baseline_time in test_set['task'].items():
                    to_test = test_set['path'] + task_name
                    print(f"Testing {to_test}")
                    flirt = [pwd + 'assets/' + i for i in test_set.get('sig')] if 'sig' in test_set else None
                    libc = pwd + 'assets/' + test_set.get('libc') if 'libc' in test_set else None
                    ld = pwd + 'assets/' + test_set.get('ld') if 'ld' in test_set else None
                    if 'static' in test_set and task_name in test_set['static']:
                        ld = None
                    res, cost = local_aeg(to_test, flirt, libc, ld, int(args.timeout), args.debug,
                                          concurrent=int(args.concurrent))
                    for extra_try in range(5):
                        if (not res and cost < 100) or cost > baseline_time:
                            res, cost = local_aeg(to_test, flirt, libc, ld, int(args.timeout), args.debug,
                                                  concurrent=int(args.concurrent))
                    if res:
                        if baseline_time != FAIL_MAX:
                            result += f"Passed, cost {str(cost)[:4]}s,\tbaseline " \
                                      f"{str(baseline_time).rjust(5, ' ')}s" \
                                      f",\t{'Diff'} {str(baseline_time - cost)[:5]}s" \
                                      f",\t Ratio {str(baseline_time / cost)[:5]}x\tat {task_name}\n"
                        else:
                            result += f"Passed, cost {str(cost)[:4]}s,\tat {task_name}\n"
                    else:
                        failed_str += f"Test {task_name} failed\n"
                        failed += 1
                result += failed_str
                result += f"Total {len(test_set['task'])} tests, {f'{failed} failed' if failed else 'all passed'}\n"
                result += BANNER
            print(result)
            if 'test_res' in os.listdir('/'):
                with open('/test_res/test_result.txt', 'w') as f:
                    f.write(result)
        for flag_name in FLAG_FILE_NAMES:
            subprocess.run(f"rm -rf {flag_name}", shell=True)
