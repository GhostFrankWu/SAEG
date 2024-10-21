# SAEG: Stateful Automatic Exploit Generation

<img align='right' src='https://github.com/GhostFrankWu/SAEG/blob/main/attachments/saeg.png?raw=true' width='300px'>  

SAEG is a framework uses angr as symbolic execution engine for Automatic Exploit Generation (AEG). Its purpose is to provide an efficient framework for handling multi-stage exploits that include information leakage. As a conceptual implementation, SAEG has implemented parts of stack exploitation and a prototype for heap exploitation.  
We provide source code and a one-click deployment script for reproduction and reference of other studies. It also offers some benchmark test cases, and you can check the results of these test cases in the [CI run results](https://github.com/GhostFrankWu/SAEG/actions/).  
If you want to know more about SAEG, please refer to [our article](#Publication).

--------------

SAEG 是一个使用 angr 作为符号执行引擎的 AEG (Automatic Exploit Generation) 框架，旨在提供一个高效的处理包含信息泄露的多步利用的框架。作为概念验证，SAEG 实现了部分栈利用以及一个堆利用的原型，并提供了源码及一键部署环境以供复现研究，同时也提供了一些基准测试用例，你可以在 CI 中看到这些测试用例的[运行结果](https://github.com/GhostFrankWu/SAEG/actions/)。  
如果您希望了解更多关于SAEG的信息，请查看[我们的文章](#Publication)。

Demo video for SAEG(演示视频):  

[![asciicast demo video](https://asciinema.org/a/bMvlXJ8PkxqE2hoXyYtAmLaec.svg)](https://asciinema.org/a/bMvlXJ8PkxqE2hoXyYtAmLaec)

## Installing & Testing on Docker
It is recommended to use Ubuntu20.04 or later on docker to run the test.  
Example of [Docker file](Dockerfile) is based on Ubuntu22.04.
Also refer to [CI file](.github/workflows/test.yml) for more details.
```sh
docker build -t saeg:01 .
# Run stack testset
docker run -v /tmp:/test_res saeg:01 bash -c 'cd /aeg && python3 saeg.py -f x -t stack'
# Get result
cat /tmp/test_result.txt
# Interactively run SAEG 
docker run -it saeg:01 bash
```
如果您在中国大陆地区，[Dockerfile](Dockerfile) 中有两行注释掉的源(apt和pip)，您可以取消注释并以加速构建。

## Usage
pwn local file:
```sh
python3 saeg.py -f input_file
```
pwn remote with libc and ld specified:  
```sh
python3 saeg.py -f input_file -l [LIBC.so] -d [LD.so] -i [ip:port]
# for example:
python3 saeg.py -f ./vuln -l `pwd`/libc.so -d ./ld.so -i 192.168.1.1:1337
```
Get help message:
```sh
python3 saeg.py --help
```

## Framework Structure

- [aseg.py](saeg.py) Run framework
- [testset.py](testset.py) Test index
- [Dockerfile](Dockerfile) 
- **aeg_module/**
  + [aeg_main.py](aeg_module/aeg_main.py) Entry and outer state machine
  + [challenge.py](aeg_module/challenge.py) Initialize the binary and analyse its static information
  + [binary_interactive.py](aeg_module/binary_interactive.py) Module to store label information and maintain interaction
  + [mod_leak.py](aeg_module/mod_leak.py) Attack Templates for infoleak
  + [mod_exploit.py](aeg_module/mod_exploit.py) Attack Templates for stack exploit
  + [mod_technique.py](aeg_module/mod_technique.py) Monitor memory write and execution path during step() in angr
  + [mod_sim_procedure.py](aeg_module/mod_sim_procedure.py) Hook functions for angr
  + [mod_sim_procedure_heap.py](aeg_module/mod_sim_procedure_heap.py) Hook memory functions for angr
  + [utils.py](aeg_module/utils.py) Misc tools such as interaction and calculation and shellcode

SAEG was designed with the concept of scalability. If you want to simply modify/expand the framework, you may start with files starting with `mod_`.  
>SAEG是基于易于扩展的理念设计的，如果您希望简单地修改/扩充框架，可以考虑从`mod_`开头的文件开始。

## Additional Documentation
### Citation
If you use this repository for research, please cite our paper: 
```
@inproceedings{saeg,
	title = {SAEG: Stateful Automatic Exploit Generation},
	author = {Yifan Wu and Yinshuai Li and Hong Zhu and Yinqian Zhang},
	booktitle = {European Symposium on Research in Computer Security},
	year = {2024}
}
```

### Publication
Link of the **draft** version of our paper (Neither a submitted version nor a preprint):  
[Paper PDF](https://ghostfrankwu.github.io/papers/saeg_draft.pdf)

### Reference of open source projects
Zeratool is a traditional symbolic execution framework for binary analysis and (stack) exploitation:  
https://github.com/ChrisTheCoolHut/Zeratool  

BOF_AEG is a simple stack exploitation tool based on angr: (Not available now)  
https://github.com/Kirito0/bof_aeg  

Simple framework for stack exploitation and detection of memory corruption:  
https://github.com/Hank0438/AEG  

Framework for detection of memory corruption:  
https://github.com/angr/heaphopper  

Awsome kernel AEGs (with angr):  
https://github.com/plummm/SyzScope   
https://github.com/seclab-ucr/SyzBridge  

## Discussion
The performance of the CI server provided by Github is fluctuating, so there may be significant deviations even after two consecutive runs. Therefore it is more recommended to run performance tests locally.
>Github提供的CI服务器性能较为波动，即使连续两次运行也会有较大的偏差，因此更推荐在本地运行性能测试。

This framework focuses on static analysis and dynamic verification, so its effectiveness is not precise enough for all protecting mechanisms (including system-level ASLR) are disabled scenarios and utilizing dangling pointers on the stack. Currently, other solutions for work include dynamically running and interacting with GDB, but these contents are not the aim of this work (information leakage).
>该框架侧重于静态分析，动态验证，因此对于保护全关的并禁用系统ASLR的场景以及利用栈上悬垂指针的场景效果不够精确，目前其他工作的解决方案是动态调试，但这些内容并非本工作（信息泄露）的目标。
