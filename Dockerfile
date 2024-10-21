FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN #sed -i "s/archive.ubuntu.com/mirrors.aliyun.com/g" /etc/apt/sources.list
RUN apt update && apt install -y python3 python3-pip git ruby-full curl \
    libstdc++6 lib32stdc++6 gcc-multilib
RUN pip3 install pwntools angr angrop r2pipe flask # -i https://pypi.tuna.tsinghua.edu.cn/simple
RUN cd tmp && git clone https://github.com/JonathanSalwan/ROPgadget.git && cd ROPgadget &&  \
    git checkout e38c9d7be9bc68cb637f75ac0f9f4d6f41662025 && python3 setup.py install
RUN gem install one_gadget
RUN curl -Ls https://github.com/radareorg/radare2/releases/download/5.9.0/radare2-5.9.0.tar.xz | tar xJv && \
    radare2-5.9.0/sys/install.sh  # r2 in apt not correctly process flirt


RUN mkdir /aeg
COPY aeg_module /aeg/aeg_module
COPY ./assets/ /aeg/assets
COPY ./saeg.py /aeg/
COPY ./testset.py /aeg/
