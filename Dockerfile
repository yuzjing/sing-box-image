# 直接使用 Debian Slim 作为基础镜像
FROM debian:stable-slim

ARG TARGETARCH
ENV ARCH=$TARGETARCH

# 设置工作目录
WORKDIR /sing-box

# 安装运行时依赖
# 1. wget, xz-utils: 下载和解压工具
# 2. nginx, bash, openssl: 核心依赖
# 3. ca-certificates: 防止 wget 报 SSL 证书错误
# 4. iputils-ping: 脚本中用到 ping 命令检测网络
# 5. xxd: 脚本中生成 Reality Key 需要用到 xxd
# 6. procps: 提供 ps 等进程工具
RUN apt-get update && apt-get install -y \
    wget \
    xz-utils \
    nginx \
    bash \
    openssl \
    ca-certificates \
    iputils-ping \
    xxd \
    procps \
    && rm -rf /var/lib/apt/lists/*

# 下载并解压 s6-overlay
# 注意：Debian 下不需要多阶段构建复制，直接下载解压更安全，避免覆盖系统关键文件
RUN set -ex &&\
  case "$ARCH" in \
    amd64) S6_ARCH=x86_64 ;; \
    arm64) S6_ARCH=aarch64 ;; \
    armv7) S6_ARCH=armhf ;; \
    *) S6_ARCH=x86_64 ;; \
  esac &&\
  wget -qO- https://github.com/just-containers/s6-overlay/releases/latest/download/s6-overlay-noarch.tar.xz | tar -C / -Jxpf - &&\
  wget -qO- https://github.com/just-containers/s6-overlay/releases/latest/download/s6-overlay-$S6_ARCH.tar.xz | tar -C / -Jxpf -

# 复制初始化脚本
COPY docker_init.sh /sing-box/init.sh

# 创建目录并赋权
RUN mkdir -p /sing-box/cert /sing-box/conf /sing-box/subscribe /sing-box/logs &&\
  chmod +x /sing-box/init.sh

# 启动容器时运行初始化脚本
# 脚本运行结束后会自动 exec /init 启动 s6 进程守护
CMD [ "./init.sh" ]