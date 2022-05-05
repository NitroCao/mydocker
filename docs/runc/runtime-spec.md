# What is Runtime Spec?

开源组织 [Open Container Initiative](https://www.opencontainers.org) 制定了一系列标准，用来规范如何在不同的操作系统上运行不同类型的容器。标准可以从[官方仓库](https://github.com/opencontainers/runtime-spec)中查看。根据这一标准，可以有不同的容器运行时的实现。在官方仓库中可以看到，有好几种不同的容器运行时。

目前此标准定义了以下几个平台上的运行时标准：

* `Linux`
* `Solaris`
* `Windows`
* `vm`
* `zos`

我们只关注 Linux 平台的实现。



Linux 平台下，`runtime.md` 中主要定义了容器的状态和生命周期，`config.md` 中定义了为了实现容器的标准操作所需的配置的详细内容。`config-linux.md` 中定义了 Linux 平台特有的配置，`runtime-linux.md` 中定义了 Linux 平台特有的运行时状态信息。

`runc spec` 命令可在当前目录下生成一个默认配置文件。

