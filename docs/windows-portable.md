# Windows 便携版

将 WiFiScope Windows x64 ZIP 解压到本地目录，双击 `WiFiScope.cmd` 启动。便携版自带 CPython 和 Tcl/Tk，可在 Windows 10/11 x64 上直接运行。实时抓包依赖系统中已有的 Npcap 和相应权限。

在终端运行同一个入口可使用命令行功能。保留解压得到的目录结构。

```powershell
.\WiFiScope.cmd network map --help
.\WiFiScope.cmd demo --out .\demo-report
```

## 构建

在 Windows x64 构建机使用 Python 3.12 或更新版本和 Git。先将审核过的上游文件保存到本地输入目录。构建程序可列出每个文件的地址及 SHA-256。

```powershell
py -3.13 tools/build_windows_portable.py --list-assets
py -3.13 tools/build_windows_portable.py --assets C:\build\approved-runtime --output C:\build\WiFiScope-windows-x64.zip
```

构建程序从 Git 提交读取应用源码，可用 `--revision` 指定提交。程序校验全部输入文件，使用 Windows Installer 的管理映像模式将 Tcl/Tk 文件解包到临时目录，再使用便携运行时测试工作台界面、测绘命令和合成报告。ZIP 内的 `build-provenance.json` 记录源提交、输入散列、许可证和运行时打包时间。相同输入和应用提交产生相同的应用与运行时文件，构建时间随次记录。

## 运行时来源

- [CPython 3.14.10 官方发行](https://www.python.org/downloads/release/python-31410/)的 Windows x64 嵌入包。源提交固定为 [b703b2c](https://github.com/python/cpython/commit/b703b2c5e704341d61e367b9b940b77ed11dded0)。Python Software Foundation 许可及配套声明、上游 SPDX 清单位于 `licenses`。
- [同版本的 Windows x64 Tcl/Tk 组件](https://www.python.org/ftp/python/3.14.10/amd64/)在本机核验过 Python Software Foundation 的 Authenticode 签名。组件原始二进制提交为 [907f3f4](https://github.com/python/cpython-bin-deps/commit/907f3f4de820cb74fc8fb4431a39beae4c690915)，源提交和许可分别列于 [Tcl](https://github.com/python/cpython-source-deps/tree/53c758cbf2cc178b359abc03fdd912c5e66ed74f) 和 [Tk](https://github.com/python/cpython-source-deps/tree/a6a5bee1ef4b526b0d11200c84bc02e85d8ecc83)。
