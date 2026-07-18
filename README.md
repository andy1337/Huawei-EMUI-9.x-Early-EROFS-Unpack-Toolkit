# Huawei EMUI 9.x Early EROFS Unpack Toolkit

适用于华为 EMUI 9.x 早期 EROFS 镜像的解包、校验、ext4 转换和 GSI vendor 挂载修补工具。

> 本工具面向 EMUI 9.x 早期 EROFS system/vendor 镜像。普通开源 EROFS 解包器处理这类镜像时可能导致 APK 或其它压缩文件损坏，本工具会按华为早期 EROFS 布局读取并校验文件内容。

## 功能

- 解包华为 EMUI 9.x 早期 EROFS `system.img` / `vendor.img`
- 直接检查 EROFS 镜像内 APK 完整性
- 从解包目录打包 RW ext4 镜像
- raw/ext4 与 Android sparse 镜像互转
- 修补 Android 13 arm64 GSI 的 `/system/lib64/libfs_mgr.so`，让 `/vendor` 使用 ext4 挂载

## 不包含

- 不提供 EROFS 回打/重打包功能
- 不修改 DTS、DTO、kernel、boot、vendor 镜像
- 不包含任何固件镜像或设备私有文件

## 环境要求

- Python 3.10+
- 无第三方 Python 依赖
- Windows / Linux / macOS 均可运行

## 快速开始

解包 system：

```powershell
python .\emui91_erofs_ext4.py unpack --partition system system.img system_extracted
```

解包 vendor：

```powershell
python .\emui91_erofs_ext4.py unpack --partition vendor vendor.img vendor_extracted
```

确认解包报告：

```powershell
Get-Content .\system_extracted\verify_report.txt
```

`failures=0` 表示解包和校验通过。

## 打包 RW ext4

```powershell
python .\emui91_erofs_ext4.py pack-ext4 --partition system system_extracted system_rw_ext4.img --sparse
python .\emui91_erofs_ext4.py pack-ext4 --partition vendor vendor_extracted vendor_rw_ext4_xattr.img --sparse
```

## 一条命令转换为 RW ext4

```powershell
python .\emui91_erofs_ext4.py convert --partition system system.img system_rw_ext4.img --sparse
python .\emui91_erofs_ext4.py convert --partition vendor vendor.img vendor_rw_ext4_xattr.img --sparse
```

## GSI vendor ext4 修补

先检查是否支持：

```powershell
python .\emui91_erofs_ext4.py patch-gsi GSI.img --dry-run
```

生成修补后的 raw ext4 GSI：

```powershell
python .\emui91_erofs_ext4.py patch-gsi GSI.img GSI_vendor-ext4-libfs.img
```

## raw/sparse 转换

```powershell
python .\emui91_erofs_ext4.py sparse raw.img sparse.img
python .\emui91_erofs_ext4.py unsparse sparse.img raw.img
```

## 发布包

发布目录只应包含脚本、说明书、校验清单和许可证。不要把固件镜像、测试输出、临时目录、设备私有文件一起上传。

## License

MIT License
